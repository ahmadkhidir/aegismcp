package dev.aegismcp.gateway.inspector;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.LastHttpContent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Telemetry broadcaster behind {@code GET /api/v1/stream/traffic}.
 *
 * <p>It owns the three things C-002 puts on the transport rather than in the payloads: the monotonic
 * event id shared by every event type for the life of the node, the {@code retry: 3000} directive the
 * stream opens with, and the {@code : keepalive} comment written every 15 seconds while a subscriber
 * is idle. Each subscriber is a chunked HTTP response; a frame is serialized once per event and
 * written on every subscriber's own event loop, so one slow console cannot block the request path and
 * no thread ever queues work onto another channel's encoder from outside its loop.
 *
 * <p>Subscriptions live and die with their channel: a closed connection is removed by a close
 * listener, which also cancels its keepalive task. Events produced while nobody is subscribed are not
 * retained and are never replayed, matching the contract's reconnect semantics.
 *
 * <p>Anchors: FEAT-008, NFR-005, C-002.
 */
public final class InspectorEventStream implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(InspectorEventStream.class);

    /** Named event types of C-002. */
    public static final String EVENT_TRAFFIC = "traffic";
    public static final String EVENT_APPROVAL = "approval";
    public static final String EVENT_SYSTEM = "system";

    /** Reconnect delay directive the stream opens with, in milliseconds (C-002). */
    public static final int RETRY_MILLIS = 3000;

    /** How long a subscriber may stay silent before a comment keeps the connection alive. */
    public static final int KEEPALIVE_INTERVAL_SECONDS = 15;

    private static final byte[] RETRY_FRAME =
            ("retry: " + RETRY_MILLIS + "\n\n").getBytes(StandardCharsets.UTF_8);
    private static final byte[] KEEPALIVE_FRAME =
            ": keepalive\n\n".getBytes(StandardCharsets.UTF_8);
    private static final long KEEPALIVE_IDLE_NANOS =
            TimeUnit.SECONDS.toNanos(KEEPALIVE_INTERVAL_SECONDS);

    private final ObjectMapper jsonMapper;
    private final ConcurrentMap<Channel, Subscriber> subscribers = new ConcurrentHashMap<>();
    private final AtomicLong eventIds = new AtomicLong();
    /**
     * Serializes id assignment with frame enqueueing. Traffic is published from request threads and
     * approval or system events from the telemetry poller, so without this lock two threads could
     * enqueue their frames in the opposite order to their ids and a subscriber would see the id jump
     * back.
     */
    private final Object publishLock = new Object();
    private volatile boolean closed;

    public InspectorEventStream(ObjectMapper jsonMapper) {
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
    }

    /** True while the endpoint may open new streams; false once the node drains or closes. */
    public boolean isAccepting() {
        return !closed;
    }

    /**
     * Reopens the broadcaster when a node starts or restarts its listener. A node that has drained
     * and is brought back up serves subscriptions again with the id sequence continuing.
     */
    public synchronized void start() {
        closed = false;
    }

    /**
     * Starts streaming to an authorized channel: queues the {@code retry} directive, registers the
     * subscriber, and schedules its keepalive. The caller has already written the response headers,
     * so the queued directive lands behind them and ahead of every event frame.
     *
     * @return false when the broadcaster is closed or the channel's loop is shutting down, in which
     *         case the caller owns closing the channel
     */
    public boolean subscribe(Channel channel) {
        Objects.requireNonNull(channel, "channel must not be null");
        if (closed) {
            return false;
        }
        Subscriber subscriber = new Subscriber(channel);
        if (subscribers.putIfAbsent(channel, subscriber) != null) {
            return true;
        }
        channel.closeFuture().addListener(future -> {
            Subscriber removed = subscribers.remove(channel);
            if (removed != null) {
                removed.cancelKeepalive();
                logger.debug("Live traffic stream subscriber disconnected; {} remain", subscribers.size());
            }
        });
        dispatch(subscriber, RETRY_FRAME);
        if (!subscriber.scheduleKeepalive()) {
            subscribers.remove(channel, subscriber);
            return false;
        }
        logger.debug("Live traffic stream subscriber connected; {} subscribed", subscribers.size());
        return true;
    }

    /** Broadcasts one {@code traffic} event. */
    public void publishTraffic(TrafficEvent event) {
        publish(EVENT_TRAFFIC, event);
    }

    /** Broadcasts one {@code approval} event. */
    public void publishApproval(ApprovalEvent event) {
        publish(EVENT_APPROVAL, event);
    }

    /** Broadcasts one {@code system} event. */
    public void publishSystem(SystemEvent event) {
        publish(EVENT_SYSTEM, event);
    }

    /**
     * Assigns the next id, serializes the payload once, and dispatches the frame to every subscriber.
     * The id is the same value in the SSE {@code id} field and in {@code data.eventId}, so a console
     * can dedupe replayed reads against the frame it already rendered.
     */
    private void publish(String eventType, Object payload) {
        if (closed) {
            return;
        }
        synchronized (publishLock) {
            long eventId = eventIds.incrementAndGet();
            String json;
            try {
                ObjectNode data = jsonMapper.createObjectNode();
                data.put("eventId", Long.toString(eventId));
                ObjectNode fields = jsonMapper.valueToTree(payload);
                data.setAll(fields);
                json = jsonMapper.writeValueAsString(data);
            } catch (JsonProcessingException | IllegalArgumentException e) {
                // A payload that cannot be serialized is dropped rather than replacing a live stream
                // with an error: the inspector is an observability surface, not the request path.
                logger.error("Failed to serialize a live {} event", eventType, e);
                return;
            }

            byte[] frame = ("id: " + eventId + "\nevent: " + eventType + "\ndata: " + json + "\n\n")
                    .getBytes(StandardCharsets.UTF_8);
            for (Subscriber subscriber : subscribers.values()) {
                dispatch(subscriber, frame);
            }
        }
    }

    private void dispatch(Subscriber subscriber, byte[] frame) {
        Channel channel = subscriber.channel;
        if (!channel.isActive()) {
            return;
        }
        // Every response write happens on the channel's own executor (NFR-001): the publishing thread
        // is a request thread or the telemetry poller, never this channel's loop. Queueing even from
        // the loop keeps frame order identical to event-id order.
        try {
            channel.eventLoop().execute(() -> writeNow(subscriber, frame));
        } catch (RejectedExecutionException e) {
            subscriber.cancelKeepalive();
            subscribers.remove(channel, subscriber);
            channel.close();
        }
    }

    private void writeNow(Subscriber subscriber, byte[] frame) {
        Channel channel = subscriber.channel;
        if (!channel.isActive()) {
            return;
        }
        subscriber.markWritten();
        channel.writeAndFlush(new DefaultHttpContent(Unpooled.wrappedBuffer(frame)))
                .addListener(future -> {
                    if (!future.isSuccess()) {
                        logger.debug("Live traffic stream write failed; closing the subscription",
                                future.cause());
                        channel.close();
                    }
                });
    }

    /**
     * Stops accepting subscribers, cancels their keepalives, terminates each chunked body, and
     * releases the subscription set. Called while the node drains, so a console sees a closed stream
     * and reconnects into its backoff state instead of a silently idle connection.
     */
    @Override
    public void close() {
        closed = true;
        List<Subscriber> remaining = List.copyOf(subscribers.values());
        subscribers.clear();
        for (Subscriber subscriber : remaining) {
            subscriber.cancelKeepalive();
            Channel channel = subscriber.channel;
            if (channel.isActive()) {
                channel.writeAndFlush(LastHttpContent.EMPTY_LAST_CONTENT)
                        .addListener(ChannelFutureListener.CLOSE);
            } else {
                channel.close();
            }
        }
    }

    /** One open SSE response: its channel, its last write instant, and its keepalive task. */
    private final class Subscriber {
        private final Channel channel;
        private final AtomicLong lastWriteNanos = new AtomicLong(System.nanoTime());
        private volatile ScheduledFuture<?> keepalive;

        private Subscriber(Channel channel) {
            this.channel = channel;
        }

        private void markWritten() {
            lastWriteNanos.set(System.nanoTime());
        }

        private boolean scheduleKeepalive() {
            try {
                keepalive = channel.eventLoop().scheduleAtFixedRate(
                        this::keepaliveIfIdle,
                        KEEPALIVE_INTERVAL_SECONDS,
                        KEEPALIVE_INTERVAL_SECONDS,
                        TimeUnit.SECONDS);
                return true;
            } catch (RejectedExecutionException e) {
                // The loop is shutting down, so the subscription would never deliver anything.
                return false;
            }
        }

        /** Writes the comment only after a full idle interval, so a busy stream carries no padding. */
        private void keepaliveIfIdle() {
            if (closed || !channel.isActive()) {
                return;
            }
            if (System.nanoTime() - lastWriteNanos.get() < KEEPALIVE_IDLE_NANOS) {
                return;
            }
            markWritten();
            channel.writeAndFlush(new DefaultHttpContent(Unpooled.wrappedBuffer(KEEPALIVE_FRAME)))
                    .addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
        }

        private void cancelKeepalive() {
            ScheduledFuture<?> task = keepalive;
            if (task != null) {
                task.cancel(false);
            }
        }
    }
}
