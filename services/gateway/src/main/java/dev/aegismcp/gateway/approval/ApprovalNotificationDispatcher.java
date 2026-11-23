package dev.aegismcp.gateway.approval;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * Fans a suspended approval ticket out to every configured destination, retrying a failed delivery
 * with a bounded backoff (FEAT-006).
 *
 * <p>Delivery runs on virtual threads so a slow or unreachable Slack workspace, webhook, or mail
 * relay never delays the suspended JSON-RPC call or blocks a Netty event loop. A destination that
 * exhausts its retries is recorded and logged without its payload, and the ticket stays pending so
 * the Web Console queue remains usable until the ticket expires; a failed notification never denies
 * the call by itself.
 *
 * <p>Anchors: FEAT-006, EVT-008, NFR-002, NFR-023.
 */
public final class ApprovalNotificationDispatcher implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalNotificationDispatcher.class);

    /** The longest single retry pause; a destination that is down for longer stays reachable in the console. */
    private static final Duration MAX_BACKOFF = Duration.ofSeconds(30);

    /** One channel's final outcome for one ticket. */
    public record DeliveryRecord(
            String ticketId,
            String channel,
            int attempts,
            boolean delivered,
            String failureReason
    ) {
        public DeliveryRecord {
            Objects.requireNonNull(ticketId, "ticketId must not be null");
            Objects.requireNonNull(channel, "channel must not be null");
        }
    }

    /** The outcome of every configured channel for one ticket. */
    public record DeliveryReport(String ticketId, List<DeliveryRecord> deliveries) {
        public DeliveryReport {
            deliveries = deliveries != null ? List.copyOf(deliveries) : List.of();
        }

        public boolean anyDelivered() {
            return deliveries.stream().anyMatch(DeliveryRecord::delivered);
        }

        public boolean allFailed() {
            return !deliveries.isEmpty() && deliveries.stream().noneMatch(DeliveryRecord::delivered);
        }
    }

    /** Pause between attempts; injectable so tests do not wait out a backoff. */
    @FunctionalInterface
    public interface Sleeper {
        void sleep(Duration duration) throws InterruptedException;
    }

    private final List<ApprovalNotificationChannel> channels;
    private final int maxAttempts;
    private final Duration retryBackoff;
    private final Executor executor;
    private final boolean ownsExecutor;
    private final Sleeper sleeper;
    private final ConcurrentMap<String, DeliveryRecord> records = new ConcurrentHashMap<>();

    public ApprovalNotificationDispatcher(
            List<ApprovalNotificationChannel> channels,
            int maxAttempts,
            Duration retryBackoff
    ) {
        this(channels, maxAttempts, retryBackoff,
                Executors.newVirtualThreadPerTaskExecutor(), true, Thread::sleep);
    }

    public ApprovalNotificationDispatcher(
            List<ApprovalNotificationChannel> channels,
            int maxAttempts,
            Duration retryBackoff,
            Executor executor,
            boolean ownsExecutor,
            Sleeper sleeper
    ) {
        this.channels = channels != null ? List.copyOf(channels) : List.of();
        this.maxAttempts = Math.max(1, maxAttempts);
        this.retryBackoff = retryBackoff != null ? retryBackoff : Duration.ZERO;
        this.executor = Objects.requireNonNull(executor, "executor must not be null");
        this.ownsExecutor = ownsExecutor;
        this.sleeper = Objects.requireNonNull(sleeper, "sleeper must not be null");
    }

    /** A dispatcher with no destination; used by tests and probe-only seams. */
    public static ApprovalNotificationDispatcher none() {
        return new ApprovalNotificationDispatcher(List.of(), 1, Duration.ZERO,
                Runnable::run, false, duration -> {
                });
    }

    public boolean hasChannels() {
        return !channels.isEmpty();
    }

    /**
     * Builds the masked notification on the dispatcher's executor, then starts delivery. Building
     * off the caller's thread matters because DLP scanning of the tool arguments must never run
     * inline on a Netty event loop (NFR-002).
     */
    public CompletableFuture<DeliveryReport> dispatch(ApprovalTicket ticket) {
        Objects.requireNonNull(ticket, "ticket must not be null");
        if (channels.isEmpty()) {
            return CompletableFuture.completedFuture(new DeliveryReport(ticket.id(), List.of()));
        }
        try {
            return CompletableFuture.supplyAsync(() -> ApprovalNotification.from(ticket), executor)
                    .thenCompose(this::dispatch)
                    .exceptionally(failure -> {
                        logger.warn("Approval notification for ticket {} could not be built: {}",
                                ticket.id(), failure.getClass().getSimpleName());
                        return failedReport(ticket.id(), "notification build failed");
                    });
        } catch (RejectedExecutionException e) {
            logger.warn("Approval notification for ticket {} was not scheduled: dispatcher is closed",
                    ticket.id());
            return CompletableFuture.completedFuture(failedReport(ticket.id(), "dispatcher closed"));
        }
    }

    /**
     * Starts delivery and returns the eventual report. It never throws: a scheduling failure is
     * reported as an all-failed record so the caller can keep the ticket pending.
     */
    public CompletableFuture<DeliveryReport> dispatch(ApprovalNotification notification) {
        Objects.requireNonNull(notification, "notification must not be null");
        if (channels.isEmpty()) {
            return CompletableFuture.completedFuture(new DeliveryReport(notification.ticketId(), List.of()));
        }

        List<CompletableFuture<DeliveryRecord>> futures = new ArrayList<>(channels.size());
        try {
            for (ApprovalNotificationChannel channel : channels) {
                futures.add(CompletableFuture.supplyAsync(
                        () -> deliverWithRetry(channel, notification), executor));
            }
        } catch (RejectedExecutionException e) {
            logger.warn("Approval notification for ticket {} was not scheduled: dispatcher is closed",
                    notification.ticketId());
            return CompletableFuture.completedFuture(
                    failedReport(notification.ticketId(), "dispatcher closed"));
        }

        return CompletableFuture
                .allOf(futures.toArray(CompletableFuture[]::new))
                .thenApply(ignored -> {
                    List<DeliveryRecord> outcomes = futures.stream()
                            .map(CompletableFuture::join)
                            .toList();
                    for (DeliveryRecord outcome : outcomes) {
                        records.put(key(outcome.ticketId(), outcome.channel()), outcome);
                    }
                    return new DeliveryReport(notification.ticketId(), outcomes);
                });
    }

    private DeliveryReport failedReport(String ticketId, String reason) {
        return new DeliveryReport(ticketId, channels.stream()
                .map(channel -> new DeliveryRecord(ticketId, channel.name(), 0, false, reason))
                .toList());
    }

    private DeliveryRecord deliverWithRetry(
            ApprovalNotificationChannel channel,
            ApprovalNotification notification
    ) {
        Exception lastFailure = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                channel.deliver(notification);
                return new DeliveryRecord(notification.ticketId(), channel.name(), attempt, true, null);
            } catch (Exception e) {
                lastFailure = e;
                if (attempt < maxAttempts && !pause(backoffFor(attempt))) {
                    break;
                }
            }
        }

        String reason = describe(lastFailure);
        logger.warn("Approval notification for ticket {} via {} was not delivered after {} attempt(s): {}",
                notification.ticketId(), channel.name(), maxAttempts, reason);
        return new DeliveryRecord(notification.ticketId(), channel.name(), maxAttempts, false, reason);
    }

    private boolean pause(Duration duration) {
        if (duration.isZero() || duration.isNegative()) {
            return true;
        }
        try {
            sleeper.sleep(duration);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private Duration backoffFor(int attempt) {
        long multiplier = 1L << Math.min(attempt - 1, 16);
        long millis = Math.min(
                retryBackoff.toMillis() * multiplier, MAX_BACKOFF.toMillis());
        return Duration.ofMillis(Math.max(0, millis));
    }

    /**
     * Describes a failure without its message: an exception message can carry the webhook URL, the
     * SMTP host, or a receiver's echoed body, and none of those belong in a log line.
     */
    private static String describe(Exception failure) {
        if (failure == null) {
            return "unknown failure";
        }
        if (failure instanceof ApprovalNotificationHttp.DeliveryFailedException delivery) {
            return delivery.statusCode() >= 0
                    ? "HTTP " + delivery.statusCode()
                    : delivery.getMessage();
        }
        return failure.getClass().getSimpleName();
    }

    /** The last recorded outcome for a ticket and channel, when a dispatch has completed. */
    public Optional<DeliveryRecord> recordFor(String ticketId, String channel) {
        return Optional.ofNullable(records.get(key(ticketId, channel)));
    }

    /** Every recorded outcome for a ticket. */
    public Map<String, DeliveryRecord> recordsFor(String ticketId) {
        Map<String, DeliveryRecord> matching = new ConcurrentHashMap<>();
        records.forEach((key, record) -> {
            if (record.ticketId().equals(ticketId)) {
                matching.put(record.channel(), record);
            }
        });
        return Map.copyOf(matching);
    }

    private static String key(String ticketId, String channel) {
        return ticketId + "|" + channel;
    }

    @Override
    public void close() {
        if (ownsExecutor && executor instanceof ExecutorService service) {
            service.shutdown();
            try {
                if (!service.awaitTermination(2, TimeUnit.SECONDS)) {
                    service.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                service.shutdownNow();
            }
        }
    }
}
