package dev.aegismcp.gateway.dlp;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * Netty outbound handler that scans and redacts sensitive credentials, API keys, private keys,
 * database URLs, and PII from a proxied tool-response body before transmission.
 *
 * <p>It is scoped, not global: the composition root attaches it immediately before the MCP proxy
 * handler, after every probe, management, and inspector-stream handler. An outbound write travels
 * toward the pipeline head from the writing handler's context, so those handlers' responses never
 * cross this filter, while the proxied upstream response does (FEAT-005, C-001).
 *
 * <p>Pattern scanning over a large payload is CPU work, not channel work, so it never runs on the
 * event loop: the payload is copied out, scanned on a worker, and the sanitized response is written
 * back on the channel's own executor. A scan that fails, times out, or is rejected by the worker
 * produces a mask instead of the raw body, so a scanner defect can never forward the secret it was
 * meant to remove.
 * Anchors: FEAT-005, NFR-002, C-001.
 */
@ChannelHandler.Sharable
public class DlpOutboundHandler extends ChannelOutboundHandlerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(DlpOutboundHandler.class);

    /**
     * Shared worker for scanning. Virtual threads keep the offload cheap per response and avoid
     * pinning a platform thread for the duration of a scan.
     */
    private static final class WorkerHolder {
        private static final ExecutorService WORKER = Executors.newVirtualThreadPerTaskExecutor();
    }

    private static final byte[] SCAN_FAILURE_BODY =
            DlpScrubber.SCAN_FAILURE_MASK.getBytes(StandardCharsets.US_ASCII);

    private final DlpScrubber scrubber;
    private final Executor worker;
    private final long scanTimeoutMillis;

    public DlpOutboundHandler() {
        this(DlpScrubber.getInstance());
    }

    public DlpOutboundHandler(DlpScrubber scrubber) {
        this(scrubber, WorkerHolder.WORKER);
    }

    public DlpOutboundHandler(DlpScrubber scrubber, Executor worker) {
        this.scrubber = Objects.requireNonNull(scrubber, "scrubber must not be null");
        this.worker = Objects.requireNonNull(worker, "worker must not be null");
        this.scanTimeoutMillis = scrubber.getConfig().getScanTimeoutMillis();
    }

    public DlpScrubber getScrubber() {
        return scrubber;
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (!(msg instanceof FullHttpResponse response)) {
            super.write(ctx, msg, promise);
            return;
        }

        CharSequence contentType = response.headers().get(HttpHeaderNames.CONTENT_TYPE);
        if (!shouldScrub(contentType)) {
            super.write(ctx, msg, promise);
            return;
        }

        // Copy what the response write needs, then hand ownership of the buffer back immediately so
        // no reference leaves this thread.
        HttpResponseStatus status = response.status();
        HttpHeaders headers = response.headers().copy();
        byte[] payload;
        try {
            payload = ByteBufUtil.getBytes(response.content());
        } finally {
            response.release();
        }

        Outcome outcome = new Outcome(ctx, status, headers, promise);
        try {
            worker.execute(() -> scanAndComplete(outcome, payload));
        } catch (RuntimeException e) {
            logger.error("DLP worker rejected the scan; masking the response body", e);
            outcome.fail();
        }

        outcome.scheduleTimeout(scanTimeoutMillis);
    }

    private void scanAndComplete(Outcome outcome, byte[] payload) {
        byte[] body;
        try {
            body = scrubber.scrub(payload);
        } catch (RuntimeException | StackOverflowError e) {
            logger.error("DLP scan failed; masking the response body", e);
            body = null;
        }
        outcome.complete(body);
    }

    private boolean shouldScrub(CharSequence contentType) {
        if (contentType == null) {
            return true;
        }
        String ct = contentType.toString().toLowerCase();
        return ct.contains("application/json") || ct.contains("text/") || ct.contains("application/xml");
    }

    /**
     * Per-response write accounting. Every method here is invoked on the channel's event loop, so the
     * settle flag needs no synchronization: the worker only posts the result back.
     */
    private static final class Outcome {
        private final ChannelHandlerContext ctx;
        private final HttpResponseStatus status;
        private final HttpHeaders headers;
        private final ChannelPromise promise;
        private boolean settled;

        Outcome(ChannelHandlerContext ctx, HttpResponseStatus status, HttpHeaders headers, ChannelPromise promise) {
            this.ctx = ctx;
            this.status = status;
            this.headers = headers;
            this.promise = promise;
        }

        void scheduleTimeout(long timeoutMillis) {
            ctx.executor().schedule(() -> {
                if (!settled) {
                    logger.warn("DLP scan exceeded {} ms; masking the response body", timeoutMillis);
                    writeMask();
                }
            }, timeoutMillis, TimeUnit.MILLISECONDS);
        }

        void complete(byte[] body) {
            if (ctx.executor().inEventLoop()) {
                writeBody(body);
                return;
            }
            try {
                ctx.executor().execute(() -> writeBody(body));
            } catch (RejectedExecutionException e) {
                promise.tryFailure(e);
            }
        }

        void fail() {
            writeMask();
        }

        private void writeBody(byte[] body) {
            if (settled) {
                return;
            }
            if (body == null) {
                writeMask();
                return;
            }
            settled = true;
            writeResponse(body, status, headers.get(HttpHeaderNames.CONTENT_TYPE));
        }

        /** Replaces the body with the scan-failure mask; the response never carries the raw payload. */
        private void writeMask() {
            if (settled) {
                return;
            }
            settled = true;
            writeResponse(SCAN_FAILURE_BODY, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    HttpHeaderValues.TEXT_PLAIN);
        }

        private void writeResponse(byte[] body, HttpResponseStatus responseStatus, CharSequence contentType) {
            // Wrapping avoids a second full-payload copy on the way to the channel.
            ByteBuf buffer = Unpooled.wrappedBuffer(body);
            FullHttpResponse message = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, responseStatus, buffer);
            message.headers().set(headers);
            message.headers().remove(HttpHeaderNames.TRANSFER_ENCODING);
            if (contentType != null) {
                message.headers().set(HttpHeaderNames.CONTENT_TYPE, contentType);
            }
            HttpUtil.setContentLength(message, body.length);
            // The caller's flush has already travelled past this handler by the time the scan
            // completes, so the deferred response is written and flushed together.
            ctx.writeAndFlush(message, promise);
        }
    }
}
