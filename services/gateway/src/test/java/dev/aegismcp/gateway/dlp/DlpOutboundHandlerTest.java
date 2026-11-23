package dev.aegismcp.gateway.dlp;

import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Netty pipeline integration tests for DlpOutboundHandler.
 * Anchors: FEAT-005, C-001, NFR-002.
 */
class DlpOutboundHandlerTest {

    /** Runs the scan on the calling thread so tests stay deterministic. */
    private static final Executor DIRECT = Runnable::run;

    @Test
    @DisplayName("FEAT-005 / C-001: Netty outbound handler redacts sensitive JSON response")
    void testOutboundJsonResponseRedaction() {
        DlpScrubber scrubber = DlpScrubber.getInstance();
        DlpOutboundHandler handler = new DlpOutboundHandler(scrubber, DIRECT);
        EmbeddedChannel channel = new EmbeddedChannel(handler);

        String jsonPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": "req-1",
                  "result": {
                    "awsKey": "AKIAIOSFODNN7EXAMPLE",
                    "email": "agent.smith@matrix.corp",
                    "safeField": 12345
                  }
                }
                """;

        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                HttpResponseStatus.OK,
                Unpooled.copiedBuffer(jsonPayload, StandardCharsets.UTF_8)
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, jsonPayload.getBytes(StandardCharsets.UTF_8).length);

        assertTrue(channel.writeOutbound(response));

        FullHttpResponse scrubbedResponse = channel.readOutbound();
        assertNotNull(scrubbedResponse);

        String scrubbedBody = scrubbedResponse.content().toString(StandardCharsets.UTF_8);

        assertFalse(scrubbedBody.contains("AKIAIOSFODNN7EXAMPLE"));
        assertFalse(scrubbedBody.contains("agent.smith@matrix.corp"));
        assertTrue(scrubbedBody.contains("[REDACTED_API_KEY]"));
        assertTrue(scrubbedBody.contains("[REDACTED_PII]"));
        assertTrue(scrubbedBody.contains("12345"));
        assertTrue(scrubbedBody.contains("\"safeField\": 12345"), "Numeric JSON values must keep their type");
        assertEquals(HttpResponseStatus.OK, scrubbedResponse.status());

        assertEquals(scrubbedResponse.content().readableBytes(),
                scrubbedResponse.headers().getInt(HttpHeaderNames.CONTENT_LENGTH));

        scrubbedResponse.release();
    }

    @Test
    @DisplayName("FEAT-005: Non-scrubbed content type passes through untouched")
    void testPassThroughNonScrubbedContentType() {
        DlpScrubber scrubber = DlpScrubber.getInstance();
        DlpOutboundHandler handler = new DlpOutboundHandler(scrubber, DIRECT);
        EmbeddedChannel channel = new EmbeddedChannel(handler);

        byte[] binaryData = new byte[] {0x00, 0x01, 0x02, 0x03};
        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                HttpResponseStatus.OK,
                Unpooled.copiedBuffer(binaryData)
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/octet-stream");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, binaryData.length);

        assertTrue(channel.writeOutbound(response));

        FullHttpResponse emitted = channel.readOutbound();
        assertNotNull(emitted);
        assertEquals(binaryData.length, emitted.content().readableBytes());

        emitted.release();
    }

    @Test
    @DisplayName("NFR-002: scanning is offloaded and never runs on the calling event-loop thread")
    void testScanRunsOnWorkerNotEventLoop() {
        AtomicReference<Runnable> submitted = new AtomicReference<>();
        Executor queueingWorker = submitted::set;

        DlpScrubber scrubber = DlpScrubber.getInstance();
        DlpOutboundHandler handler = new DlpOutboundHandler(scrubber, queueingWorker);
        EmbeddedChannel channel = new EmbeddedChannel(handler);

        String jsonPayload = "{\"result\":{\"apiKey\":\"AKIAIOSFODNN7EXAMPLE\"}}";
        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                HttpResponseStatus.OK,
                Unpooled.copiedBuffer(jsonPayload, StandardCharsets.UTF_8)
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");

        channel.writeOutbound(response);

        // The payload was handed to the worker and nothing was written while the caller held the thread.
        assertNotNull(submitted.get(), "The scan must be submitted to the worker");
        assertNull(channel.readOutbound(), "No response may be written before the scan completes");

        submitted.get().run();
        channel.runPendingTasks();

        FullHttpResponse scrubbedResponse = channel.readOutbound();
        assertNotNull(scrubbedResponse);
        String body = scrubbedResponse.content().toString(StandardCharsets.UTF_8);
        assertFalse(body.contains("AKIAIOSFODNN7EXAMPLE"));
        assertTrue(body.contains("[REDACTED_API_KEY]"));
        scrubbedResponse.release();
    }

    @Test
    @DisplayName("FEAT-005: a scanner failure masks the body instead of forwarding it")
    void testScannerFailureMasksBody() {
        DlpScrubber failingScrubber = new DlpScrubber() {
            @Override
            public byte[] scrub(byte[] payload) {
                throw new IllegalStateException("scanner defect");
            }
        };
        DlpOutboundHandler handler = new DlpOutboundHandler(failingScrubber, DIRECT);
        EmbeddedChannel channel = new EmbeddedChannel(handler);

        String jsonPayload = "{\"result\":{\"apiKey\":\"AKIAIOSFODNN7EXAMPLE\"}}";
        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                HttpResponseStatus.OK,
                Unpooled.copiedBuffer(jsonPayload, StandardCharsets.UTF_8)
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");

        channel.writeOutbound(response);

        FullHttpResponse emitted = channel.readOutbound();
        assertNotNull(emitted);
        String body = emitted.content().toString(StandardCharsets.UTF_8);
        assertEquals(DlpScrubber.SCAN_FAILURE_MASK, body);
        assertFalse(body.contains("AKIAIOSFODNN7EXAMPLE"));
        assertEquals(HttpResponseStatus.INTERNAL_SERVER_ERROR, emitted.status());
        emitted.release();
    }

    @Test
    @DisplayName("FEAT-005: a scan that overruns its budget is masked, not forwarded")
    void testScanTimeoutMasksBody() {
        Executor neverRuns = command -> {
            // Simulates a scan that never reports back.
        };
        DlpScrubber scrubber = new DlpScrubber(
                DlpConfig.builder().scanTimeoutMillis(50L).build());
        DlpOutboundHandler handler = new DlpOutboundHandler(scrubber, neverRuns);
        EmbeddedChannel channel = new EmbeddedChannel(handler);

        String jsonPayload = "{\"result\":{\"apiKey\":\"AKIAIOSFODNN7EXAMPLE\"}}";
        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                HttpResponseStatus.OK,
                Unpooled.copiedBuffer(jsonPayload, StandardCharsets.UTF_8)
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");

        channel.writeOutbound(response);
        channel.advanceTimeBy(60, java.util.concurrent.TimeUnit.MILLISECONDS);
        channel.runPendingTasks();

        FullHttpResponse emitted = channel.readOutbound();
        assertNotNull(emitted);
        assertEquals(DlpScrubber.SCAN_FAILURE_MASK, emitted.content().toString(StandardCharsets.UTF_8));
        assertEquals(HttpResponseStatus.INTERNAL_SERVER_ERROR, emitted.status());
        emitted.release();
    }
}
