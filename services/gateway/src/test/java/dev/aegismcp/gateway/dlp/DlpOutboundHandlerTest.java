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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Netty pipeline integration tests for DlpOutboundHandler.
 * Anchors: FEAT-005, C-001, NFR-002.
 */
class DlpOutboundHandlerTest {

    @Test
    @DisplayName("FEAT-005 / C-001: Netty outbound handler redacts sensitive JSON response")
    void testOutboundJsonResponseRedaction() {
        DlpScrubber scrubber = DlpScrubber.getInstance();
        DlpOutboundHandler handler = new DlpOutboundHandler(scrubber);
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

        assertEquals(scrubbedResponse.content().readableBytes(),
                scrubbedResponse.headers().getInt(HttpHeaderNames.CONTENT_LENGTH));

        scrubbedResponse.release();
    }

    @Test
    @DisplayName("FEAT-005: Non-scrubbed content type passes through untouched")
    void testPassThroughNonScrubbedContentType() {
        DlpScrubber scrubber = DlpScrubber.getInstance();
        DlpOutboundHandler handler = new DlpOutboundHandler(scrubber);
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
}
