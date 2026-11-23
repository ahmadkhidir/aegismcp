package dev.aegismcp.gateway.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the HTTPS request/response upstream transport. The peer is a local HTTP server, so
 * the suite is hermetic and exercises the real client without a live network.
 *
 * <p>Anchors: FEAT-001, C-001, NFR-001.
 */
class HttpUpstreamClientTest {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(2);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final ObjectMapper MAPPER = JsonRpcCodec.getInstance().getMapper();

    private HttpServer server;
    private URI endpoint;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor());
        endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/mcp");
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    @DisplayName("FEAT-001 / C-001: forwards one call and preserves the request id and result")
    void forwardsAndPreservesId() throws Exception {
        server.createContext("/mcp", exchange -> {
            JsonNode request = MAPPER.readTree(exchange.getRequestBody());
            String body = "{\"jsonrpc\":\"2.0\",\"id\":" + request.get("id")
                    + ",\"result\":{\"content\":\"file data\"}}";
            byte[] payload = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, payload.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(payload);
            }
        });

        UpstreamClient client = new HttpUpstreamClient(endpoint, CONNECT_TIMEOUT, REQUEST_TIMEOUT);
        JsonRpcResponse response = client.forward(context(), toolCall("call-7")).get(5, TimeUnit.SECONDS);

        assertEquals("call-7", ((JsonRpcId.StringId) response.id()).stringValue());
        assertEquals("file data", response.result().get("content").asText());
    }

    @Test
    @DisplayName("FEAT-001: a Streamable HTTP event-stream answer is correlated by id")
    void readsEventStreamResponseAndSelectsMatchingId() throws Exception {
        server.createContext("/mcp", exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"other\","
                        + "\"result\":{\"ignored\":true}}\n\n").getBytes(StandardCharsets.UTF_8));
                out.write(("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"stream-1\","
                        + "\"result\":{\"content\":\"streamed\"}}\n\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        });

        UpstreamClient client = new HttpUpstreamClient(endpoint, CONNECT_TIMEOUT, REQUEST_TIMEOUT);
        JsonRpcResponse response = client.forward(context(), toolCall("stream-1")).get(5, TimeUnit.SECONDS);

        assertEquals("stream-1", ((JsonRpcId.StringId) response.id()).stringValue());
        assertEquals("streamed", response.result().get("content").asText());
    }

    @Test
    @DisplayName("C-001: an unreachable upstream fails as UPSTREAM_UNAVAILABLE")
    void unreachableUpstreamFailsClosed() throws Exception {
        UpstreamClient client = new HttpUpstreamClient(
                URI.create("http://127.0.0.1:1/mcp"), CONNECT_TIMEOUT, Duration.ofSeconds(1));

        ExecutionException failure = assertThrows(ExecutionException.class,
                () -> client.forward(context(), toolCall("down-1")).get(5, TimeUnit.SECONDS));
        Throwable cause = failure.getCause();
        while (cause instanceof CompletionException && cause.getCause() != null) {
            cause = cause.getCause();
        }
        assertInstanceOf(UpstreamException.class, cause);
    }

    @Test
    @DisplayName("C-001: an answer carrying another id is never delivered")
    void mismatchedResponseIdIsRejected() throws Exception {
        server.createContext("/mcp", exchange -> {
            String body = "{\"jsonrpc\":\"2.0\",\"id\":\"not-mine\",\"result\":{\"content\":\"x\"}}";
            byte[] payload = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, payload.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(payload);
            }
        });

        UpstreamClient client = new HttpUpstreamClient(endpoint, CONNECT_TIMEOUT, REQUEST_TIMEOUT);
        ExecutionException failure = assertThrows(ExecutionException.class,
                () -> client.forward(context(), toolCall("mine")).get(5, TimeUnit.SECONDS));
        Throwable cause = failure.getCause();
        while (cause instanceof CompletionException && cause.getCause() != null) {
            cause = cause.getCause();
        }
        assertTrue(cause instanceof UpstreamException);
    }

    private static SecurityContext context() {
        return SecurityContext.of(AgentIdentity.anonymous(), null);
    }

    private static JsonRpcRequest toolCall(String id) {
        return new JsonRpcRequest(JsonRpcId.of(id), "tools/call", null);
    }
}
