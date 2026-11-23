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
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for the Server-Sent Events upstream transport. A local HTTP peer serves the stream and
 * the message endpoint, so the suite is hermetic.
 *
 * <p>Anchors: FEAT-001, C-001.
 */
class SseUpstreamClientTest {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(2);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final ObjectMapper MAPPER = JsonRpcCodec.getInstance().getMapper();

    private HttpServer server;
    private final CountDownLatch releaseStream = new CountDownLatch(1);
    private final Object streamLock = new Object();
    private final List<JsonNode> posted = new CopyOnWriteArrayList<>();
    private volatile OutputStream stream;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor());
        server.start();
    }

    @AfterEach
    void stopServer() {
        releaseStream.countDown();
        synchronized (streamLock) {
            if (stream != null) {
                try {
                    stream.close();
                } catch (IOException ignored) {
                    // The stream is already closing with the test.
                }
            }
        }
        server.stop(0);
    }

    @Test
    @DisplayName("FEAT-001: opens the stream, posts to its message URL, and correlates responses by id")
    void correlatesStreamedResponsesByRequestId() throws Exception {
        server.createContext("/sse", exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.sendResponseHeaders(200, 0);
            OutputStream out = exchange.getResponseBody();
            synchronized (streamLock) {
                stream = out;
            }
            out.write(("event: endpoint\ndata: /messages\n\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            try {
                releaseStream.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            out.close();
        });
        server.createContext("/messages", exchange -> {
            JsonNode request = MAPPER.readTree(exchange.getRequestBody());
            posted.add(request);
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
            if (posted.size() == 2) {
                // Answer in reverse arrival order: the transport, not the stream order, must apply
                // each response to its own request.
                for (int i = posted.size() - 1; i >= 0; i--) {
                    JsonNode postedRequest = posted.get(i);
                    String body = "{\"jsonrpc\":\"2.0\",\"id\":" + postedRequest.get("id")
                            + ",\"result\":{\"answer\":\"" + postedRequest.get("id").asText() + "\"}}";
                    synchronized (streamLock) {
                        stream.write(("event: message\ndata: " + body + "\n\n")
                                .getBytes(StandardCharsets.UTF_8));
                        stream.flush();
                    }
                }
            }
        });

        URI streamUrl = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/sse");
        SseUpstreamClient client = new SseUpstreamClient(streamUrl, CONNECT_TIMEOUT, REQUEST_TIMEOUT);
        try {
            CompletableFuture<JsonRpcResponse> first = client.forward(context(), toolCall("sse-a"));
            CompletableFuture<JsonRpcResponse> second = client.forward(context(), toolCall("sse-b"));

            JsonRpcResponse firstResponse = first.get(10, TimeUnit.SECONDS);
            JsonRpcResponse secondResponse = second.get(10, TimeUnit.SECONDS);

            assertEquals("sse-a", ((JsonRpcId.StringId) firstResponse.id()).stringValue());
            assertEquals("sse-a", firstResponse.result().get("answer").asText());
            assertEquals("sse-b", ((JsonRpcId.StringId) secondResponse.id()).stringValue());
            assertEquals("sse-b", secondResponse.result().get("answer").asText());
        } finally {
            client.close();
        }
    }

    private static SecurityContext context() {
        return SecurityContext.of(AgentIdentity.anonymous(), null);
    }

    private static JsonRpcRequest toolCall(String id) {
        return new JsonRpcRequest(JsonRpcId.of(id), "tools/call", null);
    }
}
