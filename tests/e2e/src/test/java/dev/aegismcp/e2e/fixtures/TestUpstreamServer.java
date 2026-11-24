package dev.aegismcp.e2e.fixtures;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A local MCP upstream server the gateway reaches through its configured HTTP transport. It runs in
 * its own server, never inside the gateway pipeline, and answers the JSON-RPC envelope by
 * preserving the request id.
 * Anchors: FEAT-001, C-001.
 */
public final class TestUpstreamServer implements AutoCloseable {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final HttpServer server;
    private final AtomicInteger requests = new AtomicInteger();
    private volatile boolean sensitiveResponse = true;

    public TestUpstreamServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/mcp", this::handle);
        server.start();
    }

    public String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/mcp";
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public int requestCount() {
        return requests.get();
    }

    public void sensitiveResponse(boolean enabled) {
        this.sensitiveResponse = enabled;
    }

    private void handle(HttpExchange exchange) throws IOException {
        requests.incrementAndGet();
        byte[] requestBody;
        try (InputStream input = exchange.getRequestBody()) {
            requestBody = input.readAllBytes();
        }

        String response;
        try {
            JsonNode request = MAPPER.readTree(requestBody);
            JsonNode id = request.has("id") ? request.get("id") : MAPPER.nullNode();
            String method = request.path("method").asText("");
            if ("tools/call".equals(method)) {
                String tool = request.path("params").path("name").asText("");
                ObjectNode result = MAPPER.createObjectNode();
                result.put("tool", tool);
                result.put("method", method);
                result.put("status", "executed");
                if ("get_sensitive_config".equals(tool) && sensitiveResponse) {
                    result.put("awsAccessKey", "AKIAIOSFODNN7EXAMPLE");
                    result.put("openAiKey", "sk-proj-abc1234567890abcdef1234567890abcdef");
                    result.put("connectionString", "postgres://admin:topsecret123@db.prod.internal:5432/finance");
                    result.put("cardNumber", "4111 1111 1111 1111");
                } else {
                    result.set("arguments", request.path("params").path("arguments"));
                }
                response = envelope(id, result);
            } else {
                ObjectNode result = MAPPER.createObjectNode();
                result.put("method", method);
                result.put("status", "executed");
                response = envelope(id, result);
            }
        } catch (Exception e) {
            ObjectNode error = MAPPER.createObjectNode();
            error.put("code", -32700);
            error.put("message", "Parse error");
            ObjectNode envelope = MAPPER.createObjectNode();
            envelope.put("jsonrpc", "2.0");
            envelope.set("id", MAPPER.nullNode());
            envelope.set("error", error);
            response = envelope.toString();
        }

        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private static String envelope(JsonNode id, JsonNode result) throws Exception {
        ObjectNode envelope = MAPPER.createObjectNode();
        envelope.put("jsonrpc", "2.0");
        envelope.set("id", id);
        envelope.set("result", result);
        return MAPPER.writeValueAsString(envelope);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
