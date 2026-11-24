package dev.aegismcp.e2e.fixtures;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;

/**
 * Local Slack-compatible webhook that records the approval messages the gateway posts. It is a mock
 * destination outside the gateway, never a pipeline component. Anchors: FEAT-006, C-024.
 */
public final class TestSlackWebhook implements AutoCloseable {

    private final HttpServer server;
    private final List<String> payloads = new CopyOnWriteArrayList<>();

    public TestSlackWebhook() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/slack", exchange -> {
            byte[] body;
            try (InputStream input = exchange.getRequestBody()) {
                body = input.readAllBytes();
            }
            payloads.add(new String(body, StandardCharsets.UTF_8));
            byte[] response = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(response);
            }
        });
        server.start();
    }

    public String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/slack";
    }

    public List<String> payloads() {
        return List.copyOf(payloads);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
