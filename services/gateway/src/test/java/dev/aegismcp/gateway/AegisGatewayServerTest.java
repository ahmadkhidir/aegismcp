package dev.aegismcp.gateway;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests verifying foundational Netty gateway lifecycle and virtual thread dispatch.
 * Anchors: FEAT-001, NFR-001.
 */
class AegisGatewayServerTest {

    private AegisGatewayServer server;

    @BeforeEach
    void setUp() {
        // Bind to ephemeral port 0 for hermetic unit testing
        server = new AegisGatewayServer("127.0.0.1", 0);
    }

    @AfterEach
    void tearDown() {
        if (server != null && server.isRunning()) {
            server.stop();
        }
    }

    @Test
    void testServerLifecycleAndHealthCheck() throws InterruptedException, IOException {
        assertFalse(server.isRunning(), "Server should not be running prior to start()");

        server.start();

        assertTrue(server.isRunning(), "Server should be running after start()");
        assertTrue(server.getPort() > 0, "Bound ephemeral port must be positive");
        assertNotNull(server.getServerChannel(), "Server channel must be active");
        assertTrue(server.getServerChannel().isActive(), "Server channel should be active");

        // Verify HTTP dispatch via Loom virtual thread executor
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + server.getPort() + "/health"))
                .GET()
                .timeout(Duration.ofSeconds(2))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
        assertEquals("application/json", response.headers().firstValue("content-type").orElse(""));
        assertEquals("{\"status\":\"UP\"}", response.body());

        // Verify clean graceful shutdown
        server.stop();
        assertFalse(server.isRunning(), "Server should not be running after stop()");
    }

    @Test
    void testIdempotentStop() {
        server.stop();
        assertFalse(server.isRunning());
    }
}
