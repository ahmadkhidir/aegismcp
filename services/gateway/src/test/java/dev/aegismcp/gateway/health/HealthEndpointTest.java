package dev.aegismcp.gateway.health;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.AegisGatewayServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Artifact-level tests booting the real gateway on an ephemeral port and exercising the probe
 * endpoints over HTTP.
 * Anchors: C-022, C-023, FEAT-001, NFR-010.
 */
class HealthEndpointTest {

    private static final List<String> CHECK_NAMES = List.of("configuration", "policy", "auditLedger");

    private final ObjectMapper jsonMapper = new ObjectMapper();

    private AegisGatewayServer server;
    private HttpClient client;

    @BeforeEach
    void startGateway() throws InterruptedException {
        server = new AegisGatewayServer("127.0.0.1", 0);
        server.start();
        client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    }

    @AfterEach
    void stopGateway() {
        if (server != null && server.isRunning()) {
            server.stop();
        }
    }

    @Test
    void answersLivenessProbeWithExactBody() throws Exception {
        HttpResponse<String> response = send("/health", "GET");

        assertEquals(200, response.statusCode());
        assertEquals("application/json", response.headers().firstValue("content-type").orElse(""));
        assertEquals("{\"status\":\"UP\"}", response.body());
    }

    @Test
    void livenessStaysUpWhileAReadinessCheckFails() throws Exception {
        server.getReadiness().markDependencyUnhealthy(GatewayReadiness.Dependency.AUDIT_LEDGER);

        assertEquals(200, send("/health", "GET").statusCode());
        assertEquals(503, send("/ready", "GET").statusCode());
    }

    @Test
    void readinessProbeReportsUpDependenciesAndTimestamp() throws Exception {
        HttpResponse<String> response = send("/ready", "GET");

        assertEquals(200, response.statusCode());
        assertEquals("application/json", response.headers().firstValue("content-type").orElse(""));

        JsonNode payload = jsonMapper.readTree(response.body());
        assertEquals("UP", payload.get("status").asText());
        assertTrue(payload.get("reason") == null || payload.get("reason").isNull(),
                "a ready node carries no reason");
        assertEquals(CHECK_NAMES, fieldNames(payload.get("checks")));
        CHECK_NAMES.forEach(check ->
                assertEquals("UP", payload.get("checks").get(check).get("status").asText()));
        assertEquals(payload.get("timestamp").asText(), Instant.parse(payload.get("timestamp").asText()).toString());
    }

    @Test
    void readinessProbeRefusesTrafficWhileAReadinessCheckFails() throws Exception {
        server.getReadiness().markDependencyUnhealthy(GatewayReadiness.Dependency.POLICY);

        HttpResponse<String> response = send("/ready", "GET");

        assertEquals(503, response.statusCode());
        JsonNode payload = jsonMapper.readTree(response.body());
        assertEquals("DOWN", payload.get("status").asText());
        assertEquals("POLICY_INVALID", payload.get("reason").asText());
        assertEquals(CHECK_NAMES, fieldNames(payload.get("checks")));
        assertEquals("UP", payload.get("checks").get("configuration").get("status").asText());
        assertEquals("DOWN", payload.get("checks").get("policy").get("status").asText());
        assertEquals("UP", payload.get("checks").get("auditLedger").get("status").asText());
        assertEquals(payload.get("timestamp").asText(), Instant.parse(payload.get("timestamp").asText()).toString());
    }

    @Test
    void readinessProbeReportsShuttingDown() throws Exception {
        server.getReadiness().markShuttingDown();

        HttpResponse<String> response = send("/ready", "GET");

        assertEquals(503, response.statusCode());
        JsonNode payload = jsonMapper.readTree(response.body());
        assertEquals("DOWN", payload.get("status").asText());
        assertEquals("SHUTTING_DOWN", payload.get("reason").asText());
    }

    @Test
    void rejectsNonGetProbeRequests() throws Exception {
        HttpResponse<String> liveness = send("/health", "POST");
        assertEquals(405, liveness.statusCode());
        assertEquals("{\"error\":\"Method Not Allowed\"}", liveness.body());

        HttpResponse<String> readiness = send("/ready", "POST");
        assertEquals(405, readiness.statusCode());
        assertEquals("{\"error\":\"Method Not Allowed\"}", readiness.body());
    }

    private HttpResponse<String> send(String path, String method) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + server.getPort() + path))
                .method(method, HttpRequest.BodyPublishers.noBody())
                .timeout(Duration.ofSeconds(5))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new java.util.ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
