package dev.aegismcp.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.config.GatewayConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Verifies the explicit probe-only deployment: the packaged constructor accepts a configuration
 * with no serving settings, the probes answer, readiness reports the configuration as invalid, and
 * no agent request path is attached.
 *
 * <p>Anchors: C-022, C-023, NFR-010, NFR-027.
 */
class ProbeOnlyModeTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private AegisGatewayServer server;

    @AfterEach
    void tearDown() {
        if (server != null && server.isRunning()) {
            server.stop();
        }
    }

    @Test
    @DisplayName("C-023: probe-only mode boots, reports CONFIGURATION_INVALID, and refuses agent calls")
    void probeOnlyModeServesProbesAndRefusesAgentTraffic() throws Exception {
        GatewayConfiguration configuration = GatewayConfiguration.load(Map.of(
                GatewayConfiguration.PROBE_ONLY_ENV, "true",
                "AEGIS_GATEWAY_HOST", "127.0.0.1",
                "AEGIS_GATEWAY_PORT", "0"));
        server = new AegisGatewayServer(configuration);
        server.start();

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();

        HttpResponse<String> health = get(client, "/health");
        assertEquals(200, health.statusCode());
        assertEquals("UP", JSON.readTree(health.body()).path("status").asText());

        HttpResponse<String> ready = get(client, "/ready");
        assertEquals(503, ready.statusCode());
        JsonNode readiness = JSON.readTree(ready.body());
        assertEquals("DOWN", readiness.path("status").asText());
        assertEquals("CONFIGURATION_INVALID", readiness.path("reason").asText());
        assertEquals("DOWN", readiness.path("checks").path("configuration").path("status").asText());
        assertEquals("UP", readiness.path("checks").path("policy").path("status").asText());
        assertEquals("UP", readiness.path("checks").path("auditLedger").path("status").asText());

        HttpResponse<String> agentCall = client.send(HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + server.getPort() + "/mcp/v1/rpc"))
                .timeout(Duration.ofSeconds(2))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                                + "\"params\":{\"name\":\"echo\",\"arguments\":{}}}",
                        StandardCharsets.UTF_8))
                .build(), HttpResponse.BodyHandlers.ofString());

        assertEquals(404, agentCall.statusCode(), "A probe-only node must attach no agent request path");
        assertEquals("{\"error\":\"Not Found\"}", agentCall.body());
        assertNull(server.getMcpProxyHandler());
        assertNull(server.getIdentityVerificationHandler());
        assertNull(server.getDlpOutboundHandler());
    }

    private HttpResponse<String> get(HttpClient client, String path) throws Exception {
        return client.send(HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + server.getPort() + path))
                .timeout(Duration.ofSeconds(2))
                .GET()
                .build(), HttpResponse.BodyHandlers.ofString());
    }
}
