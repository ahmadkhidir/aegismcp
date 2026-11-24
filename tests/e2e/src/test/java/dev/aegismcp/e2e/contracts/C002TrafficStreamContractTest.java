package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-002: GET /api/v1/stream/traffic. Anchors: C-002, FEAT-008, NFR-005.
 */
class C002TrafficStreamContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-002: streams traffic events with heartbeat and monotonic ids")
    void streamsTrafficEventsWithHeartbeat() throws Exception {
        GatewayHarness harness = gateway();
        try (GatewayHarness.SseStream stream = harness.openStream(harness.operatorToken())) {
            assertEquals(200, stream.statusCode());
            assertTrue(stream.header("content-type").startsWith("text/event-stream"),
                    () -> "Unexpected content type: " + stream.header("content-type"));
            assertTrue(stream.header("cache-control").contains("no-cache"));

            GatewayHarness.SseEvent retry = stream.awaitEvent("retry", Duration.ofSeconds(5));
            assertNotNull(retry, "The stream opens with a retry directive");
            assertEquals("3000", retry.data());

            ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc",
                    harness.agentToken("agent-stream-1"),
                    GatewayHarness.toolCall("stream-1", "echo", "{\"message\":\"first\"}")));

            GatewayHarness.SseEvent first = stream.awaitEvent("traffic", Duration.ofSeconds(10));
            assertNotNull(first, "A traffic event must follow the intercepted tool call");
            JsonNode data = GatewayHarness.MAPPER.readTree(first.data());
            assertEquals("agent-stream-1", data.path("agentId").asText());
            assertEquals("echo", data.path("toolName").asText());
            assertEquals("ALLOWED", data.path("decision").asText());
            assertTrue(data.path("arguments").isObject());
            assertTrue(data.path("latencyMs").isNumber());
            assertTrue(data.path("matchedRuleIds").isArray());
            assertTrue(data.path("redactions").isArray());
            Instant.parse(data.path("timestamp").asText());
            assertNotNull(first.id(), "Every event carries an id");
            long firstId = Long.parseLong(first.id());

            ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc",
                    harness.agentToken("agent-stream-1"),
                    GatewayHarness.toolCall("stream-2", "ping", "{}")));
            GatewayHarness.SseEvent second = stream.awaitEvent("traffic",
                    event -> event.id() != null && Long.parseLong(event.id()) > firstId,
                    Duration.ofSeconds(10));
            assertNotNull(second, "The second event must carry a larger id");
        }
    }

    @Test
    @DisplayName("C-002: writes a keepalive comment while the stream is idle")
    void writesKeepaliveComment() throws Exception {
        GatewayHarness harness = gateway();
        try (GatewayHarness.SseStream stream = harness.openStream(harness.adminToken())) {
            assertEquals(200, stream.statusCode());
            GatewayHarness.SseEvent keepalive = stream.awaitEvent("comment",
                    event -> event.data().startsWith(": keepalive"), Duration.ofSeconds(20));
            assertNotNull(keepalive, "An idle stream writes a keepalive comment every 15 seconds");
        }
    }

    @Test
    @DisplayName("C-002: refuses an unauthenticated subscription with 401")
    void refusesUnauthenticatedSubscription() throws Exception {
        HttpResponse<String> response = gateway().get("/api/v1/stream/traffic", null);
        ContractAssertions.assertStatus(401, response);
        assertTrue(response.headers().firstValue("content-type").orElse("").contains("application/json"));
    }

    @Test
    @DisplayName("C-002: refuses an authenticated operator with no console role with 403")
    void refusesOperatorWithoutRole() throws Exception {
        HttpResponse<String> response = gateway().get("/api/v1/stream/traffic",
                gateway().token("no-role@aegis.test"));
        ContractAssertions.assertStatus(403, response);
    }
}
