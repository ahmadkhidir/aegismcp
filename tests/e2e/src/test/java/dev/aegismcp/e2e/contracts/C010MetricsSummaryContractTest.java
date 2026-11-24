package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-010: GET /api/v1/metrics/summary. Anchors: C-010, FEAT-010.
 */
class C010MetricsSummaryContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-010: reports the twenty-four hour metric summary")
    void reportsTwentyFourHourMetricSummary() throws Exception {
        GatewayHarness harness = gateway();
        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", harness.agentToken("agent-metrics"),
                GatewayHarness.toolCall("metrics-1", "echo", "{}")));

        HttpResponse<String> response = harness.get("/api/v1/metrics/summary", harness.viewerToken());
        ContractAssertions.assertStatus(200, response);
        JsonNode body = GatewayHarness.json(response);
        assertTrue(body.path("activeAgents").isInt());
        assertTrue(body.path("toolCalls24h").asLong() >= 1);
        assertTrue(body.path("blockedViolations24h").isNumber());
        assertTrue(body.path("pendingApprovals").isInt());
        assertTrue(body.path("uptimeSeconds").asLong() >= 0);
    }

    @Test
    @DisplayName("C-010: refuses a missing credential with 401")
    void refusesUnauthenticatedCaller() throws Exception {
        ContractAssertions.assertStatus(401, gateway().get("/api/v1/metrics/summary", null));
    }

    @Test
    @DisplayName("C-010: carries exactly the five contract counters")
    void reportsIntegerCounters() throws Exception {
        JsonNode body = GatewayHarness.json(gateway().get("/api/v1/metrics/summary", gateway().adminToken()));
        assertEquals(5, body.size(), "The summary carries exactly the five C-010 counters");
    }
}
