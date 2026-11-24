package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-020: GET /api/v1/metrics/timeseries. Anchors: C-020, FEAT-010.
 */
class C020MetricsTimeseriesContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-020: returns the twenty-four hour metric timeseries")
    void returnsTwentyFourHourMetricTimeseries() throws Exception {
        GatewayHarness harness = gateway();
        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", harness.agentToken("agent-series"),
                GatewayHarness.toolCall("series-1", "ping", "{}")));

        HttpResponse<String> response = harness.get("/api/v1/metrics/timeseries", harness.viewerToken());
        ContractAssertions.assertStatus(200, response);
        JsonNode body = GatewayHarness.json(response);
        assertEquals("HOUR", body.path("interval").asText());
        assertEquals(24, body.path("buckets").size(), "The series always covers 24 hours");
        Instant previous = null;
        for (JsonNode bucket : body.path("buckets")) {
            Instant start = Instant.parse(bucket.path("bucketStart").asText());
            if (previous != null) {
                assertTrue(start.isAfter(previous), "Buckets are ordered oldest first");
            }
            previous = start;
            assertTrue(bucket.path("toolCalls").isNumber());
            assertTrue(bucket.path("blockedViolations").isNumber());
        }
    }

    @Test
    @DisplayName("C-020: refuses a missing credential with 401")
    void refusesUnauthenticatedCaller() throws Exception {
        ContractAssertions.assertStatus(401, gateway().get("/api/v1/metrics/timeseries", null));
    }
}
