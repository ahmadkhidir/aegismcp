package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * C-022: GET /health. Anchors: C-022, FEAT-001, NFR-010.
 */
class C022HealthContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-022: answers the liveness probe while dependencies are down")
    void answersLivenessProbeWhileDependenciesAreDown() throws Exception {
        // The gateway is configured without an upstream, so the dependency state is degraded while
        // the process still serves requests. Liveness must not reflect that.
        try (GatewayHarness harness = start(dev.aegismcp.e2e.fixtures.GatewayOptions.defaults()
                .upstreamConfigured(false))) {
            HttpResponse<String> response = harness.get("/health", null);
            ContractAssertions.assertStatus(200, response);
            JsonNode body = GatewayHarness.json(response);
            assertEquals("UP", body.path("status").asText());
            assertEquals(1, body.size(), "The liveness body carries only status");
        }
    }

    @Test
    @DisplayName("C-022: rejects a non-GET method with 405")
    void rejectsNonGetMethod() throws Exception {
        HttpResponse<String> response = gateway().postJson("/health", null, "{}");
        ContractAssertions.assertError(response, 405, "Method Not Allowed");
        ContractAssertions.assertNoInternalDetail(response);
    }
}
