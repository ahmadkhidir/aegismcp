package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import dev.aegismcp.e2e.fixtures.GatewayOptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * C-023: GET /ready. Anchors: C-023, FEAT-001, NFR-010.
 */
class C023ReadinessContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-023: reports dependency health and refuses traffic when down")
    void reportsDependencyHealthAndRefusesTrafficWhenDown() throws Exception {
        HttpResponse<String> ready = gateway().get("/ready", null);
        ContractAssertions.assertStatus(200, ready);
        JsonNode body = GatewayHarness.json(ready);
        assertEquals("UP", body.path("status").asText());
        assertEquals("UP", body.path("checks").path("configuration").path("status").asText());
        assertEquals("UP", body.path("checks").path("policy").path("status").asText());
        assertEquals("UP", body.path("checks").path("auditLedger").path("status").asText());
        ContractAssertions.assertIso8601(body.path("timestamp").asText(), "timestamp");

        try (GatewayHarness degraded = start(GatewayOptions.defaults().upstreamConfigured(false))) {
            HttpResponse<String> down = degraded.get("/ready", null);
            ContractAssertions.assertStatus(503, down);
            JsonNode downBody = GatewayHarness.json(down);
            assertEquals("DOWN", downBody.path("status").asText());
            assertEquals("CONFIGURATION_INVALID", downBody.path("reason").asText());
            assertEquals("DOWN", downBody.path("checks").path("configuration").path("status").asText());
        }
    }

    @Test
    @DisplayName("C-023: rejects a non-GET method with 405")
    void rejectsNonGetMethod() throws Exception {
        HttpResponse<String> response = gateway().postJson("/ready", null, "{}");
        ContractAssertions.assertError(response, 405, "Method Not Allowed");
        ContractAssertions.assertNoInternalDetail(response);
    }
}
