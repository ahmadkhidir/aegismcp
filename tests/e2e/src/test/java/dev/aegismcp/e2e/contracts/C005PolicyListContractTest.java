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
 * C-005: GET /api/v1/policies. Anchors: C-005, FEAT-002.
 */
class C005PolicyListContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-005: lists policies filtered by status")
    void listsPoliciesFilteredByStatus() throws Exception {
        GatewayHarness harness = gateway();
        HttpResponse<String> response = harness.get("/api/v1/policies?status=active", harness.auditorToken());
        ContractAssertions.assertStatus(200, response);
        JsonNode policies = GatewayHarness.json(response).path("policies");
        assertEquals(1, policies.size(), "The startup policy is the only active version");

        JsonNode policy = policies.get(0);
        assertEquals("pol_e2e_contracts", policy.path("id").asText());
        assertEquals("E2E Contract Policy", policy.path("name").asText());
        assertEquals("1.0.0", policy.path("version").asText());
        assertEquals("active", policy.path("status").asText());
        assertTrue(policy.path("rawYaml").asText().contains("id: pol_e2e_contracts"));
        assertTrue(policy.has("gitCommitHash"));
        ContractAssertions.assertIso8601(policy.path("createdAt").asText(), "createdAt");

        HttpResponse<String> all = harness.get("/api/v1/policies", harness.operatorToken());
        ContractAssertions.assertStatus(200, all);
        assertTrue(GatewayHarness.json(all).path("policies").size() >= 1);
    }

    @Test
    @DisplayName("C-005: rejects a status outside the declared vocabulary with 400")
    void rejectsInvalidStatus() throws Exception {
        ContractAssertions.assertStatus(400,
                gateway().get("/api/v1/policies?status=retired", gateway().adminToken()));
    }

    @Test
    @DisplayName("C-005: refuses a missing credential with 401 and a viewer with 403")
    void refusesUnauthorisedCaller() throws Exception {
        ContractAssertions.assertStatus(401, gateway().get("/api/v1/policies", null));
        ContractAssertions.assertStatus(403, gateway().get("/api/v1/policies", gateway().viewerToken()));
    }
}
