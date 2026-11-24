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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-017: GET /api/v1/policies/active. Anchors: C-017, FEAT-002.
 */
class C017ActivePolicyContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-017: returns the active policy document")
    void returnsActivePolicyDocument() throws Exception {
        HttpResponse<String> response = gateway().get("/api/v1/policies/active", gateway().auditorToken());
        ContractAssertions.assertStatus(200, response);
        JsonNode policy = GatewayHarness.json(response);
        assertEquals("pol_e2e_contracts", policy.path("id").asText());
        assertEquals("E2E Contract Policy", policy.path("name").asText());
        assertEquals("1.0.0", policy.path("version").asText());
        assertEquals("active", policy.path("status").asText());
        assertTrue(policy.path("rawYaml").asText().contains("pol_e2e_contracts"));
        assertTrue(policy.has("gitCommitHash"));
        ContractAssertions.assertIso8601(policy.path("createdAt").asText(), "createdAt");
    }

    @Test
    @DisplayName("C-017: answers 404 when no policy version is active")
    void answersNotFoundWithoutActivePolicy() throws Exception {
        // A serving node must name a policy document, so this deployment supplies one that cannot
        // compile: the gateway boots, reports POLICY_INVALID, and no version is active.
        try (GatewayHarness harness = start(GatewayOptions.defaults().policyYaml(""))) {
            ContractAssertions.assertStatus(404,
                    harness.get("/api/v1/policies/active", harness.adminToken()));
        }
    }

    @Test
    @DisplayName("C-017: refuses a missing credential with 401 and a viewer with 403")
    void refusesUnauthorisedCaller() throws Exception {
        ContractAssertions.assertStatus(401, gateway().get("/api/v1/policies/active", null));
        ContractAssertions.assertStatus(403, gateway().get("/api/v1/policies/active", gateway().viewerToken()));
    }
}
