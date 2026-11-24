package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-018: PUT /api/v1/policies/active. Anchors: C-018, FEAT-002.
 */
class C018PolicyDeploymentContractTest extends ArtifactTest {

    private static final String NEW_YAML = """
            id: pol_activated_e2e
            name: Activated E2E Policy
            version: 3.0.0
            targetAgents:
              - "*"
            rules:
              - id: rule_echo
                tool: echo
                action: allow
            """;

    @Test
    @DisplayName("C-018: deploys an active policy document and archives the version it replaces")
    void deploysActivePolicyDocument() throws Exception {
        GatewayHarness harness = gateway();
        String admin = harness.adminToken();

        JsonNode activeBefore = GatewayHarness.json(harness.get("/api/v1/policies/active", admin));
        String baseVersionId = activeBefore.path("id").asText();

        ContractAssertions.assertStatus(201, harness.postJson("/api/v1/policies", admin,
                C006PolicyPublishContractTest.requestBody("Activated E2E Policy", "3.0.0", NEW_YAML, "def456")));

        HttpResponse<String> activation = harness.putJson("/api/v1/policies/active", admin,
                activationBody("3.0.0", baseVersionId, NEW_YAML));
        ContractAssertions.assertStatus(200, activation);
        JsonNode activated = GatewayHarness.json(activation);
        assertEquals("pol_activated_e2e", activated.path("id").asText());
        assertEquals("3.0.0", activated.path("version").asText());
        assertEquals("active", activated.path("status").asText());
        assertEquals("Activated E2E Policy", activated.path("name").asText());
        assertEquals("def456", activated.path("gitCommitHash").asText());

        JsonNode current = GatewayHarness.json(harness.get("/api/v1/policies/active", admin));
        assertEquals("pol_activated_e2e", current.path("id").asText());

        JsonNode archived = GatewayHarness.json(harness.get("/api/v1/policies?status=archived", admin));
        boolean oldIsArchived = false;
        for (JsonNode policy : archived.path("policies")) {
            if (baseVersionId.equals(policy.path("id").asText())) {
                oldIsArchived = "archived".equals(policy.path("status").asText());
            }
        }
        assertTrue(oldIsArchived, "The replaced version is archived and readable through C-005");
    }

    @Test
    @DisplayName("C-018: rejects a missing baseVersionId or invalid YAML with 400")
    void rejectsInvalidActivation() throws Exception {
        GatewayHarness harness = gateway();
        String admin = harness.adminToken();
        String activeId = GatewayHarness.json(harness.get("/api/v1/policies/active", admin)).path("id").asText();

        ContractAssertions.assertStatus(400, harness.putJson("/api/v1/policies/active", admin,
                "{\"version\":\"3.0.0\",\"rawYaml\":\"id: x\\nname: x\\nversion: 3.0.0\\ntargetAgents: ['*']\\nrules: []\"}"));
        ContractAssertions.assertStatus(400, harness.putJson("/api/v1/policies/active", admin,
                activationBody("3.0.0", activeId, "rules: [broken")));
    }

    @Test
    @DisplayName("C-018: refuses an activation whose base version is stale with 409")
    void refusesStaleBaseVersion() throws Exception {
        GatewayHarness harness = gateway();
        String admin = harness.adminToken();
        String staleBase = GatewayHarness.json(harness.get("/api/v1/policies/active", admin)).path("id").asText();

        ContractAssertions.assertStatus(201, harness.postJson("/api/v1/policies", admin,
                C006PolicyPublishContractTest.requestBody("First Activation", "3.0.0", NEW_YAML, null)));
        ContractAssertions.assertStatus(200, harness.putJson("/api/v1/policies/active", admin,
                activationBody("3.0.0", staleBase, NEW_YAML)));

        ContractAssertions.assertStatus(409, harness.putJson("/api/v1/policies/active", admin,
                activationBody("3.0.0", staleBase, NEW_YAML)));
    }

    @Test
    @DisplayName("C-018: refuses a missing credential with 401 and an operator with 403")
    void refusesUnauthorisedCaller() throws Exception {
        GatewayHarness harness = gateway();
        String body = activationBody("3.0.0", "", NEW_YAML);
        ContractAssertions.assertStatus(401, harness.putJson("/api/v1/policies/active", null, body));
        ContractAssertions.assertStatus(403, harness.putJson("/api/v1/policies/active",
                harness.operatorToken(), body));
    }

    private static String activationBody(String version, String baseVersionId, String rawYaml) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode body = mapper.createObjectNode();
        body.put("version", version);
        body.put("baseVersionId", baseVersionId);
        body.put("rawYaml", rawYaml);
        return mapper.writeValueAsString(body);
    }
}
