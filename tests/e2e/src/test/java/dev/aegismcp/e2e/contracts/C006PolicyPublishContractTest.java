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
 * C-006: POST /api/v1/policies. Anchors: C-006, FEAT-002.
 */
class C006PolicyPublishContractTest extends ArtifactTest {

    private static final String DRAFT_YAML = """
            id: pol_published_e2e
            name: Published E2E Policy
            version: 2.0.0
            targetAgents:
              - "*"
            rules:
              - id: rule_echo
                tool: echo
                action: allow
            """;

    @Test
    @DisplayName("C-006: publishes a draft policy version")
    void publishesDraftPolicyVersion() throws Exception {
        GatewayHarness harness = gateway();
        String body = requestBody("Published E2E Policy", "2.0.0", DRAFT_YAML, "abc123");

        HttpResponse<String> response = harness.postJson("/api/v1/policies", harness.adminToken(), body);
        ContractAssertions.assertStatus(201, response);
        JsonNode created = GatewayHarness.json(response);
        assertEquals("pol_published_e2e", created.path("id").asText());
        assertEquals("Published E2E Policy", created.path("name").asText());
        assertEquals("2.0.0", created.path("version").asText());
        assertEquals("draft", created.path("status").asText());
        ContractAssertions.assertIso8601(created.path("createdAt").asText(), "createdAt");

        JsonNode listed = GatewayHarness.json(harness.get("/api/v1/policies?status=draft", harness.adminToken()));
        assertEquals(1, listed.path("policies").size());
        assertEquals("pol_published_e2e", listed.path("policies").get(0).path("id").asText());
        assertEquals("draft", listed.path("policies").get(0).path("status").asText());

        // Publishing the identical document activates the existing draft record instead of
        // creating a duplicate (C-006).
        HttpResponse<String> duplicate = harness.postJson("/api/v1/policies", harness.adminToken(), body);
        ContractAssertions.assertStatus(201, duplicate);
        assertEquals("pol_published_e2e", GatewayHarness.json(duplicate).path("id").asText());
        assertEquals(1, GatewayHarness.json(harness.get("/api/v1/policies?status=draft",
                harness.adminToken())).path("policies").size());

        // The draft never governs traffic: the startup policy still allows echo.
        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", harness.agentToken("agent-policy"),
                GatewayHarness.toolCall("policy-1", "echo", "{}")));
    }

    @Test
    @DisplayName("C-006: rejects an invalid YAML document with 400")
    void rejectsInvalidYaml() throws Exception {
        HttpResponse<String> response = gateway().postJson("/api/v1/policies", gateway().adminToken(),
                requestBody("Broken", "1.0.0", "rules: [this is not a policy", null));
        ContractAssertions.assertStatus(400, response);
    }

    @Test
    @DisplayName("C-006: refuses a missing credential with 401 and an operator with 403")
    void refusesUnauthorisedCaller() throws Exception {
        String body = requestBody("Denied", "1.0.0", DRAFT_YAML, null);
        ContractAssertions.assertStatus(401, gateway().postJson("/api/v1/policies", null, body));
        ContractAssertions.assertStatus(403, gateway().postJson("/api/v1/policies",
                gateway().operatorToken(), body));
    }

    static String requestBody(String name, String version, String rawYaml, String commit) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode body = mapper.createObjectNode();
        body.put("name", name);
        body.put("version", version);
        body.put("rawYaml", rawYaml);
        if (commit != null) {
            body.put("gitCommitHash", commit);
        }
        return mapper.writeValueAsString(body);
    }
}
