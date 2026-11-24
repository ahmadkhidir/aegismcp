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
 * C-012: POST /api/v1/policies/simulate. Anchors: C-012, FEAT-002.
 */
class C012PolicySimulationContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-012: simulates an allowed tool invocation without dispatching it upstream")
    void simulatesAllowedToolInvocation() throws Exception {
        GatewayHarness harness = gateway();
        int before = harness.upstream().requestCount();

        HttpResponse<String> response = harness.postJson("/api/v1/policies/simulate", harness.adminToken(),
                body("agent-sim", "echo", "{}"));
        ContractAssertions.assertStatus(200, response);
        JsonNode result = GatewayHarness.json(response);
        assertEquals("ALLOWED", result.path("verdict").asText());
        assertEquals("rule_echo", result.path("ruleMatched").asText());
        assertTrue(result.path("violations").isArray());
        assertEquals(0, result.path("violations").size());
        assertEquals(before, harness.upstream().requestCount(), "Simulation never dispatches upstream");
    }

    @Test
    @DisplayName("C-012: reports BLOCKED and REQUIRE_APPROVAL for the matching rules")
    void reportsBlockedAndApprovalVerdicts() throws Exception {
        GatewayHarness harness = gateway();
        JsonNode blocked = GatewayHarness.json(harness.postJson("/api/v1/policies/simulate",
                harness.adminToken(), body("agent-sim", "forbidden_tool", "{}")));
        assertEquals("BLOCKED", blocked.path("verdict").asText());
        assertEquals("rule_forbidden", blocked.path("ruleMatched").asText());

        JsonNode approval = GatewayHarness.json(harness.postJson("/api/v1/policies/simulate",
                harness.adminToken(), body("agent-sim", "deploy_prod", "{}")));
        assertEquals("REQUIRE_APPROVAL", approval.path("verdict").asText());
        assertEquals("rule_deploy", approval.path("ruleMatched").asText());
    }

    @Test
    @DisplayName("C-012: rejects a missing field with 400")
    void rejectsMissingFields() throws Exception {
        GatewayHarness harness = gateway();
        String admin = harness.adminToken();
        for (String payload : new String[]{
                "{\"toolName\":\"echo\",\"arguments\":{}}",
                "{\"agentId\":\"a\",\"arguments\":{}}",
                "[]"}) {
            ContractAssertions.assertStatus(400, harness.postJson("/api/v1/policies/simulate", admin, payload));
        }
    }

    @Test
    @DisplayName("C-012: rejects non-object arguments with 400")
    void rejectsNonObjectArguments() throws Exception {
        ContractAssertions.assertStatus(400, gateway().postJson("/api/v1/policies/simulate",
                gateway().adminToken(), "{\"agentId\":\"a\",\"toolName\":\"echo\",\"arguments\":[]}"));
    }

    @Test
    @DisplayName("C-012: admits an operator as the contract declares")
    void admitsOperator() throws Exception {
        ContractAssertions.assertStatus(200, gateway().postJson("/api/v1/policies/simulate",
                gateway().operatorToken(), body("agent-sim", "echo", "{}")));
    }

    @Test
    @DisplayName("C-012: refuses a missing credential with 401 and a viewer with 403")
    void refusesUnauthorisedCaller() throws Exception {
        String payload = body("agent-sim", "echo", "{}");
        ContractAssertions.assertStatus(401, gateway().postJson("/api/v1/policies/simulate", null, payload));
        ContractAssertions.assertStatus(403, gateway().postJson("/api/v1/policies/simulate",
                gateway().viewerToken(), payload));
    }

    private static String body(String agentId, String toolName, String arguments) {
        return "{\"agentId\":\"" + agentId + "\",\"toolName\":\"" + toolName
                + "\",\"arguments\":" + arguments + "}";
    }
}
