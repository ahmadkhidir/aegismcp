package dev.aegismcp.e2e.validation;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Phase 3 validation journey across C-001, C-012, and C-016 against the packaged artifact.
 * Anchors: FEAT-012, FEAT-004, NFR-024.
 */
class Phase3ParameterValidationE2ETest extends ArtifactTest {

    @Test
    @DisplayName("Phase 3: injected arguments are refused at the untrusted-body boundary")
    void rejectsInjectedArguments() throws Exception {
        GatewayHarness harness = gateway();
        String token = harness.agentToken("phase3-agent");

        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", token,
                GatewayHarness.toolCall("trav-1", "read_file", "{\"path\":\"../../etc/passwd\"}")),
                403, -32001, "PATH_TRAVERSAL");
        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", token,
                GatewayHarness.toolCall("sql-1", "echo", "{\"query\":\"' OR '1'='1\"}")),
                403, -32001, "SQL_INJECTION");
        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", token,
                GatewayHarness.toolCall("constraint-1", "constrained_tool", "{\"max_rows\":500}")),
                403, -32001, "ARGUMENT_CONSTRAINT_VIOLATED");

        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", token,
                GatewayHarness.toolCall("legit-1", "echo", "{\"message\":\"ordinary text\"}")));
    }

    @Test
    @DisplayName("Phase 3: policy simulation agrees with the live verdicts")
    void simulationAgreesWithLiveVerdicts() throws Exception {
        GatewayHarness harness = gateway();

        JsonNode allowed = GatewayHarness.json(harness.postJson("/api/v1/policies/simulate",
                harness.adminToken(), "{\"agentId\":\"a\",\"toolName\":\"echo\",\"arguments\":{}}"));
        assertEquals("ALLOWED", allowed.path("verdict").asText());

        JsonNode approval = GatewayHarness.json(harness.postJson("/api/v1/policies/simulate",
                harness.adminToken(), "{\"agentId\":\"a\",\"toolName\":\"deploy_prod\",\"arguments\":{}}"));
        assertEquals("REQUIRE_APPROVAL", approval.path("verdict").asText());

        JsonNode blocked = GatewayHarness.json(harness.postJson("/api/v1/policies/simulate",
                harness.adminToken(), "{\"agentId\":\"a\",\"toolName\":\"forbidden_tool\",\"arguments\":{}}"));
        assertEquals("BLOCKED", blocked.path("verdict").asText());
    }

    @Test
    @DisplayName("Phase 3: a blocked call is visible in the violation feed")
    void blockedCallIsVisibleInViolationFeed() throws Exception {
        GatewayHarness harness = gateway();
        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", harness.agentToken("feed-agent"),
                GatewayHarness.toolCall("feed-1", "forbidden_tool", "{}")), 403, -32001);

        HttpResponse<String> response = harness.get("/api/v1/audit/violations", harness.viewerToken());
        ContractAssertions.assertStatus(200, response);
        assertEquals("unauthorized_tool",
                GatewayHarness.json(response).path("violations").path(0).path("violationType").asText());
    }
}
