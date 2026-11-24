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
 * C-016: GET /api/v1/audit/violations. Anchors: C-016, FEAT-004, FEAT-012.
 */
class C016ViolationFeedContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-016: lists recent security violations")
    void listsRecentSecurityViolations() throws Exception {
        GatewayHarness harness = gateway();
        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", harness.agentToken("agent-violation"),
                GatewayHarness.toolCall("violation-1", "forbidden_tool", "{}")), 403, -32001);

        HttpResponse<String> response = harness.get("/api/v1/audit/violations", harness.viewerToken());
        ContractAssertions.assertStatus(200, response);
        JsonNode body = GatewayHarness.json(response);
        assertTrue(body.path("violations").isArray());
        JsonNode violation = body.path("violations").get(0);
        assertTrue(violation.path("id").isTextual());
        assertEquals("agent-violation", violation.path("agentId").asText());
        assertEquals("unauthorized_tool", violation.path("violationType").asText());
        assertTrue(violation.path("blockHash").isTextual());
        assertEquals("high", violation.path("severity").asText());
        assertTrue(violation.path("details").isTextual());
        ContractAssertions.assertIso8601(violation.path("createdAt").asText(), "createdAt");
    }

    @Test
    @DisplayName("C-016: rejects an undeclared violation type, severity, limit, or timestamp with 400")
    void rejectsInvalidQueryParameters() throws Exception {
        GatewayHarness harness = gateway();
        for (String query : new String[]{
                "?violationType=unknown", "?severity=urgent", "?limit=0", "?limit=101",
                "?from=yesterday", "?to=not-a-date"}) {
            ContractAssertions.assertStatus(400,
                    harness.get("/api/v1/audit/violations" + query, harness.viewerToken()));
        }
    }

    @Test
    @DisplayName("C-016: refuses a missing credential with 401")
    void refusesUnauthenticatedCaller() throws Exception {
        ContractAssertions.assertStatus(401, gateway().get("/api/v1/audit/violations", null));
    }
}
