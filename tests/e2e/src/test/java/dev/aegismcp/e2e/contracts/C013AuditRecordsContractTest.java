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
 * C-013: GET /api/v1/audit/records. Anchors: C-013, FEAT-007.
 */
class C013AuditRecordsContractTest extends ArtifactTest {

    private static final String AGENT = "agent-audited";

    @Test
    @DisplayName("C-013: queries audit records by decision")
    void queriesAuditRecordsByDecision() throws Exception {
        GatewayHarness harness = gateway();
        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", harness.agentToken(AGENT),
                GatewayHarness.toolCall("audit-1", "echo", "{}")));
        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", harness.agentToken(AGENT),
                GatewayHarness.toolCall("audit-2", "forbidden_tool", "{}")), 403, -32001);

        JsonNode allowed = awaitRecord(harness, "?decision=allow&agentId=" + AGENT);
        assertEquals("allow", allowed.path("decision").asText());
        assertEquals(AGENT, allowed.path("agentId").asText());
        assertEquals("echo", allowed.path("toolName").asText());
        assertTrue(allowed.path("blockIndex").asLong() >= 1);
        assertTrue(allowed.path("blockHash").isTextual());
        assertTrue(allowed.path("parentHash").isTextual());
        assertTrue(allowed.path("argumentsHash").isTextual());
        assertTrue(allowed.path("redactionCount").isInt());
        assertTrue(allowed.path("latencyMs").isNumber());
        ContractAssertions.assertIso8601(allowed.path("timestamp").asText(), "timestamp");
        assertTrue(allowed.path("reviewedBy").isNull());

        HttpResponse<String> blockedResponse = harness.get(
                "/api/v1/audit/records?decision=block&agentId=" + AGENT + "&toolName=forbidden_tool",
                harness.auditorToken());
        ContractAssertions.assertStatus(200, blockedResponse);
        JsonNode blocked = GatewayHarness.json(blockedResponse);
        assertTrue(blocked.path("total").asInt() >= 1);
        assertEquals("block", blocked.path("records").get(0).path("decision").asText());

        HttpResponse<String> page = harness.get("/api/v1/audit/records?limit=1&offset=0",
                harness.adminToken());
        ContractAssertions.assertStatus(200, page);
        JsonNode pageBody = GatewayHarness.json(page);
        assertEquals(1, pageBody.path("records").size());
        assertTrue(pageBody.path("total").asInt() >= 1);
    }

    @Test
    @DisplayName("C-013: rejects every invalid query parameter with 400")
    void rejectsInvalidQueryParameters() throws Exception {
        GatewayHarness harness = gateway();
        String admin = harness.adminToken();
        for (String query : new String[]{
                "?decision=deny",
                "?limit=0", "?limit=501", "?limit=abc",
                "?offset=-1", "?offset=abc",
                "?from=yesterday", "?to=not-a-date"}) {
            ContractAssertions.assertStatus(400, harness.get("/api/v1/audit/records" + query, admin));
        }
    }

    @Test
    @DisplayName("C-013: refuses a missing credential with 401 and a viewer with 403")
    void refusesUnauthorisedCaller() throws Exception {
        ContractAssertions.assertStatus(401, gateway().get("/api/v1/audit/records", null));
        ContractAssertions.assertStatus(403, gateway().get("/api/v1/audit/records", gateway().viewerToken()));
    }

    private static JsonNode awaitRecord(GatewayHarness harness, String query) throws Exception {
        long deadline = System.nanoTime() + java.time.Duration.ofSeconds(15).toNanos();
        while (System.nanoTime() < deadline) {
            HttpResponse<String> response = harness.get("/api/v1/audit/records" + query, harness.auditorToken());
            ContractAssertions.assertStatus(200, response);
            JsonNode records = GatewayHarness.json(response).path("records");
            if (records.size() > 0) {
                return records.get(0);
            }
            Thread.sleep(100);
        }
        throw new AssertionError("The ledger did not expose a matching audit record within 15s");
    }
}
