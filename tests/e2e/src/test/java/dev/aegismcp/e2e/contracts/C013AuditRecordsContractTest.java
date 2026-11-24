package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import dev.aegismcp.e2e.fixtures.GatewayOptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
    @DisplayName("C-013: seals the verified reviewer on approved and rejected interactions")
    void sealsReviewerOnApprovedAndRejectedInteractions() throws Exception {
        GatewayHarness harness = gateway();

        String approvedAgent = "agent-reviewed-approve";
        GatewayHarness.PendingCall approved = harness.createPendingCall(approvedAgent, "deploy_prod",
                "{\"environment\":\"production\",\"token\":\"sentinel-approved-credential\"}");
        ContractAssertions.assertStatus(200, harness.postJson(
                "/api/v1/approvals/" + approved.ticketId() + "/approve", harness.operatorToken(), ""));
        ContractAssertions.assertStatus(200, approved.response().get(10, TimeUnit.SECONDS));

        JsonNode approvedRecord = awaitRecord(harness, "?decision=allow&agentId=" + approvedAgent);
        assertEquals("deploy_prod", approvedRecord.path("toolName").asText());
        assertEquals(GatewayHarness.OPERATOR_SUBJECT, approvedRecord.path("reviewedBy").asText(),
                "The verified reviewer must be sealed on the approved record");
        assertEquals(64, approvedRecord.path("argumentsHash").asText().length());
        assertFalse(approvedRecord.toString().contains("sentinel-approved-credential"),
                "The raw arguments must never be returned by the audit query");

        String rejectedAgent = "agent-reviewed-reject";
        GatewayHarness.PendingCall rejected = harness.createPendingCall(rejectedAgent, "deploy_prod", "{}");
        ContractAssertions.assertStatus(200, harness.postJson(
                "/api/v1/approvals/" + rejected.ticketId() + "/reject", harness.operatorToken(),
                "{\"reason\":\"Unsafe release window\"}"));
        ContractAssertions.assertRpcError(rejected.response().get(10, TimeUnit.SECONDS),
                403, -32002, "APPROVAL_DENIED");

        JsonNode rejectedRecord = awaitRecord(harness, "?decision=block&agentId=" + rejectedAgent);
        assertEquals("deploy_prod", rejectedRecord.path("toolName").asText());
        assertEquals(GatewayHarness.OPERATOR_SUBJECT, rejectedRecord.path("reviewedBy").asText(),
                "The rejecting reviewer must be sealed on the blocked record");
        assertTrue(rejectedRecord.path("argumentsHash").isTextual());
    }

    @Test
    @DisplayName("C-013: leaves the reviewer null when no approval applied and digests canonical arguments")
    void unreviewedRecordsCarryNullReviewer() throws Exception {
        GatewayHarness harness = gateway();

        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc",
                harness.agentToken("agent-unreviewed-a"),
                GatewayHarness.toolCall("plain-a", "echo", "{\"alpha\":1,\"beta\":2}")));
        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc",
                harness.agentToken("agent-unreviewed-b"),
                GatewayHarness.toolCall("plain-b", "echo", "{\"beta\":2,\"alpha\":1}")));

        JsonNode first = awaitRecord(harness, "?decision=allow&agentId=agent-unreviewed-a");
        JsonNode second = awaitRecord(harness, "?decision=allow&agentId=agent-unreviewed-b");

        assertTrue(first.path("reviewedBy").isNull(), "A call that needed no approval has no reviewer");
        assertTrue(second.path("reviewedBy").isNull());
        assertEquals(64, first.path("argumentsHash").asText().length());
        assertEquals(first.path("argumentsHash").asText(), second.path("argumentsHash").asText(),
                "The same arguments in a different field order must seal the same digest");
    }

    @Test
    @DisplayName("C-013: seals an expired approval without a reviewer")
    void sealsExpiredApprovalWithoutReviewer() throws Exception {
        try (GatewayHarness harness = start(GatewayOptions.defaults().approvalTtl(Duration.ofSeconds(1)))) {
            String agent = "agent-review-expired";
            GatewayHarness.PendingCall pending = harness.createPendingCall(agent, "deploy_prod",
                    "{\"environment\":\"production\"}");

            ContractAssertions.assertRpcError(pending.response().get(15, TimeUnit.SECONDS),
                    408, -32002, "APPROVAL_TIMEOUT");

            JsonNode expired = awaitRecord(harness, "?decision=block&agentId=" + agent);
            assertEquals("deploy_prod", expired.path("toolName").asText());
            assertTrue(expired.path("reviewedBy").isNull(),
                    "An automatic expiry carries no human reviewer");
            assertTrue(expired.path("argumentsHash").isTextual());
        }
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
