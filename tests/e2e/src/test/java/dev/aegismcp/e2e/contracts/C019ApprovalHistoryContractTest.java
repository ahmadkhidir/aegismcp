package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-019: GET /api/v1/approvals. Anchors: C-019, FEAT-006.
 */
class C019ApprovalHistoryContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-019: lists rejected approval history")
    void listsRejectedApprovalHistory() throws Exception {
        GatewayHarness harness = gateway();
        GatewayHarness.PendingCall pending = harness.createPendingCall("agent-history", "deploy_prod", "{}");
        ContractAssertions.assertStatus(200, harness.postJson(
                "/api/v1/approvals/" + pending.ticketId() + "/reject", harness.operatorToken(),
                "{\"reason\":\"Auditor refused the change\"}"));
        pending.response().get(10, TimeUnit.SECONDS);

        HttpResponse<String> response = harness.get("/api/v1/approvals?status=rejected", harness.auditorToken());
        ContractAssertions.assertStatus(200, response);
        JsonNode body = GatewayHarness.json(response);
        assertTrue(body.path("total").asInt() >= 1);
        JsonNode ticket = null;
        for (JsonNode item : body.path("tickets")) {
            if (pending.ticketId().equals(item.path("id").asText())) {
                ticket = item;
            }
        }
        assertTrue(ticket != null, "The rejected ticket appears in the history");
        assertEquals("rejected", ticket.path("status").asText());
        assertEquals("agent-history", ticket.path("agentId").asText());
        assertEquals("deploy_prod", ticket.path("toolName").asText());
        assertEquals(GatewayHarness.OPERATOR_SUBJECT, ticket.path("reviewedBy").asText());
        assertEquals("Auditor refused the change", ticket.path("rejectionReason").asText());
        ContractAssertions.assertIso8601(ticket.path("processedAt").asText(), "processedAt");
        ContractAssertions.assertIso8601(ticket.path("createdAt").asText(), "createdAt");
        ContractAssertions.assertIso8601(ticket.path("expiresAt").asText(), "expiresAt");
        assertTrue(ticket.path("argumentsPayload").isTextual());
        assertTrue(ticket.path("triggerPolicyId").isTextual());
    }

    @Test
    @DisplayName("C-019: rejects a missing or invalid status, limit, or offset with 400")
    void rejectsInvalidQueryParameters() throws Exception {
        GatewayHarness harness = gateway();
        String admin = harness.adminToken();
        for (String query : new String[]{
                "", "?status=", "?status=pending",
                "?status=rejected&limit=0", "?status=rejected&limit=101",
                "?status=rejected&offset=-1", "?status=rejected&offset=abc"}) {
            HttpResponse<String> response = harness.get("/api/v1/approvals" + query, admin);
            ContractAssertions.assertStatus(400, response);
        }
    }

    @Test
    @DisplayName("C-019: refuses a missing credential with 401 and a viewer with 403")
    void refusesUnauthorisedCaller() throws Exception {
        ContractAssertions.assertStatus(401,
                gateway().get("/api/v1/approvals?status=rejected", null));
        ContractAssertions.assertStatus(403,
                gateway().get("/api/v1/approvals?status=rejected", gateway().viewerToken()));
    }
}
