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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-014: POST /api/v1/approvals/{id}/reject. Anchors: C-014, FEAT-006, C-001.
 */
class C014ApprovalRejectionContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-014: rejects a pending ticket with a reason")
    void rejectsPendingTicketWithReason() throws Exception {
        GatewayHarness harness = gateway();
        GatewayHarness.PendingCall pending = harness.createPendingCall("agent-reject", "deploy_prod",
                "{\"environment\":\"production\"}");

        HttpResponse<String> decision = harness.postJson(
                "/api/v1/approvals/" + pending.ticketId() + "/reject", harness.operatorToken(),
                "{\"reason\":\"Change freeze in force\"}");
        ContractAssertions.assertStatus(200, decision);
        JsonNode body = GatewayHarness.json(decision);
        assertEquals(pending.ticketId(), body.path("ticketId").asText());
        assertEquals("rejected", body.path("status").asText());
        assertEquals(GatewayHarness.OPERATOR_SUBJECT, body.path("reviewedBy").asText());
        assertEquals("Change freeze in force", body.path("rejectionReason").asText());
        ContractAssertions.assertIso8601(body.path("processedAt").asText(), "processedAt");

        HttpResponse<String> agent = pending.response().get(10, TimeUnit.SECONDS);
        JsonNode agentError = ContractAssertions.assertRpcError(agent, 403, -32002, "APPROVAL_DENIED");
        assertTrue(agentError.path("id").isTextual(), "The agent response repeats its request id");

        HttpResponse<String> replay = harness.postJson(
                "/api/v1/approvals/" + pending.ticketId() + "/reject", harness.operatorToken(),
                "{\"reason\":\"Again\"}");
        ContractAssertions.assertStatus(409, replay);
    }

    @Test
    @DisplayName("C-014: refuses a missing or blank reason with 400")
    void refusesBlankReason() throws Exception {
        GatewayHarness harness = gateway();
        GatewayHarness.PendingCall pending = harness.createPendingCall("agent-blank", "deploy_prod", "{}");
        String path = "/api/v1/approvals/" + pending.ticketId() + "/reject";

        for (String body : new String[]{"", "{}", "{\"reason\":\"\"}", "{\"reason\":\"   \"}"}) {
            ContractAssertions.assertStatus(400, harness.postJson(path, harness.operatorToken(), body));
        }

        harness.postJson(path, harness.operatorToken(), "{\"reason\":\"cleanup\"}");
    }

    @Test
    @DisplayName("C-014: answers an unknown ticket with 404")
    void reportsUnknownTicket() throws Exception {
        ContractAssertions.assertStatus(404, gateway().postJson(
                "/api/v1/approvals/appr_00000000000000000000000000/reject",
                gateway().operatorToken(), "{\"reason\":\"unknown\"}"));
    }

    @Test
    @DisplayName("C-014: answers a decision that arrives after the deadline with 410")
    void reportsExpiredTicket() throws Exception {
        try (GatewayHarness harness = start(GatewayOptions.defaults().approvalTtl(Duration.ofSeconds(1)))) {
            GatewayHarness.PendingCall pending = harness.createPendingCall("agent-expired", "deploy_prod", "{}");
            pending.response().get(15, TimeUnit.SECONDS);
            ContractAssertions.assertStatus(410, harness.postJson(
                    "/api/v1/approvals/" + pending.ticketId() + "/reject", harness.operatorToken(),
                    "{\"reason\":\"late\"}"));
        }
    }

    @Test
    @DisplayName("C-014: refuses a missing credential with 401 and a viewer with 403")
    void refusesUnauthorisedReviewer() throws Exception {
        GatewayHarness harness = gateway();
        GatewayHarness.PendingCall pending = harness.createPendingCall("agent-rbac-reject", "deploy_prod", "{}");
        String path = "/api/v1/approvals/" + pending.ticketId() + "/reject";

        ContractAssertions.assertStatus(401, harness.postJson(path, null, "{\"reason\":\"no\"}"));
        ContractAssertions.assertStatus(403, harness.postJson(path, harness.viewerToken(), "{\"reason\":\"no\"}"));

        harness.postJson(path, harness.operatorToken(), "{\"reason\":\"cleanup\"}");
    }
}
