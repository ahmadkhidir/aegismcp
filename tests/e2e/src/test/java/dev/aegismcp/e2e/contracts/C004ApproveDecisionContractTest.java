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

/**
 * C-004: POST /api/v1/approvals/{id}/approve. Anchors: C-004, FEAT-006, C-001.
 */
class C004ApproveDecisionContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-004: approves a pending ticket and resumes execution")
    void approvesPendingTicketAndResumesExecution() throws Exception {
        GatewayHarness harness = gateway();
        GatewayHarness.PendingCall pending = harness.createPendingCall("agent-approve", "deploy_prod",
                "{\"environment\":\"production\"}");

        HttpResponse<String> decision = harness.postJson(
                "/api/v1/approvals/" + pending.ticketId() + "/approve", harness.operatorToken(), "");
        ContractAssertions.assertStatus(200, decision);
        JsonNode body = GatewayHarness.json(decision);
        assertEquals(pending.ticketId(), body.path("ticketId").asText());
        assertEquals("approved", body.path("status").asText());
        assertEquals(GatewayHarness.OPERATOR_SUBJECT, body.path("reviewedBy").asText());
        ContractAssertions.assertIso8601(body.path("processedAt").asText(), "processedAt");

        HttpResponse<String> agent = pending.response().get(10, TimeUnit.SECONDS);
        ContractAssertions.assertStatus(200, agent);
        assertEquals("deploy_prod", GatewayHarness.json(agent).path("result").path("tool").asText());

        // A second decision on the resolved ticket is a conflict, not a second approval.
        HttpResponse<String> replay = harness.postJson(
                "/api/v1/approvals/" + pending.ticketId() + "/approve", harness.operatorToken(), "");
        ContractAssertions.assertStatus(409, replay);
    }

    @Test
    @DisplayName("C-004: answers an unknown ticket with 404")
    void reportsUnknownTicket() throws Exception {
        ContractAssertions.assertStatus(404, gateway().postJson(
                "/api/v1/approvals/appr_00000000000000000000000000/approve",
                gateway().operatorToken(), ""));
    }

    @Test
    @DisplayName("C-004: answers a decision that arrives after the deadline with 410")
    void reportsExpiredTicket() throws Exception {
        try (GatewayHarness harness = start(GatewayOptions.defaults().approvalTtl(Duration.ofSeconds(1)))) {
            GatewayHarness.PendingCall pending = harness.createPendingCall("agent-late", "deploy_prod", "{}");
            pending.response().get(15, TimeUnit.SECONDS);
            ContractAssertions.assertStatus(410, harness.postJson(
                    "/api/v1/approvals/" + pending.ticketId() + "/approve", harness.operatorToken(), ""));
        }
    }

    @Test
    @DisplayName("C-004: refuses a missing credential with 401 and a viewer with 403")
    void refusesUnauthorisedReviewer() throws Exception {
        GatewayHarness harness = gateway();
        GatewayHarness.PendingCall pending = harness.createPendingCall("agent-rbac", "deploy_prod", "{}");
        String path = "/api/v1/approvals/" + pending.ticketId() + "/approve";

        ContractAssertions.assertStatus(401, harness.postJson(path, null, ""));
        ContractAssertions.assertStatus(403, harness.postJson(path, harness.viewerToken(), ""));

        harness.postJson("/api/v1/approvals/" + pending.ticketId() + "/reject", harness.operatorToken(),
                "{\"reason\":\"cleanup\"}");
    }
}
