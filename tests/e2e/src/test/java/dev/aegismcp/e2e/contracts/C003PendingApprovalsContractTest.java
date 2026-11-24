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
 * C-003: GET /api/v1/approvals/pending. Anchors: C-003, FEAT-006.
 */
class C003PendingApprovalsContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-003: lists pending tickets ordered by expiry")
    void listsPendingTicketsOrderedByExpiry() throws Exception {
        GatewayHarness harness = gateway();
        GatewayHarness.PendingCall first = harness.createPendingCall("agent-first", "deploy_prod",
                "{\"environment\":\"staging\"}");
        GatewayHarness.PendingCall second = harness.createPendingCall("agent-second", "deploy_prod",
                "{\"environment\":\"production\"}");

        HttpResponse<String> response = harness.get("/api/v1/approvals/pending", harness.operatorToken());
        ContractAssertions.assertStatus(200, response);
        JsonNode tickets = GatewayHarness.json(response).path("tickets");
        assertTrue(tickets.size() >= 2);

        JsonNode firstTicket = find(tickets, "agent-first");
        JsonNode secondTicket = find(tickets, "agent-second");
        for (JsonNode ticket : tickets) {
            assertTrue(ticket.path("id").asText().matches("appr_[A-Z2-7]{26}"),
                    () -> "The ticket id is the approval identifier, got: " + ticket.path("id").asText());
        }
        assertTrue(firstTicket.path("expiresAt").asText().compareTo(secondTicket.path("expiresAt").asText()) <= 0,
                "Tickets are ordered by expiresAt ascending");
        assertEquals("pending", firstTicket.path("status").asText());
        assertEquals("deploy_prod", firstTicket.path("toolName").asText());
        assertEquals("pol_e2e_contracts", firstTicket.path("triggerPolicyId").asText());
        assertTrue(firstTicket.has("argumentsPayload"));
        assertTrue(firstTicket.path("agentIntent").isNull(), "No intent was supplied");
        ContractAssertions.assertIso8601(firstTicket.path("createdAt").asText(), "createdAt");
        ContractAssertions.assertIso8601(firstTicket.path("expiresAt").asText(), "expiresAt");

        HttpResponse<String> limited = harness.get("/api/v1/approvals/pending?limit=1", harness.operatorToken());
        ContractAssertions.assertStatus(200, limited);
        assertEquals(1, GatewayHarness.json(limited).path("tickets").size());

        harness.postJson("/api/v1/approvals/" + first.ticketId() + "/reject", harness.operatorToken(),
                "{\"reason\":\"cleanup\"}");
        harness.postJson("/api/v1/approvals/" + second.ticketId() + "/reject", harness.operatorToken(),
                "{\"reason\":\"cleanup\"}");
    }

    @Test
    @DisplayName("C-003: rejects an out-of-range or non-integer limit with 400")
    void rejectsInvalidLimit() throws Exception {
        GatewayHarness harness = gateway();
        for (String limit : new String[]{"0", "101", "abc"}) {
            HttpResponse<String> response = harness.get("/api/v1/approvals/pending?limit=" + limit,
                    harness.operatorToken());
            ContractAssertions.assertStatus(400, response);
        }
    }

    @Test
    @DisplayName("C-003: refuses a missing credential with 401 and a viewer with 403")
    void refusesUnauthorisedCaller() throws Exception {
        ContractAssertions.assertStatus(401,
                gateway().get("/api/v1/approvals/pending", null));
        ContractAssertions.assertStatus(403,
                gateway().get("/api/v1/approvals/pending", gateway().viewerToken()));
    }

    private static JsonNode find(JsonNode tickets, String agentId) {
        for (JsonNode ticket : tickets) {
            if (agentId.equals(ticket.path("agentId").asText())) {
                return ticket;
            }
        }
        throw new AssertionError("No pending ticket for agent " + agentId + " in " + tickets);
    }
}
