package dev.aegismcp.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 1 gate journey: authentication, policy enforcement, approval, DLP, and audit against the
 * packaged artifact. Anchors: FEAT-001, FEAT-002, FEAT-004, FEAT-005, FEAT-006, FEAT-007.
 */
class Phase1EndToEndVerificationTest extends ArtifactTest {

    @Test
    @DisplayName("Phase 1: an agent is authenticated, authorised, intercepted, scrubbed, and audited")
    void agentJourneyCompletesAgainstTheArtifact() throws Exception {
        GatewayHarness harness = gateway();
        String agent = "phase1-agent";

        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", null,
                GatewayHarness.toolCall("phase1-anon", "echo", "{}")), 401, -32000);

        HttpResponse<String> allowed = harness.postJson("/mcp/v1/rpc", harness.agentToken(agent),
                GatewayHarness.toolCall("phase1-allowed", "echo", "{\"message\":\"hi\"}"));
        ContractAssertions.assertStatus(200, allowed);
        assertEquals("phase1-allowed", GatewayHarness.json(allowed).path("id").asText());

        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", harness.agentToken(agent),
                GatewayHarness.toolCall("phase1-denied", "bash_exec", "{}")), 403, -32001);

        HttpResponse<String> sensitive = harness.postJson("/mcp/v1/rpc", harness.agentToken(agent),
                GatewayHarness.toolCall("phase1-dlp", "get_sensitive_config", "{}"));
        ContractAssertions.assertStatus(200, sensitive);
        assertFalse(sensitive.body().contains("AKIAIOSFODNN7EXAMPLE"));
        assertTrue(sensitive.body().contains("[REDACTED_SECRET:AWS_KEY]"));

        HttpResponse<String> integrity = harness.get("/api/v1/audit/integrity", harness.auditorToken());
        ContractAssertions.assertStatus(200, integrity);
        assertTrue(GatewayHarness.json(integrity).path("valid").asBoolean());
    }

    @Test
    @DisplayName("Phase 1: an operator approves one suspended call and rejects another")
    void approvalJourneyCompletesAgainstTheArtifact() throws Exception {
        GatewayHarness harness = gateway();

        GatewayHarness.PendingCall approved = harness.createPendingCall("phase1-approve", "deploy_prod", "{}");
        ContractAssertions.assertStatus(200, harness.postJson(
                "/api/v1/approvals/" + approved.ticketId() + "/approve", harness.operatorToken(), ""));
        ContractAssertions.assertStatus(200, approved.response().get(10, TimeUnit.SECONDS));

        GatewayHarness.PendingCall rejected = harness.createPendingCall("phase1-reject", "deploy_prod", "{}");
        ContractAssertions.assertStatus(200, harness.postJson(
                "/api/v1/approvals/" + rejected.ticketId() + "/reject", harness.operatorToken(),
                "{\"reason\":\"phase 1 rejection\"}"));
        JsonNode error = ContractAssertions.assertRpcError(
                rejected.response().get(10, TimeUnit.SECONDS), 403, -32002, "APPROVAL_DENIED");
        assertEquals("Approval Denied", error.path("error").path("message").asText().split(":")[0]);
    }
}
