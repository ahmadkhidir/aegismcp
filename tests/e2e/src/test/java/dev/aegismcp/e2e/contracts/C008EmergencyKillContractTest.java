package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-008: POST /api/v1/emergency/kill. Anchors: C-008, FEAT-010.
 */
class C008EmergencyKillContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-008: quarantines an agent and severs its sessions")
    void quarantinesAgentAndSeversSessions() throws Exception {
        GatewayHarness harness = gateway();
        String agent = "agent-rogue";
        GatewayHarness.PendingCall live = harness.createPendingCall(agent, "deploy_prod", "{}");

        HttpResponse<String> response = harness.postJson("/api/v1/emergency/kill", harness.adminToken(),
                "{\"targetType\":\"agent\",\"targetId\":\"" + agent + "\",\"reason\":\"Rogue behaviour\"}");
        ContractAssertions.assertStatus(200, response);
        JsonNode body = GatewayHarness.json(response);
        assertEquals("QUARANTINED", body.path("status").asText());
        assertTrue(body.path("affectedSessions").asInt() >= 1);
        ContractAssertions.assertIso8601(body.path("timestamp").asText(), "timestamp");

        // The agent is refused from the next call onwards.
        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", harness.agentToken(agent),
                GatewayHarness.toolCall("after-kill", "ping", "{}")), 403, -32001);

        assertTrue(live.response().isDone() || live.response().isCompletedExceptionally(),
                "The severed session does not complete normally");
    }

    @Test
    @DisplayName("C-008: locks down the fleet for a global target with a fresh multi-factor re-confirmation")
    void locksDownGlobally() throws Exception {
        GatewayHarness harness = gateway();
        String mfaToken = harness.token(GatewayHarness.ADMIN_SUBJECT, List.of("admin"),
                Map.of("auth_time", Instant.now().getEpochSecond(), "amr", List.of("pwd", "mfa")));

        HttpResponse<String> response = harness.postJson("/api/v1/emergency/kill", mfaToken,
                "{\"targetType\":\"global\",\"reason\":\"Fleet-wide incident\"}");
        ContractAssertions.assertStatus(200, response);
        assertEquals("LOCKDOWN", GatewayHarness.json(response).path("status").asText());

        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc",
                harness.agentToken("agent-any"), GatewayHarness.toolCall("lockdown-1", "ping", "{}")),
                403, -32001);
    }

    @Test
    @DisplayName("C-008: rejects every malformed target with 400 and applies nothing")
    void rejectsMalformedTarget() throws Exception {
        GatewayHarness harness = gateway();
        String admin = harness.adminToken();
        for (String payload : new String[]{
                "{\"targetType\":\"tool\",\"targetId\":\"echo\"}",
                "{\"targetType\":\"agent\"}",
                "{\"targetType\":\"global\",\"targetId\":\"profit\"}",
                "{\"targetType\":\"agent\",\"targetId\":\"agent-x\",\"secondApprover\":\"other@aegis.test\"}"}) {
            ContractAssertions.assertStatus(400, harness.postJson("/api/v1/emergency/kill", admin, payload));
        }

        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", harness.agentToken("agent-x"),
                GatewayHarness.toolCall("still-alive", "ping", "{}")));
    }

    @Test
    @DisplayName("C-008: refuses a viewer with 403 and a global target without multi-factor re-confirmation")
    void refusesUnauthorisedKill() throws Exception {
        GatewayHarness harness = gateway();
        ContractAssertions.assertStatus(403, harness.postJson("/api/v1/emergency/kill", harness.viewerToken(),
                "{\"targetType\":\"agent\",\"targetId\":\"agent-x\"}"));
        ContractAssertions.assertStatus(403, harness.postJson("/api/v1/emergency/kill", harness.operatorToken(),
                "{\"targetType\":\"global\",\"reason\":\"no step-up\"}"));
    }

    @Test
    @DisplayName("C-008: answers an unknown target with 404")
    void reportsUnknownTarget() throws Exception {
        GatewayHarness harness = gateway();
        ContractAssertions.assertStatus(404, harness.postJson("/api/v1/emergency/kill", harness.adminToken(),
                "{\"targetType\":\"agent\",\"targetId\":\"agent-does-not-exist\"}"));
        ContractAssertions.assertStatus(404, harness.postJson("/api/v1/emergency/kill", harness.adminToken(),
                "{\"targetType\":\"server\",\"targetId\":\"server-does-not-exist\"}"));
    }

    @Test
    @DisplayName("C-008: refuses a missing credential with 401")
    void refusesUnauthenticatedCaller() throws Exception {
        ContractAssertions.assertStatus(401, gateway().postJson("/api/v1/emergency/kill", null,
                "{\"targetType\":\"agent\",\"targetId\":\"agent-x\"}"));
    }
}
