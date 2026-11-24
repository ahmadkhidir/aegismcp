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

/**
 * C-021: POST /api/v1/emergency/release. Anchors: C-021, FEAT-010.
 */
class C021EmergencyReleaseContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-021: releases a quarantined target and lifts lockdown")
    void releasesQuarantinedTargetAndLiftsLockdown() throws Exception {
        GatewayHarness harness = gateway();
        String agent = "agent-release";
        harness.createPendingCall(agent, "deploy_prod", "{}");

        ContractAssertions.assertStatus(200, harness.postJson("/api/v1/emergency/kill", harness.adminToken(),
                "{\"targetType\":\"agent\",\"targetId\":\"" + agent + "\",\"reason\":\"contained\"}"));

        HttpResponse<String> release = harness.postJson("/api/v1/emergency/release", harness.adminToken(),
                "{\"targetType\":\"agent\",\"targetId\":\"" + agent + "\",\"reason\":\"root cause fixed\"}");
        ContractAssertions.assertStatus(200, release);
        JsonNode body = GatewayHarness.json(release);
        assertEquals("RELEASED", body.path("status").asText());
        ContractAssertions.assertIso8601(body.path("timestamp").asText(), "timestamp");

        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", harness.agentToken(agent),
                GatewayHarness.toolCall("released-1", "ping", "{}")));
    }

    @Test
    @DisplayName("C-021: lifts a global lockdown")
    void liftsGlobalLockdown() throws Exception {
        GatewayHarness harness = gateway();
        String mfaToken = harness.token(GatewayHarness.ADMIN_SUBJECT, List.of("admin"),
                Map.of("auth_time", Instant.now().getEpochSecond(), "amr", List.of("pwd", "mfa")));
        ContractAssertions.assertStatus(200, harness.postJson("/api/v1/emergency/kill", mfaToken,
                "{\"targetType\":\"global\",\"reason\":\"incident\"}"));

        HttpResponse<String> release = harness.postJson("/api/v1/emergency/release", mfaToken,
                "{\"targetType\":\"global\",\"reason\":\"incident resolved\"}");
        ContractAssertions.assertStatus(200, release);
        assertEquals("LOCKDOWN_LIFTED", GatewayHarness.json(release).path("status").asText());
    }

    @Test
    @DisplayName("C-021: rejects every malformed release with 400 and leaves state unchanged")
    void rejectsMalformedRelease() throws Exception {
        GatewayHarness harness = gateway();
        String admin = harness.adminToken();
        for (String payload : new String[]{
                "{\"targetType\":\"tool\",\"targetId\":\"echo\",\"reason\":\"x\"}",
                "{\"targetType\":\"session\",\"reason\":\"x\"}",
                "{\"targetType\":\"global\",\"targetId\":\"profit\",\"reason\":\"x\"}",
                "{\"targetType\":\"agent\",\"targetId\":\"agent-x\"}",
                "{\"targetType\":\"agent\",\"targetId\":\"agent-x\",\"reason\":\"   \"}"}) {
            ContractAssertions.assertStatus(400, harness.postJson("/api/v1/emergency/release", admin, payload));
        }
    }

    @Test
    @DisplayName("C-021: refuses a viewer with 403 and answers an unknown release with 404")
    void refusesUnauthorisedOrUnknownRelease() throws Exception {
        GatewayHarness harness = gateway();
        ContractAssertions.assertStatus(403, harness.postJson("/api/v1/emergency/release",
                harness.viewerToken(), "{\"targetType\":\"agent\",\"targetId\":\"agent-x\",\"reason\":\"x\"}"));
        ContractAssertions.assertStatus(404, harness.postJson("/api/v1/emergency/release",
                harness.adminToken(), "{\"targetType\":\"agent\",\"targetId\":\"agent-not-quarantined\",\"reason\":\"x\"}"));
        ContractAssertions.assertStatus(404, harness.postJson("/api/v1/emergency/release",
                harness.adminToken(), "{\"targetType\":\"global\",\"reason\":\"no lockdown\"}"));
    }

    @Test
    @DisplayName("C-021: refuses a missing credential with 401")
    void refusesUnauthenticatedCaller() throws Exception {
        ContractAssertions.assertStatus(401, gateway().postJson("/api/v1/emergency/release", null,
                "{\"targetType\":\"agent\",\"targetId\":\"agent-x\",\"reason\":\"x\"}"));
    }
}
