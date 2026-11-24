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
 * C-015: GET /api/v1/audit/integrity. Anchors: C-015, FEAT-007.
 */
class C015AuditIntegrityContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-015: reports verified ledger integrity")
    void reportsVerifiedLedgerIntegrity() throws Exception {
        GatewayHarness harness = gateway();
        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", harness.agentToken("agent-integrity"),
                GatewayHarness.toolCall("integrity-1", "echo", "{}")));

        HttpResponse<String> response = harness.get("/api/v1/audit/integrity", harness.auditorToken());
        ContractAssertions.assertStatus(200, response);
        JsonNode body = GatewayHarness.json(response);
        assertTrue(body.path("valid").isBoolean());
        assertTrue(body.path("valid").asBoolean(), "A fresh ledger verifies");
        assertTrue(body.path("totalVerifiedBlocks").asLong() >= 0);
        ContractAssertions.assertIso8601(body.path("lastVerifiedAt").asText(), "lastVerifiedAt");
        assertEquals(3, body.size(), "The integrity body carries exactly the C-015 members");
    }

    @Test
    @DisplayName("C-015: refuses a missing credential with 401 and a viewer with 403")
    void refusesUnauthorisedCaller() throws Exception {
        ContractAssertions.assertStatus(401, gateway().get("/api/v1/audit/integrity", null));
        ContractAssertions.assertStatus(403, gateway().get("/api/v1/audit/integrity", gateway().viewerToken()));
    }
}
