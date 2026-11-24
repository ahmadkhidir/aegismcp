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
 * C-009: GET /api/v1/system/status. Anchors: C-009, FEAT-010.
 */
class C009SystemStatusContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-009: reports normal fleet status")
    void reportsNormalFleetStatus() throws Exception {
        HttpResponse<String> response = gateway().get("/api/v1/system/status", gateway().viewerToken());
        ContractAssertions.assertStatus(200, response);
        JsonNode body = GatewayHarness.json(response);
        assertEquals("NORMAL", body.path("status").asText());
        assertTrue(body.path("activeConnections").isInt());
        assertEquals(1, body.path("connectedNodes").asInt());
        assertTrue(body.path("totalRequests24h").isNumber());
        assertTrue(body.path("blockedViolations24h").isNumber());
        assertEquals(0, body.path("pendingApprovals").asInt());
    }

    @Test
    @DisplayName("C-009: refuses a missing credential with 401")
    void refusesUnauthenticatedCaller() throws Exception {
        ContractAssertions.assertStatus(401, gateway().get("/api/v1/system/status", null));
    }
}
