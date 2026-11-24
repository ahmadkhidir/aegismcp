package dev.aegismcp.e2e.compliance;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 3 compliance journey across C-011, C-013, and C-015 against the packaged artifact.
 * Anchors: FEAT-007, FEAT-011, NFR-040, NFR-041, NFR-042.
 */
class Phase3ComplianceReportingE2ETest extends ArtifactTest {

    @Test
    @DisplayName("Phase 3: tool activity is sealed, queried, verified, and exported")
    void complianceJourney() throws Exception {
        GatewayHarness harness = gateway();
        for (int i = 0; i < 3; i++) {
            ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", harness.agentToken("agent-audit"),
                    GatewayHarness.toolCall("audit-" + i, "echo", "{\"n\":" + i + "}")));
        }

        HttpResponse<String> integrity = harness.get("/api/v1/audit/integrity", harness.auditorToken());
        ContractAssertions.assertStatus(200, integrity);
        assertTrue(GatewayHarness.json(integrity).path("valid").asBoolean());

        JsonNode records = awaitRecords(harness);
        assertTrue(records.path("total").asInt() >= 3);
        assertTrue(records.path("records").path(0).path("blockIndex").asLong() >= 1);

        HttpResponse<String> export = harness.postJson("/api/v1/compliance/export", harness.auditorToken(),
                "{\"framework\":\"EU_AI_ACT\",\"format\":\"JSON\",\"from\":\""
                        + Instant.now().minusSeconds(86400) + "\",\"to\":\"" + Instant.now().plusSeconds(60) + "\"}");
        ContractAssertions.assertStatus(200, export);
        JsonNode report = GatewayHarness.json(export);
        assertEquals("COMPLETED", report.path("status").asText());
        assertTrue(report.path("recordCount").asInt() >= 3);
        assertFalse(report.path("signature").asText().isBlank());
        assertTrue(report.path("content").asText().contains("EU_AI_ACT"));
    }

    private static JsonNode awaitRecords(GatewayHarness harness) throws Exception {
        long deadline = System.nanoTime() + java.time.Duration.ofSeconds(15).toNanos();
        JsonNode last = null;
        while (System.nanoTime() < deadline) {
            HttpResponse<String> response = harness.get("/api/v1/audit/records?limit=10", harness.auditorToken());
            ContractAssertions.assertStatus(200, response);
            last = GatewayHarness.json(response);
            if (last.path("total").asInt() >= 3) {
                return last;
            }
            Thread.sleep(100);
        }
        return last;
    }
}
