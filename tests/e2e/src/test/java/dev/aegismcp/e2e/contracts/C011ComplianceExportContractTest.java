package dev.aegismcp.e2e.contracts;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-011: POST /api/v1/compliance/export. Anchors: C-011, FEAT-011, NFR-040, NFR-041, NFR-042.
 */
class C011ComplianceExportContractTest extends ArtifactTest {

    @Test
    @DisplayName("C-011: exports a signed EU AI Act JSON report")
    void exportsSignedEuAiActJsonReport() throws Exception {
        GatewayHarness harness = gateway();
        ContractAssertions.assertStatus(200, harness.postJson("/mcp/v1/rpc", harness.agentToken("agent-compliance"),
                GatewayHarness.toolCall("compliance-1", "echo", "{}")));

        HttpResponse<String> response = harness.postJson("/api/v1/compliance/export", harness.auditorToken(),
                request("EU_AI_ACT", "JSON", null));
        ContractAssertions.assertStatus(200, response);
        JsonNode body = GatewayHarness.json(response);
        assertTrue(body.path("reportId").asText().startsWith("rep-"));
        assertEquals("EU_AI_ACT", body.path("framework").asText());
        assertEquals("JSON", body.path("format").asText());
        assertEquals("COMPLETED", body.path("status").asText());
        ContractAssertions.assertIso8601(body.path("generatedAt").asText(), "generatedAt");
        assertTrue(body.path("recordCount").asInt() >= 1);
        assertTrue(body.path("violationsCount").isInt());
        assertTrue(body.path("approvalsCount").isInt());
        assertFalse(body.path("merkleRoot").asText().isBlank());
        assertFalse(body.path("signature").asText().isBlank());
        assertFalse(body.path("content").asText().isBlank());
        assertTrue(body.path("content").asText().contains("EU_AI_ACT"));
    }

    @Test
    @DisplayName("C-011: exports SOC 2 Type II and CSV reports")
    void exportsOtherFrameworkAndFormat() throws Exception {
        GatewayHarness harness = gateway();
        JsonNode soc2 = GatewayHarness.json(harness.postJson("/api/v1/compliance/export", harness.adminToken(),
                request("SOC2_TYPE2", "CSV", null)));
        assertEquals("SOC2_TYPE2", soc2.path("framework").asText());
        assertEquals("CSV", soc2.path("format").asText());
        assertEquals("COMPLETED", soc2.path("status").asText());
        assertTrue(soc2.path("content").asText().contains("record_id"));
    }

    @Test
    @DisplayName("C-011: rejects an undeclared framework, format, or timestamp with 400")
    void rejectsInvalidRequest() throws Exception {
        GatewayHarness harness = gateway();
        String auditor = harness.auditorToken();
        for (String payload : new String[]{
                request("GDPR", "JSON", null),
                request("EU_AI_ACT", "XML", null),
                "{\"framework\":\"EU_AI_ACT\",\"format\":\"JSON\",\"from\":\"yesterday\",\"to\":\""
                        + Instant.now() + "\"}",
                "{\"framework\":\"EU_AI_ACT\",\"format\":\"JSON\",\"from\":\"" + Instant.now()
                        + "\",\"to\":\"" + Instant.now().minusSeconds(3600) + "\"}"}) {
            ContractAssertions.assertStatus(400,
                    harness.postJson("/api/v1/compliance/export", auditor, payload));
        }
    }

    @Test
    @DisplayName("C-011: answers a long reporting range asynchronously with 202 GENERATING")
    void answersLongRangeAsynchronously() throws Exception {
        Instant now = Instant.now();
        HttpResponse<String> response = gateway().postJson("/api/v1/compliance/export", gateway().auditorToken(),
                "{\"framework\":\"EU_AI_ACT\",\"format\":\"JSON\",\"from\":\""
                        + now.minus(Duration.ofDays(40)) + "\",\"to\":\"" + now + "\"}");
        ContractAssertions.assertStatus(202, response);
        JsonNode body = GatewayHarness.json(response);
        assertTrue(body.path("reportId").asText().startsWith("rep-"));
        assertEquals("GENERATING", body.path("status").asText());
    }

    @Test
    @DisplayName("C-011: refuses a missing credential with 401 and a viewer with 403")
    void refusesUnauthorisedCaller() throws Exception {
        String payload = request("EU_AI_ACT", "JSON", null);
        ContractAssertions.assertStatus(401,
                gateway().postJson("/api/v1/compliance/export", null, payload));
        ContractAssertions.assertStatus(403,
                gateway().postJson("/api/v1/compliance/export", gateway().viewerToken(), payload));
    }

    static String request(String framework, String format, String agentId) {
        Instant now = Instant.now();
        return "{\"framework\":\"" + framework + "\",\"format\":\"" + format + "\","
                + (agentId != null ? "\"agentId\":\"" + agentId + "\"," : "")
                + "\"from\":\"" + now.minusSeconds(86400) + "\",\"to\":\"" + now.plusSeconds(60) + "\"}";
    }
}
