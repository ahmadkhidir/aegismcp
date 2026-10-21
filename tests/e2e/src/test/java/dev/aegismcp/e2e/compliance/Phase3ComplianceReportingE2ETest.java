package dev.aegismcp.e2e.compliance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.AegisGatewayServer;
import dev.aegismcp.gateway.approval.ApprovalManager;
import dev.aegismcp.gateway.audit.AuditBlock;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.audit.AuditRecord;
import dev.aegismcp.gateway.compliance.ComplianceAttestationSigner;
import dev.aegismcp.gateway.compliance.ComplianceReportEngine;
import dev.aegismcp.gateway.killswitch.GatewayMetrics;
import dev.aegismcp.gateway.killswitch.KillSwitchManager;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-End Black-Box Verification Suite for Phase 3: Automated Regulatory Compliance Reporting & Audit Verification.
 * Validates Contracts C-011, C-013 and Features FEAT-011, NFR-040, NFR-041, NFR-042.
 */
class Phase3ComplianceReportingE2ETest {

    private final ObjectMapper mapper = new ObjectMapper();
    private AegisGatewayServer server;
    private AuditLedger auditLedger;
    private ApprovalManager approvalManager;
    private PolicyCache policyCache;
    private HttpClient httpClient;
    private String baseUrl;

    @BeforeEach
    void setUp() throws Exception {
        // 1. Initialize components with 1 record per block for granular Merkle & tamper testing
        auditLedger = new AuditLedger(1);
        policyCache = new PolicyCache();
        approvalManager = new ApprovalManager(Duration.ofMinutes(10));
        KillSwitchManager killSwitchManager = new KillSwitchManager();
        GatewayMetrics gatewayMetrics = new GatewayMetrics();
        ComplianceReportEngine reportEngine = new ComplianceReportEngine(auditLedger, policyCache, approvalManager);

        // 2. Boot AegisGatewayServer on dynamic ephemeral port
        server = new AegisGatewayServer(
                "127.0.0.1",
                0,
                Executors.newVirtualThreadPerTaskExecutor(),
                true,
                auditLedger,
                policyCache,
                approvalManager,
                killSwitchManager,
                gatewayMetrics,
                reportEngine
        );
        server.start();

        int boundPort = server.getPort();
        assertTrue(boundPort > 0, "Server must be bound to active port");
        baseUrl = "http://127.0.0.1:" + boundPort;

        // 3. Register baseline security policy
        String policyYaml = """
                id: pol-compliance-prod
                name: Production Governance Policy
                version: 2.1.0
                target_agents:
                  - "*"
                rules:
                  - id: rule-read-data
                    tool: query_customer_db
                    action: ALLOW
                  - id: rule-export-pii
                    tool: export_analytics_data
                    action: REQUIRE_APPROVAL
                  - id: rule-drop-schema
                    tool: drop_table
                    action: DENY
                """;
        SecurityPolicy policy = new SecurityPolicy(
                "pol-compliance-prod",
                "Production Governance Policy",
                "2.1.0",
                policyYaml,
                SecurityPolicy.STATUS_ACTIVE,
                "git-commit-e2e-hash",
                Instant.now().toString()
        );
        policyCache.putPolicy(policy);

        // 4. Seed simulated agent tool traffic into the audit ledger
        // Allowed traffic for agent-pipeline
        auditLedger.appendSync(AuditRecord.create("agent-pipeline", "query_customer_db", "ALLOWED", 0, 1.2, "query=SELECT count(*) FROM orders"));
        auditLedger.appendSync(AuditRecord.create("agent-pipeline", "query_customer_db", "ALLOWED", 2, 2.5, "query=SELECT email, name FROM users (redacted)"));

        // Allowed traffic for agent-analyst
        auditLedger.appendSync(AuditRecord.create("agent-analyst", "read_metrics", "ALLOWED", 0, 0.8, "target=monthly_revenue"));

        // Blocked execution traffic for rogue agent
        auditLedger.appendSync(AuditRecord.create("agent-rogue", "drop_table", "BLOCKED", 0, 0.4, "Unauthorized DDL attempt on core_ledger"));
        auditLedger.appendSync(AuditRecord.create("agent-rogue", "exec_shell", "BLOCKED", 0, 0.3, "SecurityViolation: id=viol-001, type=command_injection, details=malicious token detected"));

        // 5. Seed Human-in-the-Loop approval tickets (NFR-040 Article 14)
        var ticket1Future = approvalManager.createAndSuspendTicket(
                "agent-analyst",
                "export_analytics_data",
                mapper.readTree("{\"dataset\":\"gdpr_export_q3\",\"records\":5000}"),
                88.0,
                "pol-compliance-prod",
                Duration.ofMinutes(10)
        );
        var ticketList = approvalManager.getTickets(null);
        assertFalse(ticketList.isEmpty(), "Approval ticket must exist");
        String ticketId = ticketList.get(0).id();

        // Operator reviews and approves ticket 1
        approvalManager.submitDecision(
                ticketId,
                "APPROVE",
                "compliance.officer@enterprise.corp",
                "Verified GDPR Article 14 data processing consent"
        );

        // Create second pending approval ticket
        approvalManager.createAndSuspendTicket(
                "agent-pipeline",
                "scale_cluster",
                mapper.readTree("{\"nodes\":10}"),
                75.0,
                "pol-compliance-prod",
                Duration.ofMinutes(10)
        );

        // Flush ledger so all blocks are sealed
        auditLedger.flush();

        // 6. Build HTTP client
        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    @AfterEach
    void tearDown() {
        if (server != null && server.isRunning()) {
            server.stop();
        }
    }

    // =========================================================================
    // 1. C-011: POST /api/v1/compliance/export for EU_AI_ACT (JSON & CSV)
    // =========================================================================

    @Test
    @DisplayName("FEAT-011 / C-011: Export compliance report for EU_AI_ACT in JSON format (Articles 12 & 14)")
    void testEuAiActComplianceExportJson() throws IOException, InterruptedException {
        String requestBody = """
                {
                  "framework": "EU_AI_ACT",
                  "format": "JSON"
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/compliance/export"))
                .header("Authorization", "Bearer compliance-auditor-token")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .timeout(Duration.ofSeconds(5))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        JsonNode root = mapper.readTree(response.body());
        assertEquals("EU_AI_ACT", root.get("framework").asText());
        assertEquals("COMPLETED", root.get("status").asText());
        assertTrue(root.get("recordCount").asInt() >= 5, "Must count simulated records");
        assertTrue(root.get("violationsCount").asInt() >= 2, "Must count blocked security violations");
        assertTrue(root.get("approvalsCount").asInt() >= 2, "Must count approval tickets");

        String merkleRoot = root.get("merkleRoot").asText();
        assertNotNull(merkleRoot);
        assertEquals(64, merkleRoot.length(), "Merkle root must be SHA-256 hex string");

        String signature = root.get("signature").asText();
        assertNotNull(signature);
        assertEquals(64, signature.length(), "Signature must be 64-character SHA-256 HMAC");

        // Parse embedded report content JSON to verify EU AI Act Articles 12 & 14 (NFR-040, NFR-041)
        String contentJson = root.get("content").asText();
        assertNotNull(contentJson);
        JsonNode reportNode = mapper.readTree(contentJson);

        JsonNode controls = reportNode.get("frameworkControls");
        assertNotNull(controls);

        // Article 12: Record-Keeping (NFR-041)
        JsonNode art12 = controls.get("article12RecordKeeping");
        assertNotNull(art12, "Must contain Article 12 Record-Keeping control");
        assertEquals("COMPLIANT", art12.get("status").asText());
        assertTrue(art12.get("recordsLogged").asInt() >= 5);
        assertTrue(art12.get("attestation").asText().contains("Immutable, tamper-evident SHA-256"));

        // Article 14: Human Oversight (NFR-040)
        JsonNode art14 = controls.get("article14HumanOversight");
        assertNotNull(art14, "Must contain Article 14 Human Oversight control");
        assertEquals("COMPLIANT", art14.get("status").asText());
        assertTrue(art14.get("approvalsEvaluated").asInt() >= 2);
        assertTrue(art14.get("violationsPrevented").asInt() >= 2);

        // Verify human approval records and violations are itemized
        assertTrue(reportNode.get("humanApprovals").isArray());
        assertTrue(reportNode.get("humanApprovals").size() >= 2);
        assertTrue(reportNode.get("securityViolations").isArray());
        assertTrue(reportNode.get("securityViolations").size() >= 2);
    }

    @Test
    @DisplayName("FEAT-011 / C-011: Export compliance report for EU_AI_ACT in CSV format")
    void testEuAiActComplianceExportCsv() throws IOException, InterruptedException {
        String requestBody = """
                {
                  "framework": "EU_AI_ACT",
                  "format": "CSV"
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/compliance/export"))
                .header("Authorization", "Bearer compliance-auditor-token")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .timeout(Duration.ofSeconds(5))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        JsonNode root = mapper.readTree(response.body());
        assertEquals("EU_AI_ACT", root.get("framework").asText());
        assertEquals("COMPLETED", root.get("status").asText());

        String csvContent = root.get("content").asText();
        assertNotNull(csvContent);
        // Verify CSV header and data content
        assertTrue(csvContent.contains("record_id,timestamp,agent_id,tool_name,decision,redaction_count,latency_ms,payload_summary,record_hash"));
        assertTrue(csvContent.contains("agent-pipeline"));
        assertTrue(csvContent.contains("query_customer_db"));
        assertTrue(csvContent.contains("ALLOWED"));
        assertTrue(csvContent.contains("BLOCKED"));
    }

    // =========================================================================
    // 2. C-011: POST /api/v1/compliance/export for SOC2_TYPE2 (NFR-042)
    // =========================================================================

    @Test
    @DisplayName("FEAT-011 / NFR-042 / C-011: Export compliance report for SOC2_TYPE2 trust services criteria")
    void testSoc2Type2ComplianceExport() throws IOException, InterruptedException {
        String requestBody = """
                {
                  "framework": "SOC2_TYPE2",
                  "format": "JSON"
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/compliance/export"))
                .header("Authorization", "Bearer compliance-auditor-token")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .timeout(Duration.ofSeconds(5))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        JsonNode root = mapper.readTree(response.body());
        assertEquals("SOC2_TYPE2", root.get("framework").asText());
        assertEquals("COMPLETED", root.get("status").asText());

        String contentJson = root.get("content").asText();
        JsonNode reportNode = mapper.readTree(contentJson);
        JsonNode controls = reportNode.get("frameworkControls");

        // Common Criteria CC6.1 & CC7.1: Security & Governance
        JsonNode secControl = controls.get("trustServicesCriteriaSecurity");
        assertNotNull(secControl, "SOC 2 report must contain Security trust services criteria");
        assertEquals("COMPLIANT", secControl.get("status").asText());
        assertTrue(secControl.get("violationsDetectedAndMitigated").asInt() >= 2);

        // Common Criteria CC6.6 & CC6.7: Confidentiality & DLP
        JsonNode confControl = controls.get("trustServicesCriteriaConfidentiality");
        assertNotNull(confControl, "SOC 2 report must contain Confidentiality trust services criteria");
        assertEquals("COMPLIANT", confControl.get("status").asText());
        assertTrue(confControl.get("auditedTransactions").asInt() >= 5);
    }

    // =========================================================================
    // 3. Cryptographic Verification: SHA-256 HMAC Signature over Ledger Records & Merkle Root
    // =========================================================================

    @Test
    @DisplayName("FEAT-011 / NFR-041 / C-011: Verifies cryptographic SHA-256 HMAC signature against records & Merkle root")
    void testCryptographicHmacSignatureVerification() throws IOException, InterruptedException {
        String requestBody = """
                {
                  "framework": "EU_AI_ACT",
                  "format": "JSON"
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/compliance/export"))
                .header("Authorization", "Bearer compliance-auditor-token")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .timeout(Duration.ofSeconds(5))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        JsonNode root = mapper.readTree(response.body());
        String framework = root.get("framework").asText();
        String reportId = root.get("reportId").asText();
        String merkleRoot = root.get("merkleRoot").asText();
        int recordCount = root.get("recordCount").asInt();
        int violationsCount = root.get("violationsCount").asInt();
        int approvalsCount = root.get("approvalsCount").asInt();
        String generatedAt = root.get("generatedAt").asText();
        String signature = root.get("signature").asText();

        // Extract individual record hashes from the embedded report content
        String contentJson = root.get("content").asText();
        JsonNode reportNode = mapper.readTree(contentJson);
        JsonNode recordsArray = reportNode.get("auditTrail");
        assertNotNull(recordsArray);

        List<String> recordHashes = new ArrayList<>();
        for (JsonNode rec : recordsArray) {
            recordHashes.add(rec.get("recordHash").asText());
        }

        // Verify cryptographic signature matches using ComplianceAttestationSigner
        ComplianceAttestationSigner verifier = new ComplianceAttestationSigner();
        boolean valid = verifier.verifyAttestation(
                framework,
                reportId,
                merkleRoot,
                recordCount,
                violationsCount,
                approvalsCount,
                generatedAt,
                recordHashes,
                signature
        );
        assertTrue(valid, "Attestation signature must mathematically match HMAC computed over canonical payload");

        // Verify that tampering with any parameter causes signature verification to fail
        boolean tamperedRecordCount = verifier.verifyAttestation(
                framework,
                reportId,
                merkleRoot,
                recordCount + 1, // tampered count
                violationsCount,
                approvalsCount,
                generatedAt,
                recordHashes,
                signature
        );
        assertFalse(tamperedRecordCount, "Tampered record count must fail verification");

        boolean tamperedSignature = verifier.verifyAttestation(
                framework,
                reportId,
                merkleRoot,
                recordCount,
                violationsCount,
                approvalsCount,
                generatedAt,
                recordHashes,
                "000000000000000000000000000000000000000000000000000000000000dead"
        );
        assertFalse(tamperedSignature, "Corrupted signature must fail verification");
    }

    // =========================================================================
    // 4. C-013: GET /api/v1/audit/records Pagination and Query Filters
    // =========================================================================

    @Test
    @DisplayName("C-013: GET /api/v1/audit/records supports pagination (limit, offset) and query filters (agentId, decision)")
    void testAuditRecordsPaginationAndFilters() throws IOException, InterruptedException {
        // Query 1: Default query (all records)
        HttpRequest allReq = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/audit/records"))
                .header("Authorization", "Bearer auditor-token")
                .GET()
                .build();

        HttpResponse<String> allResp = httpClient.send(allReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, allResp.statusCode());

        JsonNode allNode = mapper.readTree(allResp.body());
        int total = allNode.get("total").asInt();
        assertTrue(total >= 5, "Total records must reflect all seeded records");
        assertEquals(total, allNode.get("records").size());

        // Query 2: Pagination with limit=2, offset=0 (page 1)
        HttpRequest page1Req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/audit/records?limit=2&offset=0"))
                .header("Authorization", "Bearer auditor-token")
                .GET()
                .build();

        HttpResponse<String> page1Resp = httpClient.send(page1Req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, page1Resp.statusCode());

        JsonNode page1Node = mapper.readTree(page1Resp.body());
        assertEquals(total, page1Node.get("total").asInt());
        assertEquals(2, page1Node.get("records").size(), "Page 1 must contain exactly 2 records");
        String firstRecordHash = page1Node.get("records").get(0).get("blockHash").asText();

        // Query 3: Pagination with limit=2, offset=2 (page 2)
        HttpRequest page2Req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/audit/records?limit=2&offset=2"))
                .header("Authorization", "Bearer auditor-token")
                .GET()
                .build();

        HttpResponse<String> page2Resp = httpClient.send(page2Req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, page2Resp.statusCode());

        JsonNode page2Node = mapper.readTree(page2Resp.body());
        assertEquals(2, page2Node.get("records").size(), "Page 2 must contain 2 records");
        String page2FirstRecordHash = page2Node.get("records").get(0).get("blockHash").asText();
        assertFalse(firstRecordHash.equals(page2FirstRecordHash), "Page 2 records must differ from Page 1");

        // Query 4: Filter by agentId=agent-pipeline
        HttpRequest agentReq = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/audit/records?agentId=agent-pipeline"))
                .header("Authorization", "Bearer auditor-token")
                .GET()
                .build();

        HttpResponse<String> agentResp = httpClient.send(agentReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, agentResp.statusCode());

        JsonNode agentNode = mapper.readTree(agentResp.body());
        assertTrue(agentNode.get("total").asInt() >= 2);
        for (JsonNode r : agentNode.get("records")) {
            assertEquals("agent-pipeline", r.get("agentId").asText());
        }

        // Query 5: Filter by decision=BLOCKED
        HttpRequest blockedReq = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/audit/records?decision=BLOCKED"))
                .header("Authorization", "Bearer auditor-token")
                .GET()
                .build();

        HttpResponse<String> blockedResp = httpClient.send(blockedReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, blockedResp.statusCode());

        JsonNode blockedNode = mapper.readTree(blockedResp.body());
        assertTrue(blockedNode.get("total").asInt() >= 2);
        for (JsonNode r : blockedNode.get("records")) {
            assertEquals("BLOCKED", r.get("decision").asText());
        }

        // Query 6: Authentication enforcement (401 Unauthorized without token)
        HttpRequest unauthReq = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/audit/records"))
                .GET()
                .build();

        HttpResponse<String> unauthResp = httpClient.send(unauthReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, unauthResp.statusCode());

        // Query 7: Role authorization enforcement (403 Forbidden with unauthorized/viewer role)
        HttpRequest forbiddenReq = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/audit/records"))
                .header("Authorization", "Bearer viewer-token")
                .GET()
                .build();

        HttpResponse<String> forbiddenResp = httpClient.send(forbiddenReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, forbiddenResp.statusCode());
    }

    // =========================================================================
    // 5. Tamper Discrepancy: Corrupted Block Aborts Compliance Export with 409 Conflict
    // =========================================================================

    @Test
    @DisplayName("FEAT-011 / C-011: Cryptographic tampering in audit ledger aborts compliance export with 409 Conflict")
    void testTamperDiscrepancyAbortsComplianceExportWith409() throws IOException, InterruptedException {
        // Tamper with block index 1 by corrupting its parent hash
        AuditBlock original = auditLedger.getBlock(1L);
        assertNotNull(original, "Block index 1 must exist");

        AuditBlock corrupted = new AuditBlock(
                1L,
                original.getTimestamp(),
                "bad000000000000000000000000000000000000000000000000000000000dead", // corrupted parent hash
                original.getPayloadHash(),
                original.getBlockHash(),
                original.getRecords()
        );
        auditLedger.tamperWithBlock(1L, corrupted);

        // Attempt compliance export on tampered ledger
        String requestBody = """
                {
                  "framework": "EU_AI_ACT",
                  "format": "JSON"
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v1/compliance/export"))
                .header("Authorization", "Bearer compliance-auditor-token")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .timeout(Duration.ofSeconds(5))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        // Must reject with HTTP 409 Conflict per C-011
        assertEquals(409, response.statusCode(), "Export must be aborted with HTTP 409 Conflict upon cryptographic discrepancy");

        JsonNode errorNode = mapper.readTree(response.body());
        assertTrue(errorNode.has("error"), "Response must contain error description");
        assertTrue(errorNode.get("error").asText().contains("Cryptographic hash chain broken or integrity compromised"));
        assertEquals(1, errorNode.get("brokenAtBlock").asInt(), "Must identify broken block index as 1");
    }
}
