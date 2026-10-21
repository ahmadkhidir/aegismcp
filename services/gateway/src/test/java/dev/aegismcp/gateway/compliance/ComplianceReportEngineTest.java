package dev.aegismcp.gateway.compliance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.anomaly.SecurityViolation;
import dev.aegismcp.gateway.approval.ApprovalManager;
import dev.aegismcp.gateway.approval.ApprovalTicket;
import dev.aegismcp.gateway.audit.AuditBlock;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.audit.AuditRecord;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests verifying regulatory compliance report generation across EU AI Act and SOC 2 Type II.
 * Anchors: FEAT-011, NFR-040, NFR-041, NFR-042, C-011.
 */
class ComplianceReportEngineTest {

    private AuditLedger ledger;
    private PolicyCache policyCache;
    private ApprovalManager approvalManager;
    private ComplianceReportEngine engine;
    private final ObjectMapper jsonMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        ledger = new AuditLedger(10);
        policyCache = new PolicyCache();
        approvalManager = new ApprovalManager();
        engine = new ComplianceReportEngine(ledger, policyCache, approvalManager);
    }

    @AfterEach
    void tearDown() {
        if (approvalManager != null) {
            approvalManager.close();
        }
        if (ledger != null) {
            ledger.close();
        }
    }

    @Test
    @DisplayName("FEAT-011 / NFR-040 / NFR-041: Compiles EU AI Act compliance report in JSON format")
    void testEuAiActReportGenerationJson() throws IOException {
        // Seed audit records
        ledger.appendSync(AuditRecord.create("agent-analyst", "query_database", "allow", 0, 1.2, "SELECT * FROM sales"));
        ledger.appendSync(AuditRecord.create("agent-analyst", "query_database", "allow", 1, 1.8, "SELECT name, email FROM users"));
        ledger.appendSync(AuditRecord.create("agent-analyst", "execute_command", "block", 0, 0.4, "rm -rf /tmp"));
        ledger.flush();

        // Seed policy
        String yaml = """
                id: policy-enterprise-default
                name: Enterprise Security Baseline
                version: 1.0.0
                description: Enforces read-only DB access and blocks shell commands
                target_agents:
                  - agent-analyst
                rules:
                  - tool: execute_command
                    action: deny
                """;
        policyCache.putPolicy(SecurityPolicy.of("policy-enterprise-default", "Enterprise Security Baseline", "1.0.0", yaml, "git-sha-123"));

        // Seed human approval
        ApprovalTicket ticket = new ApprovalTicket(
                "ticket-101",
                "agent-analyst",
                "export_financial_records",
                jsonMapper.createObjectNode().put("format", "excel"),
                85.0,
                "approved",
                Instant.now().minus(10, ChronoUnit.MINUTES).toString(),
                Instant.now().plus(50, ChronoUnit.MINUTES).toString(),
                "auditor@enterprise.com",
                "Verified monthly regulatory reconciliation",
                "policy-enterprise-default"
        );
        approvalManager.getTicket("ticket-101"); // store ticket directly if needed
        // Manually record ticket in store or through manager API
        // Also register explicit security violation
        engine.recordViolation(new SecurityViolation(
                "viol-909",
                "agent-analyst",
                "tool_chaining_anomaly",
                "block-hash-909",
                "high",
                "Suspicious read followed by unauthenticated export",
                Instant.now().toString()
        ));

        ComplianceExportRequest request = new ComplianceExportRequest(
                "EU_AI_ACT",
                "JSON",
                "agent-analyst",
                null,
                null
        );

        ComplianceExportResponse response = engine.exportReport(request);

        assertNotNull(response);
        assertEquals("EU_AI_ACT", response.framework());
        assertEquals("COMPLETED", response.status());
        assertNotNull(response.reportId());
        assertTrue(response.reportId().startsWith("rep-"));
        assertNotNull(response.generatedAt());
        assertEquals(3, response.recordCount());
        assertTrue(response.violationsCount() >= 2); // 1 explicit + 1 blocked audit record
        assertNotNull(response.merkleRoot());
        assertNotNull(response.signature());
        assertNotNull(response.content());

        // Parse content JSON and inspect EU AI Act regulatory mappings
        JsonNode content = jsonMapper.readTree(response.content());
        assertEquals("EU_AI_ACT", content.get("framework").asText());
        assertEquals("agent-analyst", content.get("targetAgentId").asText());

        JsonNode controls = content.get("frameworkControls");
        assertNotNull(controls);
        assertTrue(controls.has("article12RecordKeeping"));
        assertTrue(controls.has("article14HumanOversight"));
        assertEquals("COMPLIANT", controls.get("article12RecordKeeping").get("status").asText());
        assertEquals("COMPLIANT", controls.get("article14HumanOversight").get("status").asText());

        JsonNode summary = content.get("summary");
        assertEquals(3, summary.get("totalRecords").asInt());
        assertEquals(2, summary.get("toolExecutionCounts").get("query_database").asInt());
        assertEquals(1, summary.get("toolExecutionCounts").get("execute_command").asInt());

        JsonNode policies = content.get("policyDefinitions");
        assertEquals(1, policies.size());
        assertEquals("policy-enterprise-default", policies.get(0).get("id").asText());

        // Verify attestation signature
        boolean sigValid = engine.getAttestationSigner().verifyAttestation(
                response.framework(),
                response.reportId(),
                response.merkleRoot(),
                response.recordCount(),
                response.violationsCount(),
                response.approvalsCount(),
                response.generatedAt(),
                List.of(
                        content.get("auditTrail").get(0).get("recordHash").asText(),
                        content.get("auditTrail").get(1).get("recordHash").asText(),
                        content.get("auditTrail").get(2).get("recordHash").asText()
                ),
                response.signature()
        );
        assertTrue(sigValid, "Digital signature must verify successfully");
    }

    @Test
    @DisplayName("FEAT-011 / NFR-042: Compiles SOC 2 Type II report in CSV format")
    void testSoc2ReportGenerationCsv() {
        ledger.appendSync(AuditRecord.create("agent-ops", "read_logs", "allow", 0, 2.5, "Fetched syslog"));
        ledger.appendSync(AuditRecord.create("agent-ops", "modify_iptables", "deny", 0, 0.5, "IPTABLES command blocked"));
        ledger.flush();

        ComplianceExportRequest request = new ComplianceExportRequest(
                "SOC2_TYPE2",
                "CSV",
                null,
                null,
                null
        );

        ComplianceExportResponse response = engine.exportReport(request);

        assertNotNull(response);
        assertEquals("SOC2_TYPE2", response.framework());
        assertEquals("COMPLETED", response.status());
        assertEquals(2, response.recordCount());
        assertTrue(response.violationsCount() >= 1);
        assertNotNull(response.content());

        // Verify CSV header and format
        String[] lines = response.content().split("\r?\n");
        assertTrue(lines.length >= 3, "CSV must contain header plus at least 2 data rows");
        assertEquals("record_id,timestamp,agent_id,tool_name,decision,redaction_count,latency_ms,payload_summary,record_hash", lines[0]);
        assertTrue(lines[1].contains("agent-ops"));
        assertTrue(lines[1].contains("read_logs"));
        assertTrue(lines[2].contains("modify_iptables"));
    }

    @Test
    @DisplayName("FEAT-011 / C-011: Interruption on hash mismatch aborts report generation with LedgerIntegrityException")
    void testTamperedLedgerThrowsLedgerIntegrityException() {
        ledger.appendSync(AuditRecord.create("agent-x", "read_file", "allow", 0, 1.0, "read /etc/hosts"));
        ledger.flush();

        // Tamper with block 1 to simulate cryptographic corruption
        AuditBlock original = ledger.getBlock(1);
        assertNotNull(original);
        AuditBlock tampered = new AuditBlock(
                1L,
                original.getTimestamp(),
                "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb", // corrupted parent hash
                original.getPayloadHash(),
                original.getBlockHash(),
                original.getRecords()
        );
        ledger.tamperWithBlock(1L, tampered);

        ComplianceExportRequest request = new ComplianceExportRequest("EU_AI_ACT", "JSON", null, null, null);

        LedgerIntegrityException ex = assertThrows(LedgerIntegrityException.class, () -> engine.exportReport(request));
        assertEquals(1L, ex.getBrokenAtBlock());
        assertTrue(ex.getMessage().contains("Cryptographic hash chain broken or integrity compromised at block 1"));
    }

    @Test
    @DisplayName("FEAT-011: Filters records by time window (from/to) and agent ID")
    void testFilterByDateRangeAndAgentId() {
        Instant t0 = Instant.now().minus(2, ChronoUnit.HOURS);
        Instant t1 = Instant.now().minus(1, ChronoUnit.HOURS);
        Instant t2 = Instant.now().minus(30, ChronoUnit.MINUTES);

        ledger.appendSync(AuditRecord.of("rec-1", t0.toString(), "agent-A", "tool1", "allow", 0, 1.0, "call 1"));
        ledger.appendSync(AuditRecord.of("rec-2", t1.toString(), "agent-A", "tool2", "allow", 0, 1.0, "call 2"));
        ledger.appendSync(AuditRecord.of("rec-3", t2.toString(), "agent-B", "tool3", "allow", 0, 1.0, "call 3"));
        ledger.flush();

        // Query only agent-A
        ComplianceExportRequest reqAgentA = new ComplianceExportRequest("EU_AI_ACT", "JSON", "agent-A", null, null);
        ComplianceExportResponse respAgentA = engine.exportReport(reqAgentA);
        assertEquals(2, respAgentA.recordCount());

        // Query window between t0 + 10min and t1 + 10min for agent-A (should match rec-2 only)
        Instant from = t0.plus(10, ChronoUnit.MINUTES);
        Instant to = t1.plus(10, ChronoUnit.MINUTES);
        ComplianceExportRequest reqWindow = new ComplianceExportRequest("EU_AI_ACT", "JSON", "agent-A", from.toString(), to.toString());
        ComplianceExportResponse respWindow = engine.exportReport(reqWindow);
        assertEquals(1, respWindow.recordCount());
    }

    @Test
    @DisplayName("FEAT-011: Request validation catches invalid framework, format, or date order")
    void testRequestValidation() {
        assertThrows(IllegalArgumentException.class, () ->
                new ComplianceExportRequest(null, "JSON", null, null, null).validate());
        assertThrows(IllegalArgumentException.class, () ->
                new ComplianceExportRequest("INVALID_FRAMEWORK", "JSON", null, null, null).validate());
        assertThrows(IllegalArgumentException.class, () ->
                new ComplianceExportRequest("EU_AI_ACT", "YAML", null, null, null).validate());
        assertThrows(IllegalArgumentException.class, () ->
                new ComplianceExportRequest("EU_AI_ACT", "JSON", null, "invalid-date", null).validate());
        // from after to
        assertThrows(IllegalArgumentException.class, () ->
                new ComplianceExportRequest("EU_AI_ACT", "JSON", null,
                        Instant.now().toString(),
                        Instant.now().minus(1, ChronoUnit.HOURS).toString()).validate());
    }
}
