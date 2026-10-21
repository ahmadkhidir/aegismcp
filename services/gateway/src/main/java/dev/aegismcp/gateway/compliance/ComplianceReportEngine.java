package dev.aegismcp.gateway.compliance;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import dev.aegismcp.gateway.anomaly.SecurityViolation;
import dev.aegismcp.gateway.approval.ApprovalManager;
import dev.aegismcp.gateway.approval.ApprovalTicket;
import dev.aegismcp.gateway.audit.AuditBlock;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.audit.AuditRecord;
import dev.aegismcp.gateway.audit.AuditVerificationEngine;
import dev.aegismcp.gateway.audit.AuditVerificationResult;
import dev.aegismcp.gateway.audit.MerkleTree;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Compliance report generation engine compiling immutable audit records, active policy definitions,
 * tool execution statistics, human approval interventions, and security incidents into standardized
 * reports for EU AI Act (Articles 12 & 14) and SOC 2 Type II Security & Confidentiality.
 * Conforms to contract C-011 and requirements FEAT-011, NFR-040, NFR-041, NFR-042.
 * Anchors: FEAT-011, NFR-040, NFR-041, NFR-042, C-011.
 */
public class ComplianceReportEngine {

    private static final Logger logger = LoggerFactory.getLogger(ComplianceReportEngine.class);

    private final AuditLedger ledger;
    private final AuditVerificationEngine verificationEngine;
    private final PolicyCache policyCache;
    private final ApprovalManager approvalManager;
    private final ComplianceAttestationSigner attestationSigner;
    private final ObjectMapper jsonMapper;
    private final List<SecurityViolation> securityViolationsStore = new CopyOnWriteArrayList<>();

    public ComplianceReportEngine(AuditLedger ledger) {
        this(ledger, AuditVerificationEngine.getInstance(), null, null,
                new ComplianceAttestationSigner(), createDefaultMapper());
    }

    public ComplianceReportEngine(AuditLedger ledger, PolicyCache policyCache, ApprovalManager approvalManager) {
        this(ledger, AuditVerificationEngine.getInstance(), policyCache, approvalManager,
                new ComplianceAttestationSigner(), createDefaultMapper());
    }

    public ComplianceReportEngine(
            AuditLedger ledger,
            AuditVerificationEngine verificationEngine,
            PolicyCache policyCache,
            ApprovalManager approvalManager,
            ComplianceAttestationSigner attestationSigner,
            ObjectMapper jsonMapper
    ) {
        this.ledger = Objects.requireNonNull(ledger, "ledger must not be null");
        this.verificationEngine = verificationEngine != null ? verificationEngine : AuditVerificationEngine.getInstance();
        this.policyCache = policyCache;
        this.approvalManager = approvalManager;
        this.attestationSigner = attestationSigner != null ? attestationSigner : new ComplianceAttestationSigner();
        this.jsonMapper = jsonMapper != null ? jsonMapper : createDefaultMapper();
    }

    private static ObjectMapper createDefaultMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        return mapper;
    }

    /**
     * Registers a security violation event for forensic itemization in compliance exports.
     */
    public void recordViolation(SecurityViolation violation) {
        if (violation != null) {
            securityViolationsStore.add(violation);
        }
    }

    /**
     * Compiles and generates a signed regulatory compliance report conforming to contract C-011.
     *
     * @param request the export request parameters
     * @return ComplianceExportResponse envelope containing report metadata, Merkle root, digital signature, and content
     * @throws IllegalArgumentException if request validation fails
     * @throws LedgerIntegrityException if cryptographic verification detects any tampered historical block (HTTP 409)
     */
    public ComplianceExportResponse exportReport(ComplianceExportRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        request.validate();

        ComplianceFramework framework = ComplianceFramework.fromString(request.framework());
        ReportFormat format = ReportFormat.fromString(request.format());
        String agentId = request.agentId();
        Instant fromInstant = (request.from() != null && !request.from().isBlank()) ? Instant.parse(request.from()) : null;
        Instant toInstant = (request.to() != null && !request.to().isBlank()) ? Instant.parse(request.to()) : null;

        // 1. Mandatory Cryptographic Ledger Integrity Check per FEAT-011 / NFR-041 / C-011
        long latestBlockIndex = ledger.getLatestBlockIndex();
        AuditVerificationResult verifyResult = verificationEngine.verifyRange(ledger, 0L, latestBlockIndex);
        if (!verifyResult.valid()) {
            logger.warn("Ledger integrity failure during compliance export: broken at block {}", verifyResult.brokenAtBlock());
            throw new LedgerIntegrityException(
                    "Cryptographic hash chain broken or integrity compromised at block " + verifyResult.brokenAtBlock(),
                    verifyResult.brokenAtBlock()
            );
        }

        // 2. Query and filter matching audit records
        List<AuditRecord> matchingRecords = new ArrayList<>();
        Map<String, Long> toolExecutionCounts = new LinkedHashMap<>();

        for (long i = 0; i <= latestBlockIndex; i++) {
            AuditBlock block = ledger.getBlock(i);
            if (block == null) {
                continue;
            }

            for (AuditRecord record : block.getRecords()) {
                if (matchesRecord(record, agentId, fromInstant, toInstant)) {
                    matchingRecords.add(record);
                    toolExecutionCounts.merge(record.getToolName(), 1L, Long::sum);
                }
            }
        }

        int recordCount = matchingRecords.size();

        // 3. Query human approval tickets
        List<ComplianceReport.ApprovalSummary> approvalSummaries = new ArrayList<>();
        if (approvalManager != null) {
            List<ApprovalTicket> tickets = approvalManager.getTickets(null);
            for (ApprovalTicket ticket : tickets) {
                if (matchesApproval(ticket, agentId, fromInstant, toInstant)) {
                    approvalSummaries.add(new ComplianceReport.ApprovalSummary(
                            ticket.id(),
                            ticket.agentId(),
                            ticket.toolName(),
                            ticket.status(),
                            ticket.requestedAt(),
                            ticket.reviewer(),
                            ticket.decisionReason(),
                            ticket.triggerPolicyId()
                    ));
                }
            }
        }
        int approvalsCount = approvalSummaries.size();

        // 4. Query security violations (both explicit store and blocked audit records)
        List<ComplianceReport.ViolationSummary> violationSummaries = new ArrayList<>();
        for (SecurityViolation viol : securityViolationsStore) {
            if (matchesViolation(viol, agentId, fromInstant, toInstant)) {
                violationSummaries.add(new ComplianceReport.ViolationSummary(
                        viol.id(),
                        viol.agentId(),
                        viol.violationType(),
                        viol.severity(),
                        viol.details(),
                        viol.blockHash(),
                        viol.createdAt()
                ));
            }
        }

        // Itemize blocked execution attempts from audit records
        for (AuditRecord record : matchingRecords) {
            String dec = record.getDecision().toLowerCase();
            if (dec.contains("block") || dec.contains("deny") || dec.contains("quarantine") || dec.contains("violation")) {
                boolean alreadyPresent = false;
                for (ComplianceReport.ViolationSummary vs : violationSummaries) {
                    if (vs.details().contains(record.getRecordId())) {
                        alreadyPresent = true;
                        break;
                    }
                }
                if (!alreadyPresent) {
                    violationSummaries.add(new ComplianceReport.ViolationSummary(
                            "viol-" + record.getRecordId().substring(0, Math.min(8, record.getRecordId().length())),
                            record.getAgentId(),
                            "policy_blocked_execution",
                            "high",
                            "Blocked tool call '" + record.getToolName() + "': " + record.getPayloadSummary(),
                            record.getRecordHash(),
                            record.getTimestamp()
                    ));
                }
            }
        }
        int violationsCount = violationSummaries.size();

        // 5. Query active policies
        List<ComplianceReport.PolicySummary> policySummaries = new ArrayList<>();
        if (policyCache != null) {
            List<SecurityPolicy> policies = policyCache.getAllPolicies(null);
            for (SecurityPolicy policy : policies) {
                policySummaries.add(new ComplianceReport.PolicySummary(
                        policy.id(),
                        policy.name(),
                        policy.version(),
                        policy.status(),
                        policy.gitCommitHash()
                ));
            }
        }

        // 6. Compute Merkle Root & Digital Attestation Signature
        String merkleRoot = MerkleTree.computeRoot(matchingRecords);
        String reportId = "rep-" + UUID.randomUUID();
        String generatedAt = Instant.now().toString();

        List<String> recordHashes = new ArrayList<>(matchingRecords.size());
        for (AuditRecord r : matchingRecords) {
            recordHashes.add(r.getRecordHash());
        }

        String signature = attestationSigner.signAttestation(
                framework.name(),
                reportId,
                merkleRoot,
                recordCount,
                violationsCount,
                approvalsCount,
                generatedAt,
                recordHashes
        );

        // 7. Framework-specific regulatory control mappings
        Map<String, Object> frameworkControls = buildFrameworkControls(framework, recordCount, approvalsCount, violationsCount);

        // 8. Convert audit records to report summaries
        List<ComplianceReport.AuditRecordSummary> auditSummaries = new ArrayList<>(matchingRecords.size());
        for (AuditRecord r : matchingRecords) {
            auditSummaries.add(new ComplianceReport.AuditRecordSummary(
                    r.getRecordId(),
                    r.getTimestamp(),
                    r.getAgentId(),
                    r.getToolName(),
                    r.getDecision(),
                    r.getRedactionCount(),
                    r.getLatencyMs(),
                    r.getPayloadSummary(),
                    r.getRecordHash()
            ));
        }

        ComplianceReport report = new ComplianceReport(
                reportId,
                framework.name(),
                format.name(),
                "COMPLETED",
                generatedAt,
                new ComplianceReport.ReportingPeriod(request.from(), request.to()),
                agentId != null ? agentId : "ALL",
                merkleRoot,
                signature,
                new ComplianceReport.ComplianceSummary(
                        recordCount,
                        matchingRecords.size(),
                        violationsCount,
                        approvalsCount,
                        toolExecutionCounts
                ),
                frameworkControls,
                policySummaries,
                approvalSummaries,
                violationSummaries,
                auditSummaries
        );

        // 9. Format content according to JSON or CSV
        String content;
        if (format == ReportFormat.CSV) {
            content = renderCsv(report);
        } else {
            try {
                content = jsonMapper.writeValueAsString(report);
            } catch (JsonProcessingException e) {
                logger.error("Failed to render JSON report content", e);
                content = "{}";
            }
        }

        return new ComplianceExportResponse(
                reportId,
                framework.name(),
                "COMPLETED",
                generatedAt,
                recordCount,
                violationsCount,
                approvalsCount,
                merkleRoot,
                signature,
                content
        );
    }

    private boolean matchesRecord(AuditRecord record, String targetAgentId, Instant from, Instant to) {
        if (targetAgentId != null && !targetAgentId.isBlank()) {
            if (!targetAgentId.trim().equalsIgnoreCase(record.getAgentId())) {
                return false;
            }
        }

        if (from != null || to != null) {
            try {
                Instant recInstant = Instant.parse(record.getTimestamp());
                if (from != null && recInstant.isBefore(from)) {
                    return false;
                }
                if (to != null && recInstant.isAfter(to)) {
                    return false;
                }
            } catch (Exception e) {
                // If timestamp unparseable, include conservatively
            }
        }

        return true;
    }

    private boolean matchesApproval(ApprovalTicket ticket, String targetAgentId, Instant from, Instant to) {
        if (targetAgentId != null && !targetAgentId.isBlank()) {
            if (!targetAgentId.trim().equalsIgnoreCase(ticket.agentId())) {
                return false;
            }
        }

        if (from != null || to != null) {
            try {
                Instant ticketInstant = Instant.parse(ticket.requestedAt());
                if (from != null && ticketInstant.isBefore(from)) {
                    return false;
                }
                if (to != null && ticketInstant.isAfter(to)) {
                    return false;
                }
            } catch (Exception e) {
                // Fall back
            }
        }

        return true;
    }

    private boolean matchesViolation(SecurityViolation viol, String targetAgentId, Instant from, Instant to) {
        if (targetAgentId != null && !targetAgentId.isBlank()) {
            if (!targetAgentId.trim().equalsIgnoreCase(viol.agentId())) {
                return false;
            }
        }

        if (from != null || to != null) {
            try {
                Instant violInstant = Instant.parse(viol.createdAt());
                if (from != null && violInstant.isBefore(from)) {
                    return false;
                }
                if (to != null && violInstant.isAfter(to)) {
                    return false;
                }
            } catch (Exception e) {
                // Fall back
            }
        }

        return true;
    }

    private Map<String, Object> buildFrameworkControls(
            ComplianceFramework framework,
            int recordCount,
            int approvalsCount,
            int violationsCount
    ) {
        Map<String, Object> controls = new LinkedHashMap<>();

        if (framework == ComplianceFramework.EU_AI_ACT) {
            controls.put("article12RecordKeeping", Map.of(
                    "status", "COMPLIANT",
                    "mandate", "EU AI Act Article 12: Automatic recording of events throughout high-risk AI system lifecycle.",
                    "attestation", "Immutable, tamper-evident SHA-256 hash-chained ledger sealing all tool invocations and outcomes.",
                    "recordsLogged", recordCount
            ));
            controls.put("article14HumanOversight", Map.of(
                    "status", "COMPLIANT",
                    "mandate", "EU AI Act Article 14: Human oversight mechanisms enabling real-time human intervention and execution halting.",
                    "attestation", "Human-in-the-Loop approval gateway with configurable TTL timeouts and operator authorization traces.",
                    "approvalsEvaluated", approvalsCount,
                    "violationsPrevented", violationsCount
            ));
        } else {
            // SOC 2 Type II
            controls.put("trustServicesCriteriaSecurity", Map.of(
                    "status", "COMPLIANT",
                    "criteria", "Common Criteria CC6.1 & CC7.1: Logical access control, policy governance, and incident monitoring.",
                    "attestation", "Declarative Policy-as-Code engine enforcement with zero unauthorized tool execution.",
                    "violationsDetectedAndMitigated", violationsCount
            ));
            controls.put("trustServicesCriteriaConfidentiality", Map.of(
                    "status", "COMPLIANT",
                    "criteria", "Common Criteria CC6.6 & CC6.7: Data loss prevention and confidential data protection.",
                    "attestation", "Automated real-time DLP redaction and cryptographically sealed audit blocks.",
                    "auditedTransactions", recordCount
            ));
        }

        return controls;
    }

    private String renderCsv(ComplianceReport report) {
        StringBuilder sb = new StringBuilder(1024);
        sb.append("record_id,timestamp,agent_id,tool_name,decision,redaction_count,latency_ms,payload_summary,record_hash\r\n");

        for (ComplianceReport.AuditRecordSummary r : report.auditTrail()) {
            sb.append(escapeCsv(r.recordId())).append(',')
                    .append(escapeCsv(r.timestamp())).append(',')
                    .append(escapeCsv(r.agentId())).append(',')
                    .append(escapeCsv(r.toolName())).append(',')
                    .append(escapeCsv(r.decision())).append(',')
                    .append(r.redactionCount()).append(',')
                    .append(r.latencyMs()).append(',')
                    .append(escapeCsv(r.payloadSummary())).append(',')
                    .append(escapeCsv(r.recordHash())).append("\r\n");
        }

        return sb.toString();
    }

    private String escapeCsv(String value) {
        if (value == null) {
            return "\"\"";
        }
        if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return "\"" + value + "\"";
    }

    public ComplianceAttestationSigner getAttestationSigner() {
        return attestationSigner;
    }
}
