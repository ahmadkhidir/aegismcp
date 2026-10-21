package dev.aegismcp.gateway.compliance;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Structured domain model representing a completed compliance audit report.
 * Anchors: FEAT-011, NFR-040, NFR-041, NFR-042, C-011.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ComplianceReport(
        @JsonProperty("reportId") String reportId,
        @JsonProperty("framework") String framework,
        @JsonProperty("format") String format,
        @JsonProperty("status") String status,
        @JsonProperty("generatedAt") String generatedAt,
        @JsonProperty("reportingPeriod") ReportingPeriod reportingPeriod,
        @JsonProperty("targetAgentId") String targetAgentId,
        @JsonProperty("merkleRoot") String merkleRoot,
        @JsonProperty("signature") String signature,
        @JsonProperty("summary") ComplianceSummary summary,
        @JsonProperty("frameworkControls") Map<String, Object> frameworkControls,
        @JsonProperty("policyDefinitions") List<PolicySummary> policyDefinitions,
        @JsonProperty("humanApprovals") List<ApprovalSummary> humanApprovals,
        @JsonProperty("securityViolations") List<ViolationSummary> securityViolations,
        @JsonProperty("auditTrail") List<AuditRecordSummary> auditTrail
) {

    public record ReportingPeriod(
            @JsonProperty("from") String from,
            @JsonProperty("to") String to
    ) {}

    public record ComplianceSummary(
            @JsonProperty("totalRecords") int totalRecords,
            @JsonProperty("totalToolExecutions") int totalToolExecutions,
            @JsonProperty("violationsCount") int violationsCount,
            @JsonProperty("approvalsCount") int approvalsCount,
            @JsonProperty("toolExecutionCounts") Map<String, Long> toolExecutionCounts
    ) {}

    public record PolicySummary(
            @JsonProperty("id") String id,
            @JsonProperty("name") String name,
            @JsonProperty("version") String version,
            @JsonProperty("status") String status,
            @JsonProperty("gitCommitHash") String gitCommitHash
    ) {}

    public record ApprovalSummary(
            @JsonProperty("ticketId") String ticketId,
            @JsonProperty("agentId") String agentId,
            @JsonProperty("toolName") String toolName,
            @JsonProperty("status") String status,
            @JsonProperty("requestedAt") String requestedAt,
            @JsonProperty("reviewer") String reviewer,
            @JsonProperty("decisionReason") String decisionReason,
            @JsonProperty("triggerPolicyId") String triggerPolicyId
    ) {}

    public record ViolationSummary(
            @JsonProperty("violationId") String violationId,
            @JsonProperty("agentId") String agentId,
            @JsonProperty("violationType") String violationType,
            @JsonProperty("severity") String severity,
            @JsonProperty("details") String details,
            @JsonProperty("blockHash") String blockHash,
            @JsonProperty("timestamp") String timestamp
    ) {}

    public record AuditRecordSummary(
            @JsonProperty("recordId") String recordId,
            @JsonProperty("timestamp") String timestamp,
            @JsonProperty("agentId") String agentId,
            @JsonProperty("toolName") String toolName,
            @JsonProperty("decision") String decision,
            @JsonProperty("redactionCount") int redactionCount,
            @JsonProperty("latencyMs") double latencyMs,
            @JsonProperty("payloadSummary") String payloadSummary,
            @JsonProperty("recordHash") String recordHash
    ) {}
}
