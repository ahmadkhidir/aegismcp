package dev.aegismcp.gateway.anomaly;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable security incident record conforming to schema.md#SecurityViolation.
 * Generated when an agent violates policy, executes a prohibited sequence, or triggers anomaly heuristics.
 * Anchors: FEAT-004, C-001, schema.md#SecurityViolation.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SecurityViolation(
        @JsonProperty(value = "id", required = true) String id,
        @JsonProperty(value = "agentId", required = true) String agentId,
        @JsonProperty(value = "violationType", required = true) String violationType,
        @JsonProperty(value = "blockHash", required = true) String blockHash,
        @JsonProperty(value = "severity", required = true) String severity,
        @JsonProperty(value = "details", required = true) String details,
        @JsonProperty(value = "createdAt", required = true) String createdAt
) {
    // Violation types defined in schema.md#SecurityViolation
    public static final String TYPE_PROMPT_INJECTION = "prompt_injection";
    public static final String TYPE_TOOL_CHAINING_ANOMALY = "tool_chaining_anomaly";
    public static final String TYPE_SCHEMA_VIOLATION = "schema_violation";
    public static final String TYPE_PATH_TRAVERSAL = "path_traversal";
    public static final String TYPE_UNAUTHORIZED_TOOL = "unauthorized_tool";
    public static final String TYPE_RATE_LIMIT_EXCEEDED = "rate_limit_exceeded";

    // Severities defined in schema.md#SecurityViolation
    public static final String SEVERITY_LOW = "low";
    public static final String SEVERITY_MEDIUM = "medium";
    public static final String SEVERITY_HIGH = "high";
    public static final String SEVERITY_CRITICAL = "critical";

    public SecurityViolation {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(agentId, "agentId must not be null");
        Objects.requireNonNull(violationType, "violationType must not be null");
        Objects.requireNonNull(blockHash, "blockHash must not be null");
        Objects.requireNonNull(severity, "severity must not be null");
        Objects.requireNonNull(details, "details must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
    }

    /**
     * Factory method creating a tool chaining anomaly violation with default UUID and timestamp.
     */
    public static SecurityViolation toolChainingAnomaly(String agentId, String details, String severity) {
        String violationId = "viol-" + UUID.randomUUID();
        String pendingBlockHash = "audit-block-pending-" + UUID.randomUUID().toString().substring(0, 8);
        String assessedSeverity = severity != null ? severity : SEVERITY_CRITICAL;
        return new SecurityViolation(
                violationId,
                agentId,
                TYPE_TOOL_CHAINING_ANOMALY,
                pendingBlockHash,
                assessedSeverity,
                details,
                Instant.now().toString()
        );
    }

    public static SecurityViolation of(String agentId, String violationType, String severity, String details) {
        String violationId = "viol-" + UUID.randomUUID();
        String pendingBlockHash = "audit-block-pending-" + UUID.randomUUID().toString().substring(0, 8);
        return new SecurityViolation(
                violationId,
                agentId,
                violationType,
                pendingBlockHash,
                severity != null ? severity : SEVERITY_HIGH,
                details,
                Instant.now().toString()
        );
    }
}
