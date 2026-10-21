package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable audit record representing an intercepted MCP protocol interaction or gateway event.
 * Anchors: FEAT-007, schema.md#AuditBlock.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AuditRecord {

    private final String recordId;
    private final String timestamp;
    private final String agentId;
    private final String toolName;
    private final String decision;
    private final int redactionCount;
    private final double latencyMs;
    private final String payloadSummary;
    private final String recordHash;

    @JsonCreator
    public AuditRecord(
            @JsonProperty("recordId") String recordId,
            @JsonProperty("timestamp") String timestamp,
            @JsonProperty("agentId") String agentId,
            @JsonProperty("toolName") String toolName,
            @JsonProperty("decision") String decision,
            @JsonProperty("redactionCount") int redactionCount,
            @JsonProperty("latencyMs") double latencyMs,
            @JsonProperty("payloadSummary") String payloadSummary,
            @JsonProperty("recordHash") String recordHash
    ) {
        this.recordId = recordId != null ? recordId : UUID.randomUUID().toString();
        this.timestamp = timestamp != null ? timestamp : Instant.now().toString();
        this.agentId = Objects.requireNonNull(agentId, "agentId must not be null");
        this.toolName = Objects.requireNonNull(toolName, "toolName must not be null");
        this.decision = Objects.requireNonNull(decision, "decision must not be null");
        this.redactionCount = Math.max(0, redactionCount);
        this.latencyMs = Math.max(0.0, latencyMs);
        this.payloadSummary = payloadSummary != null ? payloadSummary : "";
        this.recordHash = (recordHash != null && !recordHash.isBlank())
                ? recordHash
                : calculateHash(this.recordId, this.timestamp, this.agentId, this.toolName, this.decision, this.redactionCount, this.latencyMs, this.payloadSummary);
    }

    public static AuditRecord create(String agentId, String toolName, String decision, int redactionCount, double latencyMs, String payloadSummary) {
        String recordId = UUID.randomUUID().toString();
        String timestamp = Instant.now().toString();
        String hash = calculateHash(recordId, timestamp, agentId, toolName, decision, redactionCount, latencyMs, payloadSummary);
        return new AuditRecord(recordId, timestamp, agentId, toolName, decision, redactionCount, latencyMs, payloadSummary, hash);
    }

    public static AuditRecord of(String recordId, String timestamp, String agentId, String toolName, String decision, int redactionCount, double latencyMs, String payloadSummary) {
        String hash = calculateHash(recordId, timestamp, agentId, toolName, decision, redactionCount, latencyMs, payloadSummary);
        return new AuditRecord(recordId, timestamp, agentId, toolName, decision, redactionCount, latencyMs, payloadSummary, hash);
    }

    public static String calculateHash(String recordId, String timestamp, String agentId, String toolName, String decision, int redactionCount, double latencyMs, String payloadSummary) {
        String canonical = String.join("|",
                recordId != null ? recordId : "",
                timestamp != null ? timestamp : "",
                agentId != null ? agentId : "",
                toolName != null ? toolName : "",
                decision != null ? decision : "",
                String.valueOf(redactionCount),
                String.valueOf(latencyMs),
                payloadSummary != null ? payloadSummary : ""
        );
        return HashUtils.sha256Hex(canonical);
    }

    public String getRecordId() {
        return recordId;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getAgentId() {
        return agentId;
    }

    public String getToolName() {
        return toolName;
    }

    public String getDecision() {
        return decision;
    }

    public int getRedactionCount() {
        return redactionCount;
    }

    public double getLatencyMs() {
        return latencyMs;
    }

    public String getPayloadSummary() {
        return payloadSummary;
    }

    public String getRecordHash() {
        return recordHash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditRecord that = (AuditRecord) o;
        return redactionCount == that.redactionCount &&
                Double.compare(that.latencyMs, latencyMs) == 0 &&
                Objects.equals(recordId, that.recordId) &&
                Objects.equals(timestamp, that.timestamp) &&
                Objects.equals(agentId, that.agentId) &&
                Objects.equals(toolName, that.toolName) &&
                Objects.equals(decision, that.decision) &&
                Objects.equals(payloadSummary, that.payloadSummary) &&
                Objects.equals(recordHash, that.recordHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(recordId, timestamp, agentId, toolName, decision, redactionCount, latencyMs, payloadSummary, recordHash);
    }

    @Override
    public String toString() {
        return "AuditRecord{" +
                "recordId='" + recordId + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", agentId='" + agentId + '\'' +
                ", toolName='" + toolName + '\'' +
                ", decision='" + decision + '\'' +
                ", redactionCount=" + redactionCount +
                ", latencyMs=" + latencyMs +
                ", recordHash='" + recordHash + '\'' +
                '}';
    }
}
