package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * DTO representing an audit record item returned by the audit query API conforming to contract
 * C-013. The request arguments themselves are never carried: {@code argumentsHash} is the digest
 * sealed with the decision, and {@code reviewedBy} names the human reviewer when an approval
 * applied.
 *
 * <p>Anchors: C-013, FEAT-011, schema.md#AuditBlock.
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public record AuditRecordDto(
        @JsonProperty("blockIndex") long blockIndex,
        @JsonProperty("blockHash") String blockHash,
        @JsonProperty("parentHash") String parentHash,
        @JsonProperty("agentId") String agentId,
        @JsonProperty("toolName") String toolName,
        @JsonProperty("argumentsHash") String argumentsHash,
        @JsonProperty("decision") String decision,
        @JsonProperty("redactionCount") int redactionCount,
        @JsonProperty("latencyMs") double latencyMs,
        @JsonProperty("timestamp") String timestamp,
        @JsonProperty("reviewedBy") String reviewedBy
) {
}
