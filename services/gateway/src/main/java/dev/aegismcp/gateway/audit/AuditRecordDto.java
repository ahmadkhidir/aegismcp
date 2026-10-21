package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * DTO representing an audit record item returned by the audit query API conforming to contract C-013.
 * Anchors: C-013, FEAT-011, schema.md#AuditBlock.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuditRecordDto(
        @JsonProperty("index") long index,
        @JsonProperty("blockHash") String blockHash,
        @JsonProperty("parentHash") String parentHash,
        @JsonProperty("agentId") String agentId,
        @JsonProperty("toolName") String toolName,
        @JsonProperty("decision") String decision,
        @JsonProperty("redactionCount") int redactionCount,
        @JsonProperty("latencyMs") double latencyMs,
        @JsonProperty("timestamp") String timestamp
) {
}
