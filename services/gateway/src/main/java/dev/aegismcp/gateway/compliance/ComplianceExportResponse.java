package dev.aegismcp.gateway.compliance;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Attested compliance export response envelope conforming to contract C-011.
 * Anchors: C-011, FEAT-011.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ComplianceExportResponse(
        @JsonProperty("reportId") String reportId,
        @JsonProperty("framework") String framework,
        @JsonProperty("status") String status,
        @JsonProperty("generatedAt") String generatedAt,
        @JsonProperty("recordCount") int recordCount,
        @JsonProperty("violationsCount") int violationsCount,
        @JsonProperty("approvalsCount") int approvalsCount,
        @JsonProperty("merkleRoot") String merkleRoot,
        @JsonProperty("signature") String signature,
        @JsonProperty("content") String content
) {
}
