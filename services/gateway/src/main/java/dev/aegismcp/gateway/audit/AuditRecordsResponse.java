package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Envelope response containing paginated audit records conforming to contract C-013.
 * Anchors: C-013, FEAT-011.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuditRecordsResponse(
        @JsonProperty("records") List<AuditRecordDto> records,
        @JsonProperty("total") int total
) {
}
