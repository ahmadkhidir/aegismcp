package dev.aegismcp.gateway.compliance;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Objects;

/**
 * Request payload for POST /api/v1/compliance/export conforming to contract C-011.
 * Anchors: C-011, FEAT-011.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ComplianceExportRequest(
        @JsonProperty("framework") String framework,
        @JsonProperty("format") String format,
        @JsonProperty("agentId") String agentId,
        @JsonProperty("from") String from,
        @JsonProperty("to") String to
) {

    @JsonCreator
    public ComplianceExportRequest {
        // Raw values accepted by Jackson; validate() provides explicit business rule checks
    }

    /**
     * Validates that framework, format, and optional ISO-8601 date ranges are sound.
     *
     * @throws IllegalArgumentException if validation fails
     */
    public void validate() {
        if (framework == null || framework.isBlank()) {
            throw new IllegalArgumentException("Missing required property 'framework'");
        }
        ComplianceFramework.fromString(framework);

        if (format == null || format.isBlank()) {
            throw new IllegalArgumentException("Missing required property 'format'");
        }
        ReportFormat.fromString(format);

        Instant fromInstant = null;
        Instant toInstant = null;

        if (from != null && !from.isBlank()) {
            try {
                fromInstant = Instant.parse(from);
            } catch (DateTimeParseException e) {
                throw new IllegalArgumentException("Invalid 'from' timestamp: must be valid ISO-8601 format (" + from + ")");
            }
        }

        if (to != null && !to.isBlank()) {
            try {
                toInstant = Instant.parse(to);
            } catch (DateTimeParseException e) {
                throw new IllegalArgumentException("Invalid 'to' timestamp: must be valid ISO-8601 format (" + to + ")");
            }
        }

        if (fromInstant != null && toInstant != null && fromInstant.isAfter(toInstant)) {
            throw new IllegalArgumentException("Invalid date range: 'from' (" + from + ") cannot be after 'to' (" + to + ")");
        }
    }
}
