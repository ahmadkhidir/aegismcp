package dev.aegismcp.gateway.killswitch;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Data Transfer Objects conforming to contracts C-008, C-009, and C-010.
 * Anchors: C-008, C-009, C-010, FEAT-010.
 */
public final class KillSwitchDto {

    private KillSwitchDto() {
    }

    /**
     * Request body for emergency kill-switch endpoint (C-008).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record KillRequest(
            @JsonProperty(value = "targetType", required = true) String targetType,
            @JsonProperty("targetId") String targetId,
            @JsonProperty("reason") String reason
    ) {
    }

    /**
     * Response payload for emergency kill-switch endpoint (C-008).
     */
    public record KillResponse(
            @JsonProperty("status") String status,
            @JsonProperty("affectedSessions") int affectedSessions,
            @JsonProperty("timestamp") String timestamp
    ) {
    }

    /**
     * Response payload for system status endpoint (C-009).
     */
    public record SystemStatusResponse(
            @JsonProperty("status") String status,
            @JsonProperty("activeConnections") int activeConnections,
            @JsonProperty("totalRequests24h") long totalRequests24h,
            @JsonProperty("blockedViolations24h") long blockedViolations24h,
            @JsonProperty("pendingApprovals") int pendingApprovals
    ) {
    }

    /**
     * Response payload for metrics summary endpoint (C-010).
     */
    public record MetricsSummaryResponse(
            @JsonProperty("activeAgents") int activeAgents,
            @JsonProperty("toolCalls24h") long toolCalls24h,
            @JsonProperty("blockedViolations24h") long blockedViolations24h,
            @JsonProperty("pendingApprovals") int pendingApprovals,
            @JsonProperty("uptimeSeconds") long uptimeSeconds
    ) {
    }

    /**
     * Generic error response structure.
     */
    public record ErrorResponse(
            @JsonProperty("error") String error
    ) {
    }
}
