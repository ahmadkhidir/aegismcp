package dev.aegismcp.gateway.killswitch;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Data Transfer Objects conforming to contracts C-008, C-009, C-010, and C-020.
 * Anchors: C-008, C-009, C-010, C-020, FEAT-010.
 */
public final class KillSwitchDto {

    private KillSwitchDto() {
    }

    /**
     * Request body for the emergency kill-switch endpoint (C-008).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record KillRequest(
            @JsonProperty(value = "targetType", required = true) String targetType,
            @JsonProperty("targetId") String targetId,
            @JsonProperty("reason") String reason,
            @JsonProperty("secondApprover") String secondApprover
    ) {
    }

    /**
     * Response payload for the emergency kill-switch endpoint (C-008).
     */
    public record KillResponse(
            @JsonProperty("status") String status,
            @JsonProperty("affectedSessions") int affectedSessions,
            @JsonProperty("timestamp") String timestamp
    ) {
    }

    /**
     * Response payload for the system status endpoint (C-009).
     */
    public record SystemStatusResponse(
            @JsonProperty("status") String status,
            @JsonProperty("activeConnections") int activeConnections,
            @JsonProperty("connectedNodes") int connectedNodes,
            @JsonProperty("totalRequests24h") long totalRequests24h,
            @JsonProperty("blockedViolations24h") long blockedViolations24h,
            @JsonProperty("pendingApprovals") int pendingApprovals
    ) {
    }

    /**
     * Response payload for the metrics summary endpoint (C-010).
     */
    public record MetricsSummaryResponse(
            @JsonProperty("activeAgents") int activeAgents,
            @JsonProperty("toolCalls24h") long toolCalls24h,
            @JsonProperty("blockedViolations24h") long blockedViolations24h,
            @JsonProperty("pendingApprovals") int pendingApprovals,
            @JsonProperty("uptimeSeconds") long uptimeSeconds
    ) {
    }

    /** One hourly bucket of the metrics timeseries (C-020). */
    public record MetricsBucket(
            @JsonProperty("bucketStart") String bucketStart,
            @JsonProperty("toolCalls") long toolCalls,
            @JsonProperty("blockedViolations") long blockedViolations
    ) {
    }

    /** Response payload for the metrics timeseries endpoint (C-020). */
    public record MetricsTimeseriesResponse(
            @JsonProperty("interval") String interval,
            @JsonProperty("buckets") List<MetricsBucket> buckets
    ) {
        public MetricsTimeseriesResponse {
            buckets = buckets != null ? List.copyOf(buckets) : List.of();
        }
    }

    /**
     * Generic error response structure. It names the failure class only; exception text and
     * credential material never appear in a management error body.
     */
    public record ErrorResponse(
            @JsonProperty("error") String error
    ) {
    }
}
