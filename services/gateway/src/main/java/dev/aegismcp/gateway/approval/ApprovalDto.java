package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Data Transfer Objects for the Human-in-the-Loop management contracts C-003, C-004, C-014, and
 * C-019. Each record mirrors the response shape the contract names; internal ticket state is not
 * serialised directly because the contracts expose masked arguments and the resolved reviewer
 * rather than the gateway's bookkeeping fields.
 *
 * <p>Anchors: C-003, C-004, C-014, C-019, FEAT-006.
 */
public final class ApprovalDto {

    private ApprovalDto() {
    }

    /**
     * One pending approval ticket conforming to C-003. {@code argumentsPayload} carries the
     * JSON-serialised request arguments with secret values already masked.
     */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record PendingTicket(
            @JsonProperty("id") String id,
            @JsonProperty("agentId") String agentId,
            @JsonProperty("toolName") String toolName,
            @JsonProperty("argumentsPayload") String argumentsPayload,
            @JsonProperty("triggerPolicyId") String triggerPolicyId,
            @JsonProperty("agentIntent") String agentIntent,
            @JsonProperty("status") String status,
            @JsonProperty("createdAt") String createdAt,
            @JsonProperty("expiresAt") String expiresAt
    ) {
    }

    /** Response payload for GET /api/v1/approvals/pending (C-003). */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record PendingTicketsResponse(
            @JsonProperty("tickets") List<PendingTicket> tickets
    ) {
        public PendingTicketsResponse {
            tickets = tickets != null ? List.copyOf(tickets) : List.of();
        }
    }

    /** Request payload for POST /api/v1/approvals/{id}/reject (C-014). */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record RejectRequest(
            @JsonProperty("reason") String reason
    ) {
    }

    /** Response payload for POST /api/v1/approvals/{id}/approve (C-004). */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record ApproveResponse(
            @JsonProperty("ticketId") String ticketId,
            @JsonProperty("status") String status,
            @JsonProperty("reviewedBy") String reviewedBy,
            @JsonProperty("processedAt") String processedAt
    ) {
    }

    /** Response payload for POST /api/v1/approvals/{id}/reject (C-014). */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record RejectResponse(
            @JsonProperty("ticketId") String ticketId,
            @JsonProperty("status") String status,
            @JsonProperty("reviewedBy") String reviewedBy,
            @JsonProperty("rejectionReason") String rejectionReason,
            @JsonProperty("processedAt") String processedAt
    ) {
    }

    /** One resolved ticket in the approval history conforming to C-019. */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record HistoryTicket(
            @JsonProperty("id") String id,
            @JsonProperty("agentId") String agentId,
            @JsonProperty("toolName") String toolName,
            @JsonProperty("argumentsPayload") String argumentsPayload,
            @JsonProperty("status") String status,
            @JsonProperty("triggerPolicyId") String triggerPolicyId,
            @JsonProperty("createdAt") String createdAt,
            @JsonProperty("expiresAt") String expiresAt,
            @JsonProperty("reviewedBy") String reviewedBy,
            @JsonProperty("rejectionReason") String rejectionReason,
            @JsonProperty("processedAt") String processedAt
    ) {
    }

    /** Response payload for GET /api/v1/approvals (C-019). */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record HistoryResponse(
            @JsonProperty("tickets") List<HistoryTicket> tickets,
            @JsonProperty("total") int total
    ) {
        public HistoryResponse {
            tickets = tickets != null ? List.copyOf(tickets) : List.of();
        }
    }

    /**
     * Standard error response payload for management errors. The message names the failure class
     * only; exception text, token fragments, and argument values never appear here.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ErrorResponse(
            @JsonProperty("error") String error,
            @JsonProperty("details") String details
    ) {
        public ErrorResponse(String error) {
            this(error, null);
        }
    }
}
