package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Data Transfer Objects for Human-in-the-Loop REST contracts C-003 and C-004.
 * Anchors: C-003, C-004, FEAT-006.
 */
public final class ApprovalDto {

    private ApprovalDto() {
    }

    /**
     * Request payload for operator decision conforming to C-004.
     */
    public record DecisionRequest(
            @JsonProperty("decision") String decision,
            @JsonProperty("reviewer") String reviewer,
            @JsonProperty("reason") String reason
    ) {
    }

    /**
     * Response payload for operator decision conforming to C-004.
     */
    public record DecisionResponse(
            @JsonProperty("ticketId") String ticketId,
            @JsonProperty("status") String status,
            @JsonProperty("processedAt") String processedAt
    ) {
    }

    /**
     * Response payload for ticket listing conforming to C-003.
     */
    public record TicketListResponse(
            @JsonProperty("tickets") List<ApprovalTicket> tickets
    ) {
    }

    /**
     * Standard error response payload for REST errors.
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
