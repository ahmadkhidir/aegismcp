package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

import java.time.Instant;
import java.util.Objects;

/**
 * Model representing a suspended tool invocation awaiting Human-in-the-Loop review.
 * Conforms to docs/AegisMCP/schema.md#ApprovalTicket and contract C-003.
 * Anchors: FEAT-006, C-003, C-004.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApprovalTicket(
        @JsonProperty("id") String id,
        @JsonProperty("agentId") String agentId,
        @JsonProperty("toolName") String toolName,
        @JsonProperty("arguments") JsonNode arguments,
        @JsonProperty("riskScore") double riskScore,
        @JsonProperty("status") String status,
        @JsonProperty("requestedAt") String requestedAt,
        @JsonProperty("expiresAt") String expiresAt,
        @JsonProperty("reviewer") String reviewer,
        @JsonProperty("decisionReason") String decisionReason,
        @JsonProperty("triggerPolicyId") String triggerPolicyId
) {

    public ApprovalTicket {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(agentId, "agentId must not be null");
        Objects.requireNonNull(toolName, "toolName must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(requestedAt, "requestedAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        if (arguments == null) {
            arguments = JsonNodeFactory.instance.objectNode();
        }
    }

    /**
     * Compatibility alias for docs/AegisMCP/schema.md#ApprovalTicket: argumentsPayload.
     */
    @JsonProperty("argumentsPayload")
    public String argumentsPayload() {
        return arguments != null ? arguments.toString() : "{}";
    }

    /**
     * Compatibility alias for docs/AegisMCP/schema.md#ApprovalTicket: createdAt.
     */
    @JsonProperty("createdAt")
    public String createdAt() {
        return requestedAt;
    }

    /**
     * Compatibility alias for docs/AegisMCP/schema.md#ApprovalTicket: reviewedBy.
     */
    @JsonProperty("reviewedBy")
    public String reviewedBy() {
        return reviewer;
    }

    /**
     * Compatibility alias for docs/AegisMCP/schema.md#ApprovalTicket: rejectionReason.
     */
    @JsonProperty("rejectionReason")
    public String rejectionReason() {
        return decisionReason;
    }

    public boolean isPending() {
        return ApprovalStatus.PENDING.getValue().equalsIgnoreCase(status);
    }

    public boolean isExpired() {
        return isExpired(Instant.now());
    }

    public boolean isExpired(Instant now) {
        try {
            return now.isAfter(Instant.parse(expiresAt));
        } catch (Exception e) {
            return false;
        }
    }

    public ApprovalTicket withDecision(ApprovalStatus newStatus, String reviewerName, String reason) {
        return new ApprovalTicket(
                id,
                agentId,
                toolName,
                arguments,
                riskScore,
                newStatus.getValue(),
                requestedAt,
                expiresAt,
                reviewerName,
                reason,
                triggerPolicyId
        );
    }
}
