package dev.aegismcp.gateway.approval;

import dev.aegismcp.gateway.dlp.DlpScrubber;

import java.util.Objects;

/**
 * The reviewer-facing view of a pending approval ticket, published to an out-of-band channel.
 *
 * <p>Every field is safe to leave the process: the arguments and the agent-supplied intent pass
 * through the DLP scrubber before they are stored here, so a credential in a tool argument never
 * reaches Slack, an operator webhook, an email body, or a log line (FEAT-005, FEAT-006).
 *
 * <p>Anchors: FEAT-006, FEAT-005.
 */
public record ApprovalNotification(
        String ticketId,
        String agentId,
        String toolName,
        String argumentsPayload,
        String triggerPolicyId,
        String agentIntent,
        String createdAt,
        String expiresAt,
        double riskScore
) {

    /** Upper bound on inline argument text so one oversized call cannot bloat the notification. */
    private static final int MAX_INLINE_ARGUMENTS = 2000;
    private static final int MAX_INLINE_INTENT = 1000;

    public ApprovalNotification {
        Objects.requireNonNull(ticketId, "ticketId must not be null");
        Objects.requireNonNull(agentId, "agentId must not be null");
        Objects.requireNonNull(toolName, "toolName must not be null");
        Objects.requireNonNull(argumentsPayload, "argumentsPayload must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    }

    /** Builds the masked notification for a ticket that was just suspended. */
    public static ApprovalNotification from(ApprovalTicket ticket) {
        Objects.requireNonNull(ticket, "ticket must not be null");
        DlpScrubber scrubber = DlpScrubber.getInstance();
        String maskedArguments = truncate(
                ApprovalManager.maskedArguments(ticket), MAX_INLINE_ARGUMENTS);
        String maskedIntent = ticket.agentIntent() == null || ticket.agentIntent().isBlank()
                ? null
                : truncate(scrubber.scrubText(ticket.agentIntent()), MAX_INLINE_INTENT);
        return new ApprovalNotification(
                ticket.id(),
                ticket.agentId(),
                ticket.toolName(),
                maskedArguments,
                ticket.triggerPolicyId(),
                maskedIntent,
                ticket.createdAt(),
                ticket.expiresAt(),
                ticket.riskScore()
        );
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return "{}";
        }
        return value.length() <= max ? value : value.substring(0, max) + "…";
    }

    /** Plain-text rendering shared by the email body and the channel titles. */
    public String asText() {
        StringBuilder text = new StringBuilder();
        text.append("Approval required for ").append(toolName)
                .append(" requested by ").append(agentId).append('\n')
                .append("Ticket: ").append(ticketId).append('\n')
                .append("Policy: ").append(triggerPolicyId != null ? triggerPolicyId : "default")
                .append('\n');
        if (agentIntent != null) {
            text.append("Agent intent: ").append(agentIntent).append('\n');
        }
        text.append("Arguments: ").append(argumentsPayload).append('\n')
                .append("Expires: ").append(expiresAt).append('\n')
                .append("Risk score: ").append(riskScore);
        return text.toString();
    }
}
