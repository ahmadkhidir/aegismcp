package dev.aegismcp.gateway.inspector;

/**
 * Payload of a {@code system} event (C-002): the fleet threat level or the pending approval count
 * changed, so the console's live indicators can follow without polling.
 *
 * <p>Anchors: FEAT-008, FEAT-010, C-002, C-009.
 */
public record SystemEvent(String status, int pendingApprovals) {
}
