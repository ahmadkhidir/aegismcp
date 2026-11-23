package dev.aegismcp.gateway.inspector;

/**
 * Payload of an {@code approval} event (C-002): one approval ticket was created, approved, rejected,
 * or expired.
 *
 * <p>Anchors: FEAT-006, FEAT-008, C-002.
 */
public record ApprovalEvent(String ticketId, String status, String expiresAt) {
}
