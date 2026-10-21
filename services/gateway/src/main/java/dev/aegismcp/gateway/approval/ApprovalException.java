package dev.aegismcp.gateway.approval;

/**
 * Exceptions thrown during Human-in-the-Loop ticket lifecycle processing.
 * Anchors: FEAT-006, C-004.
 */
public class ApprovalException extends RuntimeException {

    public ApprovalException(String message) {
        super(message);
    }

    public static class TicketNotFoundException extends ApprovalException {
        public TicketNotFoundException(String ticketId) {
            super("Approval ticket not found or expired: " + ticketId);
        }
    }

    public static class TicketAlreadyResolvedException extends ApprovalException {
        public TicketAlreadyResolvedException(String ticketId, String currentStatus) {
            super("Approval ticket " + ticketId + " has already been resolved with status: " + currentStatus);
        }
    }

    public static class InvalidDecisionException extends ApprovalException {
        public InvalidDecisionException(String message) {
            super(message);
        }
    }
}
