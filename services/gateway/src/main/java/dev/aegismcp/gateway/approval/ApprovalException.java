package dev.aegismcp.gateway.approval;

/**
 * Exceptions thrown during Human-in-the-Loop ticket lifecycle processing. Each type maps to one
 * status code row of the approval contracts: not found (404), already resolved (409), expired
 * (410), and an invalid decision payload (400).
 *
 * <p>Anchors: FEAT-006, C-004, C-014.
 */
public class ApprovalException extends RuntimeException {

    public ApprovalException(String message) {
        super(message);
    }

    public static class TicketNotFoundException extends ApprovalException {
        public TicketNotFoundException(String ticketId) {
            super("Approval ticket not found: " + ticketId);
        }
    }

    public static class TicketAlreadyResolvedException extends ApprovalException {
        private final String resolvingReviewer;

        public TicketAlreadyResolvedException(String ticketId, String currentStatus) {
            this(ticketId, currentStatus, null);
        }

        public TicketAlreadyResolvedException(String ticketId, String currentStatus, String resolvingReviewer) {
            super("Approval ticket " + ticketId + " has already been resolved with status: " + currentStatus);
            this.resolvingReviewer = resolvingReviewer;
        }

        /** The operator (or {@code system}) that resolved the ticket first. */
        public String resolvingReviewer() {
            return resolvingReviewer;
        }
    }

    public static class TicketExpiredException extends ApprovalException {
        public TicketExpiredException(String ticketId) {
            super("Approval ticket " + ticketId + " expired before the decision arrived");
        }
    }

    public static class InvalidDecisionException extends ApprovalException {
        public InvalidDecisionException(String message) {
            super(message);
        }
    }
}
