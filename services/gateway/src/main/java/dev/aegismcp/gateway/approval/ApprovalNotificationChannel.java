package dev.aegismcp.gateway.approval;

/**
 * One out-of-band destination for a suspended approval ticket: Slack, an operator webhook, or an
 * email relay (FEAT-006).
 *
 * <p>{@link #deliver(ApprovalNotification)} is blocking and runs on a virtual thread owned by the
 * notification dispatcher, never on a Netty event loop. A failure is reported by throwing; the
 * dispatcher records it and retries, and the ticket stays pending so the Web Console queue remains
 * a fallback until the ticket expires.
 *
 * <p>Anchors: FEAT-006, NFR-002.
 */
public interface ApprovalNotificationChannel {

    /** Stable channel name used in delivery records and log lines, for example {@code slack}. */
    String name();

    /** Delivers one notification, blocking until the destination answers or fails. */
    void deliver(ApprovalNotification notification) throws Exception;
}
