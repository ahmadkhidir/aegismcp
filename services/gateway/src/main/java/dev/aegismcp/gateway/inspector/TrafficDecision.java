package dev.aegismcp.gateway.inspector;

/**
 * Terminal decision carried by one live traffic event.
 *
 * <p>The three values are the complete set contract C-002 defines for the {@code traffic} event: a
 * call the chain allowed, a call a stage blocked, and a call suspended for human approval. The wire
 * form is the constant name.
 *
 * <p>Anchors: FEAT-008, NFR-005, C-002.
 */
public enum TrafficDecision {
    ALLOWED,
    BLOCKED,
    PENDING_APPROVAL
}
