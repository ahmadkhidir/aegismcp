package dev.aegismcp.gateway.killswitch;

/**
 * Resulting operational status after an emergency kill-switch or quarantine invocation.
 *
 * <p>Anchors: FEAT-010, C-008.
 */
public enum QuarantineStatus {
    QUARANTINED,
    SEVERED,
    LOCKDOWN
}
