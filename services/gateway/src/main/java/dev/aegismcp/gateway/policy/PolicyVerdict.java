package dev.aegismcp.gateway.policy;

/**
 * Authorization verdict emitted by the declarative policy evaluation engine.
 * Anchors: FEAT-002, NFR-027.
 */
public enum PolicyVerdict {
    ALLOW,
    DENY,
    REQUIRE_APPROVAL
}
