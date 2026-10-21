package dev.aegismcp.gateway.identity;

/**
 * Supported cryptographic and credential identity types for AI agent workloads.
 * Anchors: FEAT-009, NFR-020, C-001.
 */
public enum IdentityType {
    /**
     * Workload identified and verified via SPIFFE X.509 SVID (mTLS).
     */
    SPIFFE,

    /**
     * Workload identified and verified via OpenID Connect / OAuth 2.0 Bearer JWT.
     */
    OIDC,

    /**
     * Workload or client identified via API key.
     */
    API_KEY,

    /**
     * Anonymous or unauthenticated connection.
     */
    ANONYMOUS
}
