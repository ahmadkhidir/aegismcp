package dev.aegismcp.gateway.identity;

import java.security.cert.X509Certificate;

/**
 * Result of validating an X.509 SVID.
 * Anchors: FEAT-009, NFR-020.
 */
public record SpiffeValidationResult(
        boolean valid,
        SpiffeId spiffeId,
        String workloadId,
        X509Certificate certificate,
        String errorMessage
) {
    public static SpiffeValidationResult success(SpiffeId spiffeId, String workloadId, X509Certificate certificate) {
        return new SpiffeValidationResult(true, spiffeId, workloadId, certificate, null);
    }

    public static SpiffeValidationResult failure(String errorMessage) {
        return new SpiffeValidationResult(false, null, null, null, errorMessage);
    }
}
