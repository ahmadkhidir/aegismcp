package dev.aegismcp.gateway.identity;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * Result of validating an OpenID Connect / OAuth 2.0 Bearer JWT.
 * Anchors: FEAT-009, NFR-020.
 */
public record OidcValidationResult(
        boolean valid,
        String subject,
        Map<String, Object> claims,
        Set<String> roles,
        String errorMessage
) {
    public OidcValidationResult {
        claims = claims != null ? Collections.unmodifiableMap(claims) : Map.of();
        roles = roles != null ? Collections.unmodifiableSet(roles) : Set.of();
    }

    public static OidcValidationResult success(String subject, Map<String, Object> claims, Set<String> roles) {
        return new OidcValidationResult(true, subject, claims, roles, null);
    }

    public static OidcValidationResult failure(String errorMessage) {
        return new OidcValidationResult(false, null, Map.of(), Set.of(), errorMessage);
    }
}
