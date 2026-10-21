package dev.aegismcp.gateway.identity;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Representation of a verified agent identity authenticated via SPIFFE SVID or OIDC JWT.
 * Anchors: FEAT-009, NFR-020, C-001.
 */
public record AgentIdentity(
        IdentityType type,
        String id,
        String spiffeId,
        Map<String, Object> claims,
        Set<String> roles,
        boolean authenticated
) {
    public AgentIdentity {
        Objects.requireNonNull(type, "IdentityType cannot be null");
        claims = claims != null ? Collections.unmodifiableMap(claims) : Map.of();
        roles = roles != null ? Collections.unmodifiableSet(roles) : Set.of();
    }

    public static AgentIdentity anonymous() {
        return new AgentIdentity(IdentityType.ANONYMOUS, "anonymous", null, Map.of(), Set.of(), false);
    }

    public static AgentIdentity unauthenticated(String id, String reason) {
        return new AgentIdentity(
                IdentityType.ANONYMOUS,
                id != null ? id : "unauthenticated",
                null,
                Map.of("error", reason != null ? reason : "authentication failed"),
                Set.of(),
                false
        );
    }

    public static AgentIdentity spiffe(String spiffeId, String workloadId, Map<String, Object> claims, Set<String> roles) {
        return new AgentIdentity(IdentityType.SPIFFE, workloadId, spiffeId, claims, roles, true);
    }

    public static AgentIdentity oidc(String subject, Map<String, Object> claims, Set<String> roles) {
        return new AgentIdentity(IdentityType.OIDC, subject, null, claims, roles, true);
    }

    public static AgentIdentity apiKey(String keyId, Set<String> roles) {
        return new AgentIdentity(IdentityType.API_KEY, keyId, null, Map.of("keyId", keyId), roles, true);
    }

    /**
     * Alias for {@link #id()} to match agent identifier conventions.
     */
    public String agentId() {
        return id;
    }

    /**
     * Converts this verified identity to the gateway proxy {@link dev.aegismcp.gateway.proxy.AgentIdentity}
     * for seamless compatibility across gateway filters and policy interceptors.
     */
    public dev.aegismcp.gateway.proxy.AgentIdentity toProxyIdentity() {
        String token = claims.containsKey("raw_token") ? String.valueOf(claims.get("raw_token")) : null;
        return new dev.aegismcp.gateway.proxy.AgentIdentity(id, spiffeId, token, authenticated);
    }
}
