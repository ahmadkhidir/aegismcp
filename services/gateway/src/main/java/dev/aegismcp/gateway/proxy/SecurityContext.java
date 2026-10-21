package dev.aegismcp.gateway.proxy;

import java.net.SocketAddress;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Context holding security attributes for an intercepted request.
 * Anchors: FEAT-001, C-001.
 */
public record SecurityContext(
        String requestId,
        AgentIdentity identity,
        SocketAddress remoteAddress,
        Instant receivedAt
) {
    public SecurityContext {
        Objects.requireNonNull(identity, "identity must not be null");
        if (requestId == null) {
            requestId = UUID.randomUUID().toString();
        }
        if (receivedAt == null) {
            receivedAt = Instant.now();
        }
    }

    public static SecurityContext of(AgentIdentity identity, SocketAddress remoteAddress) {
        return new SecurityContext(UUID.randomUUID().toString(), identity, remoteAddress, Instant.now());
    }

    public boolean isAuthenticated() {
        return identity.authenticated();
    }
}
