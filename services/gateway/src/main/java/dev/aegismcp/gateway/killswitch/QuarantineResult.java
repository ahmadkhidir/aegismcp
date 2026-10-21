package dev.aegismcp.gateway.killswitch;

import java.time.Instant;
import java.util.Objects;

/**
 * Result returned upon executing an emergency kill-switch activation.
 * Anchors: FEAT-010, C-008.
 */
public record QuarantineResult(
        QuarantineStatus status,
        int affectedSessions,
        Instant timestamp
) {
    public QuarantineResult {
        Objects.requireNonNull(status, "status must not be null");
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }

    public static QuarantineResult quarantined(int affectedSessions) {
        return new QuarantineResult(QuarantineStatus.QUARANTINED, affectedSessions, Instant.now());
    }

    public static QuarantineResult severed(int affectedSessions) {
        return new QuarantineResult(QuarantineStatus.SEVERED, affectedSessions, Instant.now());
    }

    public static QuarantineResult active(int affectedSessions) {
        return new QuarantineResult(QuarantineStatus.ACTIVE, affectedSessions, Instant.now());
    }
}
