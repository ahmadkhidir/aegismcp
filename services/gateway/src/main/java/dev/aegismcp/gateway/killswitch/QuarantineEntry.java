package dev.aegismcp.gateway.killswitch;

import java.time.Instant;
import java.util.Objects;

/**
 * Record representing an active emergency quarantine or lockdown.
 * Anchors: FEAT-010, C-008.
 */
public record QuarantineEntry(
        KillTargetType targetType,
        String targetId,
        String reason,
        Instant activatedAt
) {
    public QuarantineEntry {
        Objects.requireNonNull(targetType, "targetType must not be null");
        if (targetId == null) {
            targetId = "*";
        }
        if (reason == null || reason.isBlank()) {
            reason = "Emergency quarantine activated";
        }
        if (activatedAt == null) {
            activatedAt = Instant.now();
        }
    }
}
