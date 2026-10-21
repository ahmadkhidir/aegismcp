package dev.aegismcp.gateway.killswitch;

import java.util.Locale;

/**
 * Granularity target types for the emergency kill-switch mechanism.
 * Anchors: FEAT-010, C-008.
 */
public enum KillTargetType {
    GLOBAL,
    AGENT,
    TOOL,
    SERVER;

    /**
     * Parses a target type string case-insensitively.
     *
     * @param value raw target type string (e.g. "global", "agent", "tool", "server")
     * @return KillTargetType or null if invalid
     */
    public static KillTargetType fromString(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return KillTargetType.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
