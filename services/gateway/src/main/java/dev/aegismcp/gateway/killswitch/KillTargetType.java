package dev.aegismcp.gateway.killswitch;

import java.util.Locale;

/**
 * Granularity target types for the emergency kill-switch mechanism.
 *
 * <p>The management contract C-008 accepts exactly {@code session}, {@code agent}, {@code server},
 * and {@code global}. {@link #TOOL} remains an internal automation target used by the circuit
 * breaker; it is never accepted from an HTTP request and is not part of the contract vocabulary.
 *
 * <p>Anchors: FEAT-010, C-008.
 */
public enum KillTargetType {
    GLOBAL,
    SESSION,
    AGENT,
    SERVER,
    TOOL;

    /**
     * Parses a target type from the management API. Only the four declared contract values are
     * accepted; {@code null} means the caller supplied an undeclared target.
     *
     * @param value raw target type string from the request body
     * @return the matching contract target type, or null when the value is undeclared
     */
    public static KillTargetType fromApiValue(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "GLOBAL" -> GLOBAL;
            case "SESSION" -> SESSION;
            case "AGENT" -> AGENT;
            case "SERVER" -> SERVER;
            default -> null;
        };
    }

    /**
     * Parses any target type, including the internal {@link #TOOL} state, case-insensitively.
     *
     * @param value raw target type string
     * @return the matching target type, or null if invalid
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

    /** True for the target types the C-008 request body may carry. */
    public boolean isContractTarget() {
        return this == GLOBAL || this == SESSION || this == AGENT || this == SERVER;
    }
}
