package dev.aegismcp.gateway.policy;

import java.util.Locale;

/**
 * Supported comparison and matching operators for tool argument constraints.
 * Anchors: FEAT-002, NFR-024.
 */
public enum ConstraintOperator {
    STARTS_WITH,
    ENDS_WITH,
    CONTAINS,
    EQUALS,
    NOT_EQUALS,
    MATCHES_REGEX,
    IN,
    NOT_IN,
    LESS_THAN,
    LESS_THAN_OR_EQUAL,
    GREATER_THAN,
    GREATER_THAN_OR_EQUAL;

    /**
     * Resolves a string operator representation to a typed enum, supporting common aliases.
     */
    public static ConstraintOperator fromString(String op) {
        if (op == null || op.isBlank()) {
            throw new IllegalArgumentException("Constraint operator must not be null or blank");
        }
        String normalized = op.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        return switch (normalized) {
            case "STARTS_WITH", "STARTSWITH", "PREFIX" -> STARTS_WITH;
            case "ENDS_WITH", "ENDSWITH", "SUFFIX" -> ENDS_WITH;
            case "CONTAINS", "SUBSTRING" -> CONTAINS;
            case "EQUALS", "EQ", "EXACT", "==" -> EQUALS;
            case "NOT_EQUALS", "NEQ", "NOT_EQ", "!=" -> NOT_EQUALS;
            case "MATCHES_REGEX", "MATCHES", "REGEX", "PATTERN" -> MATCHES_REGEX;
            case "IN", "ONE_OF", "WHITELIST" -> IN;
            case "NOT_IN", "NONE_OF", "BLACKLIST" -> NOT_IN;
            case "LESS_THAN", "LT", "<" -> LESS_THAN;
            case "LESS_THAN_OR_EQUAL", "LTE", "MAX", "<=" -> LESS_THAN_OR_EQUAL;
            case "GREATER_THAN", "GT", ">" -> GREATER_THAN;
            case "GREATER_THAN_OR_EQUAL", "GTE", "MIN", ">=" -> GREATER_THAN_OR_EQUAL;
            default -> throw new IllegalArgumentException("Unsupported constraint operator: " + op);
        };
    }
}
