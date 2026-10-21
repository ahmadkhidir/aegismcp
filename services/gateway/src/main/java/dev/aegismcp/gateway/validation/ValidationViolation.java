package dev.aegismcp.gateway.validation;

import dev.aegismcp.gateway.anomaly.SecurityViolation;

import java.util.Objects;

/**
 * Encapsulates a single parameter validation, schema deviation, or injection sanitization violation.
 * Anchors: FEAT-012, NFR-024, schema.md#SecurityViolation.
 */
public record ValidationViolation(
        String parameterName,
        String violationType,
        String severity,
        String message,
        String offendingValue
) {
    public ValidationViolation {
        Objects.requireNonNull(parameterName, "parameterName must not be null");
        Objects.requireNonNull(violationType, "violationType must not be null");
        Objects.requireNonNull(severity, "severity must not be null");
        Objects.requireNonNull(message, "message must not be null");
    }

    public static ValidationViolation schemaViolation(String parameterName, String message, String offendingValue) {
        return new ValidationViolation(
                parameterName,
                SecurityViolation.TYPE_SCHEMA_VIOLATION,
                SecurityViolation.SEVERITY_HIGH,
                message,
                offendingValue
        );
    }

    public static ValidationViolation pathTraversal(String parameterName, String message, String offendingValue) {
        return new ValidationViolation(
                parameterName,
                SecurityViolation.TYPE_PATH_TRAVERSAL,
                SecurityViolation.SEVERITY_HIGH,
                message,
                offendingValue
        );
    }

    public static ValidationViolation sqlInjection(String parameterName, String message, String offendingValue) {
        return new ValidationViolation(
                parameterName,
                SecurityViolation.TYPE_SCHEMA_VIOLATION,
                SecurityViolation.SEVERITY_CRITICAL,
                message,
                offendingValue
        );
    }

    public static ValidationViolation commandInjection(String parameterName, String message, String offendingValue) {
        return new ValidationViolation(
                parameterName,
                SecurityViolation.TYPE_SCHEMA_VIOLATION,
                SecurityViolation.SEVERITY_HIGH,
                message,
                offendingValue
        );
    }
}
