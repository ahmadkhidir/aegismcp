package dev.aegismcp.gateway.validation;

import dev.aegismcp.gateway.anomaly.SecurityViolation;

import java.util.Objects;

/**
 * Encapsulates a single parameter validation, schema deviation, or injection sanitization violation.
 *
 * <p>Two classifications travel with every violation because they answer different questions. The
 * {@code violationType} is the {@code schema.md#SecurityViolation} family recorded in the audit
 * trail, which names one value for every argument-level incident. The {@code family} is the C-001
 * response row the agent sees, which distinguishes a malformed argument ({@code
 * SCHEMA_VALIDATION_FAILED}) from a traversal ({@code PATH_TRAVERSAL}) or an injection payload
 * ({@code SQL_INJECTION}).
 *
 * <p>Anchors: FEAT-012, NFR-024, C-001, schema.md#SecurityViolation.
 */
public record ValidationViolation(
        String parameterName,
        String violationType,
        Family family,
        String severity,
        String message,
        String offendingValue
) {
    /** C-001 response family an argument violation is reported under. */
    public enum Family {
        SCHEMA,
        PATH_TRAVERSAL,
        SQL_INJECTION,
        COMMAND_INJECTION
    }

    public ValidationViolation {
        Objects.requireNonNull(parameterName, "parameterName must not be null");
        Objects.requireNonNull(violationType, "violationType must not be null");
        Objects.requireNonNull(family, "family must not be null");
        Objects.requireNonNull(severity, "severity must not be null");
        Objects.requireNonNull(message, "message must not be null");
    }

    public static ValidationViolation schemaViolation(String parameterName, String message, String offendingValue) {
        return new ValidationViolation(
                parameterName,
                SecurityViolation.TYPE_SCHEMA_VIOLATION,
                Family.SCHEMA,
                SecurityViolation.SEVERITY_HIGH,
                message,
                offendingValue
        );
    }

    public static ValidationViolation pathTraversal(String parameterName, String message, String offendingValue) {
        return new ValidationViolation(
                parameterName,
                SecurityViolation.TYPE_PATH_TRAVERSAL,
                Family.PATH_TRAVERSAL,
                SecurityViolation.SEVERITY_HIGH,
                message,
                offendingValue
        );
    }

    public static ValidationViolation sqlInjection(String parameterName, String message, String offendingValue) {
        return new ValidationViolation(
                parameterName,
                SecurityViolation.TYPE_SCHEMA_VIOLATION,
                Family.SQL_INJECTION,
                SecurityViolation.SEVERITY_CRITICAL,
                message,
                offendingValue
        );
    }

    public static ValidationViolation commandInjection(String parameterName, String message, String offendingValue) {
        return new ValidationViolation(
                parameterName,
                SecurityViolation.TYPE_SCHEMA_VIOLATION,
                Family.COMMAND_INJECTION,
                SecurityViolation.SEVERITY_HIGH,
                message,
                offendingValue
        );
    }
}
