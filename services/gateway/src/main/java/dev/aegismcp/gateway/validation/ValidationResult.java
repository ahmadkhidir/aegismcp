package dev.aegismcp.gateway.validation;

import dev.aegismcp.gateway.anomaly.SecurityViolation;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Result of tool parameter schema validation and injection sanitization.
 * Anchors: FEAT-012, NFR-024, C-001.
 */
public record ValidationResult(
        boolean isValid,
        List<ValidationViolation> violations
) {
    public ValidationResult {
        violations = violations != null ? List.copyOf(violations) : Collections.emptyList();
    }

    public static ValidationResult valid() {
        return new ValidationResult(true, Collections.emptyList());
    }

    public static ValidationResult invalid(List<ValidationViolation> violations) {
        return new ValidationResult(false, violations);
    }

    public static ValidationResult invalid(ValidationViolation... violations) {
        return new ValidationResult(false, List.of(violations));
    }

    public String summaryMessage() {
        if (isValid || violations.isEmpty()) {
            return "Validation successful";
        }
        return violations.stream()
                .map(ValidationViolation::message)
                .collect(Collectors.joining("; "));
    }

    public String primaryViolationType() {
        for (ValidationViolation v : violations) {
            if (SecurityViolation.TYPE_PATH_TRAVERSAL.equals(v.violationType())) {
                return SecurityViolation.TYPE_PATH_TRAVERSAL;
            }
        }
        return SecurityViolation.TYPE_SCHEMA_VIOLATION;
    }

    /**
     * The C-001 response family for this result. A single call can trip several checks at once, so
     * the security families outrank a plain schema mismatch: a traversal or injection payload is
     * reported as such even when it also fails a type or required-property check.
     */
    public ValidationViolation.Family primaryFamily() {
        for (ValidationViolation.Family family : List.of(
                ValidationViolation.Family.PATH_TRAVERSAL,
                ValidationViolation.Family.SQL_INJECTION,
                ValidationViolation.Family.COMMAND_INJECTION)) {
            for (ValidationViolation v : violations) {
                if (v.family() == family) {
                    return family;
                }
            }
        }
        return ValidationViolation.Family.SCHEMA;
    }
}
