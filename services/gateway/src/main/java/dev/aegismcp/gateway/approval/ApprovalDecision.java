package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Locale;

/**
 * Operator authorization decision for a pending Human-in-the-Loop approval ticket.
 * Anchors: FEAT-006, C-004.
 */
public enum ApprovalDecision {
    APPROVE("APPROVE"),
    REJECT("REJECT");

    private final String value;

    ApprovalDecision(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    @JsonCreator
    public static ApprovalDecision fromString(String text) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("Approval decision must not be null or blank");
        }
        String normalized = text.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "APPROVE" -> APPROVE;
            case "REJECT" -> REJECT;
            default -> throw new IllegalArgumentException(
                    "Invalid approval decision: '" + text + "'. Expected 'APPROVE' or 'REJECT'."
            );
        };
    }
}
