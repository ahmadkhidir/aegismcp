package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Locale;

/**
 * Lifecycle status of a Human-in-the-Loop approval ticket.
 * Conforms to schema.md#ApprovalTicket and contract C-003.
 * Anchors: FEAT-006, C-003, C-004.
 */
public enum ApprovalStatus {
    PENDING("pending"),
    APPROVED("approved"),
    REJECTED("rejected"),
    TIMED_OUT("timed_out");

    private final String value;

    ApprovalStatus(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    @JsonCreator
    public static ApprovalStatus fromString(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String normalized = text.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "pending" -> PENDING;
            case "approved", "approve" -> APPROVED;
            case "rejected", "reject" -> REJECTED;
            case "timed_out", "timeout", "timedout", "expired" -> TIMED_OUT;
            default -> throw new IllegalArgumentException("Unknown approval status: " + text);
        };
    }

    public boolean isTerminal() {
        return this != PENDING;
    }
}
