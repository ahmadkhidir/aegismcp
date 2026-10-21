package dev.aegismcp.gateway.dlp;

/**
 * High-level categories for data loss prevention (DLP) detections.
 * Anchors: FEAT-005, C-001.
 */
public enum DlpCategory {
    API_KEY("[REDACTED_API_KEY]"),
    PRIVATE_KEY("[REDACTED_PRIVATE_KEY]"),
    DATABASE_CREDENTIAL("[REDACTED_DB_CREDENTIAL]"),
    PII("[REDACTED_PII]"),
    HIGH_ENTROPY_SECRET("[REDACTED_HIGH_ENTROPY_SECRET]");

    private final String defaultReplacement;

    DlpCategory(String defaultReplacement) {
        this.defaultReplacement = defaultReplacement;
    }

    public String defaultReplacement() {
        return defaultReplacement;
    }
}
