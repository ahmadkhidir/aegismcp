package dev.aegismcp.gateway.dlp;

/**
 * High-level categories for data loss prevention (DLP) detections.
 *
 * <p>The category fallback keeps the C-001 marker shape when a detection has no finer family: a
 * credential is a {@code [REDACTED_SECRET:...]} marker and personal data is a
 * {@code [REDACTED_PII:...]} marker.
 *
 * <p>Anchors: FEAT-005, C-001.
 */
public enum DlpCategory {
    API_KEY("[REDACTED_SECRET:API_KEY]"),
    PRIVATE_KEY("[REDACTED_SECRET:PRIVATE_KEY]"),
    DATABASE_CREDENTIAL("[REDACTED_SECRET:DATABASE_CREDENTIAL]"),
    PII("[REDACTED_PII:PII]"),
    HIGH_ENTROPY_SECRET("[REDACTED_SECRET:HIGH_ENTROPY]");

    private final String defaultReplacement;

    DlpCategory(String defaultReplacement) {
        this.defaultReplacement = defaultReplacement;
    }

    public String defaultReplacement() {
        return defaultReplacement;
    }
}
