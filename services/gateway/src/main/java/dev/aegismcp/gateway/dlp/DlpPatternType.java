package dev.aegismcp.gateway.dlp;

/**
 * Specific pattern types detected by the DLP scanner.
 * Anchors: FEAT-005, C-001.
 */
public enum DlpPatternType {
    // API Keys
    AWS_ACCESS_KEY(DlpCategory.API_KEY, "[REDACTED_API_KEY]"),
    AWS_SECRET_KEY(DlpCategory.API_KEY, "[REDACTED_API_KEY]"),
    OPENAI_API_KEY(DlpCategory.API_KEY, "[REDACTED_API_KEY]"),
    GITHUB_TOKEN(DlpCategory.API_KEY, "[REDACTED_API_KEY]"),
    BEARER_TOKEN(DlpCategory.API_KEY, "[REDACTED_API_KEY]"),

    // Private Keys
    PEM_PRIVATE_KEY(DlpCategory.PRIVATE_KEY, "[REDACTED_PRIVATE_KEY]"),
    PGP_PRIVATE_KEY(DlpCategory.PRIVATE_KEY, "[REDACTED_PRIVATE_KEY]"),

    // Database Connection Strings with Passwords
    DATABASE_CONNECTION_STRING(DlpCategory.DATABASE_CREDENTIAL, "[REDACTED_DB_CREDENTIAL]"),
    JDBC_CONNECTION_STRING(DlpCategory.DATABASE_CREDENTIAL, "[REDACTED_DB_CREDENTIAL]"),

    // Personal Data (PII)
    SSN(DlpCategory.PII, "[REDACTED_SSN]"),
    CREDIT_CARD(DlpCategory.PII, "[REDACTED_CREDIT_CARD]"),
    EMAIL_ADDRESS(DlpCategory.PII, "[REDACTED_EMAIL]"),
    PHONE_NUMBER(DlpCategory.PII, "[REDACTED_PHONE]"),

    // Unformatted High Entropy
    HIGH_ENTROPY_TOKEN(DlpCategory.HIGH_ENTROPY_SECRET, "[REDACTED_HIGH_ENTROPY_SECRET]");

    private final DlpCategory category;
    private final String fineGrainedReplacement;

    DlpPatternType(DlpCategory category, String fineGrainedReplacement) {
        this.category = category;
        this.fineGrainedReplacement = fineGrainedReplacement;
    }

    public DlpCategory category() {
        return category;
    }

    public String fineGrainedReplacement() {
        return fineGrainedReplacement;
    }
}
