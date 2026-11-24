package dev.aegismcp.gateway.dlp;

/**
 * Specific pattern types detected by the DLP scanner.
 *
 * <p>Each pattern carries the C-001 replacement marker for its family: a credential becomes
 * {@code [REDACTED_SECRET:TYPE]} and a personal identifier becomes {@code [REDACTED_PII:TYPE]},
 * where TYPE names the family the scanner detected.
 *
 * <p>Anchors: FEAT-005, C-001.
 */
public enum DlpPatternType {
    // API Keys
    AWS_ACCESS_KEY(DlpCategory.API_KEY, "[REDACTED_SECRET:AWS_KEY]"),
    AWS_SECRET_KEY(DlpCategory.API_KEY, "[REDACTED_SECRET:AWS_KEY]"),
    OPENAI_API_KEY(DlpCategory.API_KEY, "[REDACTED_SECRET:OPENAI_KEY]"),
    GITHUB_TOKEN(DlpCategory.API_KEY, "[REDACTED_SECRET:GITHUB_TOKEN]"),
    BEARER_TOKEN(DlpCategory.API_KEY, "[REDACTED_SECRET:BEARER_TOKEN]"),

    // Private Keys
    PEM_PRIVATE_KEY(DlpCategory.PRIVATE_KEY, "[REDACTED_SECRET:PRIVATE_KEY]"),
    PGP_PRIVATE_KEY(DlpCategory.PRIVATE_KEY, "[REDACTED_SECRET:PRIVATE_KEY]"),

    // Database Connection Strings with Passwords
    DATABASE_CONNECTION_STRING(DlpCategory.DATABASE_CREDENTIAL, "[REDACTED_SECRET:DATABASE_CREDENTIAL]"),
    JDBC_CONNECTION_STRING(DlpCategory.DATABASE_CREDENTIAL, "[REDACTED_SECRET:DATABASE_CREDENTIAL]"),

    // Personal Data (PII)
    SSN(DlpCategory.PII, "[REDACTED_PII:SSN]"),
    CREDIT_CARD(DlpCategory.PII, "[REDACTED_PII:CREDIT_CARD]"),
    EMAIL_ADDRESS(DlpCategory.PII, "[REDACTED_PII:EMAIL]"),
    PHONE_NUMBER(DlpCategory.PII, "[REDACTED_PII:PHONE]"),

    // Unformatted High Entropy
    HIGH_ENTROPY_TOKEN(DlpCategory.HIGH_ENTROPY_SECRET, "[REDACTED_SECRET:HIGH_ENTROPY]");

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
