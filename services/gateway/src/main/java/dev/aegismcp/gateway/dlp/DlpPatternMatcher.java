package dev.aegismcp.gateway.dlp;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * High-throughput regex pattern matcher covering credentials, API keys, private keys,
 * database URLs with passwords, and personal data (PII).
 * Anchors: FEAT-005, NFR-002, C-001.
 */
public final class DlpPatternMatcher {

    // --- API Keys ---
    private static final Pattern AWS_ACCESS_KEY_PATTERN = Pattern.compile(
            "\\b(AKIA|ASIA|AROA|AIPA|ANPA|ANVA|AGPA)[A-Z0-9]{16}\\b"
    );

    private static final Pattern AWS_SECRET_KEY_PATTERN = Pattern.compile(
            "(?i)\\b(?:aws_secret_access_key|aws_secret_key|secret_key|aws_secret)\\s*[:=]\\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
    );

    private static final Pattern OPENAI_KEY_PATTERN = Pattern.compile(
            "\\bsk-(?:proj-|admin-|svcacct-)?[A-Za-z0-9_-]{20,}\\b"
    );

    private static final Pattern GITHUB_TOKEN_PATTERN = Pattern.compile(
            "\\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\\b|\\bgithub_pat_[A-Za-z0-9_]{82}\\b"
    );

    private static final Pattern BEARER_TOKEN_PATTERN = Pattern.compile(
            "(?i)\\bBearer\\s+([A-Za-z0-9_\\-\\.]{20,})\\b"
    );

    // --- Private Keys ---
    private static final Pattern PEM_PRIVATE_KEY_PATTERN = Pattern.compile(
            "-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\\s\\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    );

    private static final Pattern PGP_PRIVATE_KEY_PATTERN = Pattern.compile(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----[\\s\\S]*?-----END PGP PRIVATE KEY BLOCK-----"
    );

    // --- Database Connection Strings with Passwords ---
    private static final Pattern DB_URI_WITH_PASSWORD_PATTERN = Pattern.compile(
            "\\b(?:postgres(?:ql)?|mongodb(?:\\+srv)?|mysql|redis|mariadb)://[^:\\s\"'/]+:([^@\\s\"']+)@[^\\s\"']+\\b"
    );

    private static final Pattern JDBC_WITH_PASSWORD_PATTERN = Pattern.compile(
            "\\bjdbc:[a-zA-Z0-9]+://[^\\s\"']*(?:password=([^;&\\s\"']+)|:([^@\\s\"']+)@)[^\\s\"']*"
    );

    // --- Personal Data (PII) ---
    private static final Pattern SSN_PATTERN = Pattern.compile(
            "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b"
    );

    // Candidate credit cards for Luhn validation
    private static final Pattern CREDIT_CARD_CANDIDATE_PATTERN = Pattern.compile(
            "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|2(?:2[2-9][0-9]{12}|[3-6][0-9]{13}|7[0-1][0-9]{12}|720[0-9]{12})|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\\b|" +
            "\\b(?:\\d{4}[ -]){3}\\d{4}\\b|\\b3[47]\\d{2}[ -]\\d{6}[ -]\\d{5}\\b"
    );

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"
    );

    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "\\b(?:\\+?1[-.\\s]?)?\\(?([2-9]\\d{2})\\)?[-.\\s]?([2-9]\\d{2})[-.\\s]?(\\d{4})\\b|" +
            "\\b\\+(?:[1-9]\\d{0,2})[-.\\s]?\\(?\\d{1,4}\\)?[-.\\s]?\\d{1,4}[-.\\s]?\\d{2,9}\\b"
    );

    private final DlpConfig config;

    public DlpPatternMatcher(DlpConfig config) {
        this.config = Objects.requireNonNull(config, "config must not be null");
    }

    /**
     * Scans input text and returns all detected DLP patterns.
     */
    public List<DlpDetection> scan(String text) {
        List<DlpDetection> detections = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return detections;
        }

        // 1. AWS Access Key
        if (text.length() < 200 || containsAnyAwsPrefix(text)) {
            scanSimple(AWS_ACCESS_KEY_PATTERN, DlpPatternType.AWS_ACCESS_KEY, text, detections);
        }

        // 2. AWS Secret Key
        if (text.length() < 200 || containsIgnoreCase(text, "secret")) {
            scanSecretKey(AWS_SECRET_KEY_PATTERN, DlpPatternType.AWS_SECRET_KEY, text, detections);
        }

        // 3. OpenAI API Key
        if (text.length() < 200 || text.contains("sk-")) {
            scanSimple(OPENAI_KEY_PATTERN, DlpPatternType.OPENAI_API_KEY, text, detections);
        }

        // 4. GitHub Token
        if (text.length() < 200 || text.contains("gh") || text.contains("github_pat_")) {
            scanSimple(GITHUB_TOKEN_PATTERN, DlpPatternType.GITHUB_TOKEN, text, detections);
        }

        // 5. Bearer Token (masks token portion)
        if (text.length() < 200 || containsIgnoreCase(text, "bearer")) {
            scanBearerToken(text, detections);
        }

        // 6. PEM Private Key
        if (text.length() < 200 || text.contains("-----BEGIN")) {
            scanSimple(PEM_PRIVATE_KEY_PATTERN, DlpPatternType.PEM_PRIVATE_KEY, text, detections);
            scanSimple(PGP_PRIVATE_KEY_PATTERN, DlpPatternType.PGP_PRIVATE_KEY, text, detections);
        }

        // 8. DB Connection Strings
        if (text.length() < 200 || text.contains("://")) {
            scanSimple(DB_URI_WITH_PASSWORD_PATTERN, DlpPatternType.DATABASE_CONNECTION_STRING, text, detections);
        }
        if (text.length() < 200 || text.contains("jdbc:")) {
            scanSimple(JDBC_WITH_PASSWORD_PATTERN, DlpPatternType.JDBC_CONNECTION_STRING, text, detections);
        }

        // 9. SSN
        if (text.length() < 200 || text.indexOf('-') >= 0) {
            scanSimple(SSN_PATTERN, DlpPatternType.SSN, text, detections);
        }

        // 10. Credit Card (with Luhn check)
        scanCreditCards(text, detections);

        // 11. Email
        if (text.length() < 200 || text.indexOf('@') >= 0) {
            scanSimple(EMAIL_PATTERN, DlpPatternType.EMAIL_ADDRESS, text, detections);
        }

        // 12. Phone
        scanPhone(text, detections);

        return detections;
    }

    private static boolean containsAnyAwsPrefix(String text) {
        return text.contains("AKIA") || text.contains("ASIA") || text.contains("AROA")
                || text.contains("AIPA") || text.contains("ANPA") || text.contains("ANVA") || text.contains("AGPA");
    }

    private static boolean containsIgnoreCase(String text, String needle) {
        int nlen = needle.length();
        int tlen = text.length();
        if (tlen < nlen) return false;
        char firstLower = Character.toLowerCase(needle.charAt(0));
        char firstUpper = Character.toUpperCase(needle.charAt(0));
        for (int i = 0; i <= tlen - nlen; i++) {
            char c = text.charAt(i);
            if (c == firstLower || c == firstUpper) {
                boolean match = true;
                for (int j = 1; j < nlen; j++) {
                    char tc = Character.toLowerCase(text.charAt(i + j));
                    char nc = Character.toLowerCase(needle.charAt(j));
                    if (tc != nc) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
        }
        return false;
    }

    private void scanSimple(Pattern pattern, DlpPatternType type, String text, List<DlpDetection> detections) {
        Matcher matcher = pattern.matcher(text);
        String replacement = config.resolveReplacement(type);
        while (matcher.find()) {
            detections.add(new DlpDetection(
                    type.category(),
                    type,
                    matcher.start(),
                    matcher.end(),
                    matcher.group(),
                    replacement
            ));
        }
    }

    private void scanSecretKey(Pattern pattern, DlpPatternType type, String text, List<DlpDetection> detections) {
        Matcher matcher = pattern.matcher(text);
        String replacement = config.resolveReplacement(type);
        while (matcher.find()) {
            // Group 1 is the 40-char secret
            int start = matcher.start(1);
            int end = matcher.end(1);
            detections.add(new DlpDetection(
                    type.category(),
                    type,
                    start,
                    end,
                    matcher.group(1),
                    replacement
            ));
        }
    }

    private void scanBearerToken(String text, List<DlpDetection> detections) {
        Matcher matcher = BEARER_TOKEN_PATTERN.matcher(text);
        String replacement = config.resolveReplacement(DlpPatternType.BEARER_TOKEN);
        while (matcher.find()) {
            // Replace the token part (group 1)
            int start = matcher.start(1);
            int end = matcher.end(1);
            detections.add(new DlpDetection(
                    DlpCategory.API_KEY,
                    DlpPatternType.BEARER_TOKEN,
                    start,
                    end,
                    matcher.group(1),
                    replacement
            ));
        }
    }

    private void scanCreditCards(String text, List<DlpDetection> detections) {
        Matcher matcher = CREDIT_CARD_CANDIDATE_PATTERN.matcher(text);
        String replacement = config.resolveReplacement(DlpPatternType.CREDIT_CARD);
        while (matcher.find()) {
            if (LuhnValidator.isValidCreditCard(text, matcher.start(), matcher.end())) {
                detections.add(new DlpDetection(
                        DlpCategory.PII,
                        DlpPatternType.CREDIT_CARD,
                        matcher.start(),
                        matcher.end(),
                        matcher.group(),
                        replacement
                ));
            }
        }
    }

    private void scanPhone(String text, List<DlpDetection> detections) {
        Matcher matcher = PHONE_PATTERN.matcher(text);
        String replacement = config.resolveReplacement(DlpPatternType.PHONE_NUMBER);
        while (matcher.find()) {
            String match = matcher.group();
            // Disqualify IP-like patterns or date-like patterns
            if (match.contains(".") && isIpOrVersion(match)) {
                continue;
            }
            detections.add(new DlpDetection(
                    DlpCategory.PII,
                    DlpPatternType.PHONE_NUMBER,
                    matcher.start(),
                    matcher.end(),
                    match,
                    replacement
            ));
        }
    }

    private boolean isIpOrVersion(String match) {
        // Simple check if it looks like 192.168.1.1 or 1.2.3.4
        String[] parts = match.split("\\.");
        if (parts.length >= 3) {
            for (String p : parts) {
                try {
                    int val = Integer.parseInt(p.trim());
                    if (val < 0 || val > 255) {
                        return false;
                    }
                } catch (NumberFormatException e) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }
}
