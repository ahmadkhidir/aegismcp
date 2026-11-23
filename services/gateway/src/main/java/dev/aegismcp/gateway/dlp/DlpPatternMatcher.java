package dev.aegismcp.gateway.dlp;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Regex pattern library for credentials, API keys, private keys, database URLs with passwords,
 * and personal data (PII).
 *
 * <p>Every pattern is evaluated against a bounded region of the payload, never against the whole
 * payload. The caller ({@link DlpScanner}) narrows the work to the neighbourhood of a candidate it
 * already found, which keeps a 1 MB response within the NFR-002 budget and removes the
 * catastrophic-backtracking behaviour of word-boundary scans over megabytes of input.
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

    /** A compiled pattern plus the capture group that carries the sensitive span. */
    private record Spec(Pattern pattern, int group) {
    }

    private static final Map<DlpPatternType, Spec> SPECS = new EnumMap<>(DlpPatternType.class);

    static {
        SPECS.put(DlpPatternType.AWS_ACCESS_KEY, new Spec(AWS_ACCESS_KEY_PATTERN, 0));
        SPECS.put(DlpPatternType.AWS_SECRET_KEY, new Spec(AWS_SECRET_KEY_PATTERN, 1));
        SPECS.put(DlpPatternType.OPENAI_API_KEY, new Spec(OPENAI_KEY_PATTERN, 0));
        SPECS.put(DlpPatternType.GITHUB_TOKEN, new Spec(GITHUB_TOKEN_PATTERN, 0));
        SPECS.put(DlpPatternType.BEARER_TOKEN, new Spec(BEARER_TOKEN_PATTERN, 1));
        SPECS.put(DlpPatternType.PEM_PRIVATE_KEY, new Spec(PEM_PRIVATE_KEY_PATTERN, 0));
        SPECS.put(DlpPatternType.PGP_PRIVATE_KEY, new Spec(PGP_PRIVATE_KEY_PATTERN, 0));
        SPECS.put(DlpPatternType.DATABASE_CONNECTION_STRING, new Spec(DB_URI_WITH_PASSWORD_PATTERN, 0));
        SPECS.put(DlpPatternType.JDBC_CONNECTION_STRING, new Spec(JDBC_WITH_PASSWORD_PATTERN, 0));
        SPECS.put(DlpPatternType.SSN, new Spec(SSN_PATTERN, 0));
        SPECS.put(DlpPatternType.CREDIT_CARD, new Spec(CREDIT_CARD_CANDIDATE_PATTERN, 0));
        SPECS.put(DlpPatternType.EMAIL_ADDRESS, new Spec(EMAIL_PATTERN, 0));
        SPECS.put(DlpPatternType.PHONE_NUMBER, new Spec(PHONE_PATTERN, 0));
    }

    private final DlpConfig config;

    public DlpPatternMatcher(DlpConfig config) {
        this.config = Objects.requireNonNull(config, "config must not be null");
    }

    /**
     * Applies a single pattern type to the region {@code [from, to)} of {@code text} and appends
     * every detection with absolute offsets.
     *
     * <p>Region bounds are transparent, so a word boundary at either edge is evaluated against the
     * characters outside the region exactly as it would be in a whole-payload scan.
     */
    public void scan(DlpPatternType type, CharSequence text, int from, int to, List<DlpDetection> out) {
        Spec spec = SPECS.get(type);
        if (spec == null || from >= to) {
            return;
        }

        Matcher matcher = spec.pattern().matcher(text);
        matcher.region(from, to);
        matcher.useTransparentBounds(true);
        matcher.useAnchoringBounds(false);

        String replacement = config.resolveReplacement(type);
        while (matcher.find()) {
            int start = matcher.start(spec.group());
            int end = matcher.end(spec.group());
            if (start < 0 || end <= start) {
                continue;
            }
            if (type == DlpPatternType.CREDIT_CARD && !LuhnValidator.isValidCreditCard(text, start, end)) {
                continue;
            }
            if (type == DlpPatternType.PHONE_NUMBER && isIpOrVersion(matcher.group(spec.group()))) {
                continue;
            }
            out.add(new DlpDetection(
                    type.category(),
                    type,
                    start,
                    end,
                    text.subSequence(start, end).toString(),
                    replacement
            ));
        }
    }

    private static boolean isIpOrVersion(String match) {
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
