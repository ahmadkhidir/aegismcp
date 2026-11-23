package dev.aegismcp.gateway.dlp;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shannon entropy scanner to catch unformatted high-entropy secrets (e.g., random base64/alphanumeric tokens).
 *
 * <p>The candidate regex is only evaluated against the token run the caller already isolated, so the
 * cost per payload is proportional to the number of long tokens, not to the payload size.
 * Anchors: FEAT-005, NFR-002.
 */
public final class ShannonEntropyScanner {

    // Matches unformatted alphanumeric/base64 tokens of length >= minLength
    private static final Pattern CANDIDATE_TOKEN_PATTERN = Pattern.compile(
            "\\b[A-Za-z0-9+/=_-]{16,}\\b"
    );

    // Standard UUID RFC 4122 pattern (excluded from high entropy flags)
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );

    // Common ISO-8601 timestamps
    private static final Pattern TIMESTAMP_PATTERN = Pattern.compile(
            "^\\d{4}-\\d{2}-\\d{2}(?:T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?)?$"
    );

    private final DlpConfig config;

    public ShannonEntropyScanner(DlpConfig config) {
        this.config = Objects.requireNonNull(config, "config must not be null");
    }

    /**
     * Calculates the Shannon entropy in bits per character:
     * H = - \sum (P(x) * log2(P(x)))
     */
    public static double calculateEntropy(CharSequence token) {
        if (token == null || token.isEmpty()) {
            return 0.0;
        }
        return calculateEntropy(token, 0, token.length());
    }

    /**
     * Fast zero-allocation Shannon entropy computation over a sub-sequence.
     */
    public static double calculateEntropy(CharSequence token, int start, int end) {
        int length = end - start;
        if (length <= 0) {
            return 0.0;
        }

        int[] frequencies = new int[256];
        for (int i = start; i < end; i++) {
            char c = token.charAt(i);
            if (c < 256) {
                frequencies[c]++;
            }
        }

        double log2Length = Math.log(length) / Math.log(2.0);
        double sum = 0.0;
        for (int count : frequencies) {
            if (count > 0) {
                sum += count * (Math.log(count) / Math.log(2.0));
            }
        }

        return log2Length - (sum / length);
    }

    /**
     * Scans a whole string for high-entropy secret tokens.
     */
    public List<DlpDetection> scan(String text) {
        List<DlpDetection> detections = new ArrayList<>();
        if (text != null) {
            scan(text, 0, text.length(), detections);
        }
        return detections;
    }

    /**
     * Scans the region {@code [from, to)} of {@code text}, which the caller has already narrowed to
     * a single token run, and appends detections with absolute offsets.
     */
    public void scan(CharSequence text, int from, int to, List<DlpDetection> detections) {
        if (!config.isEnableEntropyScanner() || text == null || from >= to) {
            return;
        }
        int minLength = config.getMinEntropyTokenLength();
        if (to - from < minLength) {
            return;
        }

        Matcher matcher = CANDIDATE_TOKEN_PATTERN.matcher(text);
        matcher.region(from, to);
        matcher.useTransparentBounds(true);
        matcher.useAnchoringBounds(false);

        double threshold = config.getEntropyThreshold();
        String replacement = config.resolveReplacement(DlpPatternType.HIGH_ENTROPY_TOKEN);

        while (matcher.find()) {
            int start = matcher.start();
            int end = matcher.end();

            if (end - start < minLength) {
                continue;
            }

            String token = matcher.group();

            // Check exclusions
            if (isExcluded(token, text, start, end)) {
                continue;
            }

            double entropy = calculateEntropy(text, start, end);
            if (entropy >= threshold) {
                detections.add(new DlpDetection(
                        DlpCategory.HIGH_ENTROPY_SECRET,
                        DlpPatternType.HIGH_ENTROPY_TOKEN,
                        start,
                        end,
                        token,
                        replacement
                ));
            }
        }
    }

    /**
     * Excludes false positive candidates like UUIDs, timestamps, URLs, and standard code identifiers.
     */
    private boolean isExcluded(String token, CharSequence fullText, int start, int end) {
        // Exclude UUIDs
        if (UUID_PATTERN.matcher(token).matches()) {
            return true;
        }

        // Exclude ISO timestamps
        if (TIMESTAMP_PATTERN.matcher(token).matches()) {
            return true;
        }

        // Exclude URLs and web schemes (e.g. preceded by "http://", "https://", etc.)
        if (start >= 7) {
            CharSequence prefix = fullText.subSequence(Math.max(0, start - 8), start);
            String prefixText = prefix.toString();
            if (prefixText.endsWith("http://") || prefixText.endsWith("https://") || prefixText.endsWith("ftp://")) {
                return true;
            }
        }

        // Exclude file paths or package names (e.g. surrounded by slashes or package dots)
        if (start > 0 && fullText.charAt(start - 1) == '/') {
            return true;
        }
        if (end < fullText.length() && fullText.charAt(end) == '/') {
            return true;
        }

        // Exclude identifiers that are clearly PascalCase or camelCase English words
        // e.g. "ConcurrentHashMapWithVirtualThreads"
        return isPascalOrCamelCaseCodeIdentifier(token);
    }

    /**
     * Checks if a token is a typical code identifier composed of concatenated words
     * (e.g. AbstractAnnotationConfigDispatcherServletInitializer).
     */
    private boolean isPascalOrCamelCaseCodeIdentifier(String token) {
        // If it contains non-alphabetic chars (digits, +, /, =, _), check distribution
        boolean hasDigits = false;
        boolean hasSymbols = false;
        int upperCount = 0;
        int lowerCount = 0;

        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (Character.isDigit(c)) {
                hasDigits = true;
            } else if (c == '+' || c == '/' || c == '=' || c == '_' || c == '-') {
                hasSymbols = true;
            } else if (Character.isUpperCase(c)) {
                upperCount++;
            } else if (Character.isLowerCase(c)) {
                lowerCount++;
            }
        }

        // Pure letters with multiple camelCase word boundaries are code identifiers
        if (!hasDigits && !hasSymbols && upperCount >= 2 && lowerCount > 0) {
            return true;
        }

        // All lowercase or all uppercase letters without numbers/symbols are normal words
        return !hasDigits && !hasSymbols && (upperCount == 0 || lowerCount == 0);
    }
}
