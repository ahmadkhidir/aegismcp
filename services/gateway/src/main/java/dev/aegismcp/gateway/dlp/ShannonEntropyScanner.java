package dev.aegismcp.gateway.dlp;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shannon entropy scanner to catch unformatted high-entropy secrets (e.g., random base64/alphanumeric tokens).
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
     * Scans the input text for high-entropy secret tokens.
     */
    public List<DlpDetection> scan(String text) {
        List<DlpDetection> detections = new ArrayList<>();
        if (!config.isEnableEntropyScanner() || text == null || text.length() < config.getMinEntropyTokenLength()) {
            return detections;
        }

        Matcher matcher = CANDIDATE_TOKEN_PATTERN.matcher(text);
        int minLength = config.getMinEntropyTokenLength();
        double threshold = config.getEntropyThreshold();
        String replacement = config.resolveReplacement(DlpPatternType.HIGH_ENTROPY_TOKEN);

        while (matcher.find()) {
            int start = matcher.start();
            int end = matcher.end();
            int tokenLength = end - start;

            if (tokenLength < minLength) {
                continue;
            }

            String token = matcher.group();

            // Check exclusions
            if (isExcluded(token, text, start, end)) {
                continue;
            }

            double entropy = calculateEntropy(token);
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

        return detections;
    }

    /**
     * Excludes false positive candidates like UUIDs, timestamps, URLs, and standard code identifiers.
     */
    private boolean isExcluded(String token, String fullText, int start, int end) {
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
            String prefix = fullText.substring(Math.max(0, start - 8), start);
            if (prefix.endsWith("http://") || prefix.endsWith("https://") || prefix.endsWith("ftp://")) {
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

        // Exclude pure hex hashes if length is 32 or 40 or 64 and entropy is low (<= 4.0)
        // Note: Max entropy of hex is 4.0; if threshold > 4.0, hex is naturally excluded.

        // Exclude identifiers that are clearly PascalCase or camelCase English words
        // e.g. "ConcurrentHashMapWithVirtualThreads"
        if (isPascalOrCamelCaseCodeIdentifier(token)) {
            return true;
        }

        return false;
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
        if (!hasDigits && !hasSymbols && (upperCount == 0 || lowerCount == 0)) {
            return true;
        }

        return false;
    }
}
