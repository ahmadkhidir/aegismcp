package dev.aegismcp.gateway.dlp;

import java.util.Objects;

/**
 * Record representing a detected secret or PII instance within a payload.
 * Anchors: FEAT-005.
 *
 * @param category     High-level category (API_KEY, PRIVATE_KEY, DATABASE_CREDENTIAL, PII, HIGH_ENTROPY_SECRET)
 * @param patternType  Specific pattern type detected
 * @param start        Start offset in text (inclusive)
 * @param end          End offset in text (exclusive)
 * @param matchedText  The matched raw text containing the secret/PII
 * @param replacement  Deterministic replacement string
 */
public record DlpDetection(
        DlpCategory category,
        DlpPatternType patternType,
        int start,
        int end,
        String matchedText,
        String replacement
) implements Comparable<DlpDetection> {

    public DlpDetection {
        Objects.requireNonNull(category, "category must not be null");
        Objects.requireNonNull(patternType, "patternType must not be null");
        Objects.requireNonNull(matchedText, "matchedText must not be null");
        Objects.requireNonNull(replacement, "replacement must not be null");
        if (start < 0 || end < start) {
            throw new IllegalArgumentException("Invalid offsets: start=" + start + ", end=" + end);
        }
    }

    @Override
    public int compareTo(DlpDetection other) {
        int cmp = Integer.compare(this.start, other.start);
        if (cmp != 0) {
            return cmp;
        }
        // Longer spans take priority on identical start offsets
        return Integer.compare(other.end, this.end);
    }
}
