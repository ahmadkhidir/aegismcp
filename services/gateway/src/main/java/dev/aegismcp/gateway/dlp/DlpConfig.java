package dev.aegismcp.gateway.dlp;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable configuration for the DLP masking engine.
 * Anchors: FEAT-005, NFR-002.
 */
public final class DlpConfig {

    public static final double DEFAULT_ENTROPY_THRESHOLD = 4.5;
    public static final int DEFAULT_MIN_ENTROPY_TOKEN_LENGTH = 20;
    /**
     * Wall-clock ceiling for one scrub before the caller masks the payload instead of
     * forwarding it. A scanner that overruns this is treated as failed, never as clean.
     */
    public static final long DEFAULT_SCAN_TIMEOUT_MILLIS = 250L;

    private final boolean enableEntropyScanner;
    private final double entropyThreshold;
    private final int minEntropyTokenLength;
    private final long scanTimeoutMillis;
    private final Map<DlpCategory, String> categoryReplacements;
    private final Map<DlpPatternType, String> patternReplacements;

    private DlpConfig(Builder builder) {
        this.enableEntropyScanner = builder.enableEntropyScanner;
        this.entropyThreshold = builder.entropyThreshold;
        this.minEntropyTokenLength = builder.minEntropyTokenLength;
        this.scanTimeoutMillis = builder.scanTimeoutMillis;
        this.categoryReplacements = Collections.unmodifiableMap(new EnumMap<>(builder.categoryReplacements));
        this.patternReplacements = Collections.unmodifiableMap(new EnumMap<>(builder.patternReplacements));
    }

    public static DlpConfig defaultConfig() {
        return new Builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public boolean isEnableEntropyScanner() {
        return enableEntropyScanner;
    }

    public double getEntropyThreshold() {
        return entropyThreshold;
    }

    public int getMinEntropyTokenLength() {
        return minEntropyTokenLength;
    }

    public long getScanTimeoutMillis() {
        return scanTimeoutMillis;
    }

    /**
     * Resolves the replacement for a detection.
     *
     * <p>C-001 fixes the marker shape: {@code [REDACTED_SECRET:TYPE]} for a credential and
     * {@code [REDACTED_PII:TYPE]} for a personal identifier, where TYPE is the detected family. The
     * pattern's own family marker therefore wins over the category-wide fallback; an operator-supplied
     * pattern replacement still overrides it.
     */
    public String resolveReplacement(DlpPatternType patternType) {
        if (patternReplacements.containsKey(patternType)) {
            return patternReplacements.get(patternType);
        }
        String familyMarker = patternType.fineGrainedReplacement();
        if (familyMarker != null && !familyMarker.isBlank()) {
            return familyMarker;
        }
        DlpCategory cat = patternType.category();
        return categoryReplacements.getOrDefault(cat, cat.defaultReplacement());
    }

    public static final class Builder {
        private boolean enableEntropyScanner = true;
        private double entropyThreshold = DEFAULT_ENTROPY_THRESHOLD;
        private int minEntropyTokenLength = DEFAULT_MIN_ENTROPY_TOKEN_LENGTH;
        private long scanTimeoutMillis = DEFAULT_SCAN_TIMEOUT_MILLIS;
        private final Map<DlpCategory, String> categoryReplacements = new EnumMap<>(DlpCategory.class);
        private final Map<DlpPatternType, String> patternReplacements = new EnumMap<>(DlpPatternType.class);

        public Builder() {
            for (DlpCategory cat : DlpCategory.values()) {
                categoryReplacements.put(cat, cat.defaultReplacement());
            }
        }

        public Builder enableEntropyScanner(boolean enable) {
            this.enableEntropyScanner = enable;
            return this;
        }

        public Builder entropyThreshold(double threshold) {
            if (threshold <= 0.0 || threshold > 8.0) {
                throw new IllegalArgumentException("Entropy threshold must be between 0.0 and 8.0");
            }
            this.entropyThreshold = threshold;
            return this;
        }

        public Builder minEntropyTokenLength(int minLength) {
            if (minLength < 8) {
                throw new IllegalArgumentException("Minimum entropy token length must be >= 8");
            }
            this.minEntropyTokenLength = minLength;
            return this;
        }

        public Builder scanTimeoutMillis(long timeoutMillis) {
            if (timeoutMillis <= 0L) {
                throw new IllegalArgumentException("Scan timeout must be greater than zero");
            }
            this.scanTimeoutMillis = timeoutMillis;
            return this;
        }

        public Builder setCategoryReplacement(DlpCategory category, String replacement) {
            this.categoryReplacements.put(Objects.requireNonNull(category), Objects.requireNonNull(replacement));
            return this;
        }

        public Builder setPatternReplacement(DlpPatternType patternType, String replacement) {
            this.patternReplacements.put(Objects.requireNonNull(patternType), Objects.requireNonNull(replacement));
            return this;
        }

        public DlpConfig build() {
            return new DlpConfig(this);
        }
    }
}
