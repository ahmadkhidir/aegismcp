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

    private final boolean enableEntropyScanner;
    private final double entropyThreshold;
    private final int minEntropyTokenLength;
    private final boolean fineGrainedPii;
    private final Map<DlpCategory, String> categoryReplacements;
    private final Map<DlpPatternType, String> patternReplacements;

    private DlpConfig(Builder builder) {
        this.enableEntropyScanner = builder.enableEntropyScanner;
        this.entropyThreshold = builder.entropyThreshold;
        this.minEntropyTokenLength = builder.minEntropyTokenLength;
        this.fineGrainedPii = builder.fineGrainedPii;
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

    public boolean isFineGrainedPii() {
        return fineGrainedPii;
    }

    public String resolveReplacement(DlpPatternType patternType) {
        if (patternReplacements.containsKey(patternType)) {
            return patternReplacements.get(patternType);
        }
        if (fineGrainedPii && patternType.category() == DlpCategory.PII) {
            return patternType.fineGrainedReplacement();
        }
        DlpCategory cat = patternType.category();
        return categoryReplacements.getOrDefault(cat, cat.defaultReplacement());
    }

    public static final class Builder {
        private boolean enableEntropyScanner = true;
        private double entropyThreshold = DEFAULT_ENTROPY_THRESHOLD;
        private int minEntropyTokenLength = DEFAULT_MIN_ENTROPY_TOKEN_LENGTH;
        private boolean fineGrainedPii = false;
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

        public Builder fineGrainedPii(boolean fineGrained) {
            this.fineGrainedPii = fineGrained;
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
