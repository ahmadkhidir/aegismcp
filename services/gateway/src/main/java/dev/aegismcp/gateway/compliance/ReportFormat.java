package dev.aegismcp.gateway.compliance;

/**
 * Report export serialisation format.
 * Anchors: C-011, FEAT-011.
 */
public enum ReportFormat {
    JSON("application/json"),
    CSV("text/csv");

    private final String mediaType;

    ReportFormat(String mediaType) {
        this.mediaType = mediaType;
    }

    public String getMediaType() {
        return mediaType;
    }

    public static ReportFormat fromString(String format) {
        if (format == null || format.isBlank()) {
            throw new IllegalArgumentException("Report format must not be null or blank");
        }
        String clean = format.trim().toUpperCase();
        for (ReportFormat rf : values()) {
            if (rf.name().equals(clean)) {
                return rf;
            }
        }
        throw new IllegalArgumentException("Unsupported report format: " + format + ". Supported: JSON, CSV");
    }
}
