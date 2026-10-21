package dev.aegismcp.gateway.compliance;

/**
 * Standard regulatory compliance control frameworks supported by AegisMCP.
 * Anchors: FEAT-011, NFR-040, NFR-041, NFR-042, C-011.
 */
public enum ComplianceFramework {
    EU_AI_ACT("EU AI Act (Articles 12 & 14)"),
    SOC2_TYPE2("SOC 2 Type II Security & Confidentiality");

    private final String displayName;

    ComplianceFramework(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static ComplianceFramework fromString(String framework) {
        if (framework == null || framework.isBlank()) {
            throw new IllegalArgumentException("Framework must not be null or blank");
        }
        String clean = framework.trim().toUpperCase().replace("-", "_").replace(" ", "_");
        for (ComplianceFramework cf : values()) {
            if (cf.name().equals(clean)) {
                return cf;
            }
        }
        throw new IllegalArgumentException("Unsupported compliance framework: " + framework + ". Supported: EU_AI_ACT, SOC2_TYPE2");
    }
}
