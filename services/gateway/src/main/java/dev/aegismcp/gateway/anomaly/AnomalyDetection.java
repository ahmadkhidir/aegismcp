package dev.aegismcp.gateway.anomaly;

import java.util.List;
import java.util.Objects;

/**
 * Result of an anomaly evaluation identifying a prohibited sequence or behavioral anomaly.
 * Anchors: FEAT-004.
 */
public record AnomalyDetection(
        String ruleName,
        String reason,
        String severity,
        List<String> triggeringSequence
) {
    public AnomalyDetection {
        Objects.requireNonNull(ruleName, "ruleName must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        if (severity == null) {
            severity = SecurityViolation.SEVERITY_HIGH;
        }
        if (triggeringSequence == null) {
            triggeringSequence = List.of();
        } else {
            triggeringSequence = List.copyOf(triggeringSequence);
        }
    }

    public AnomalyDetection(String ruleName, String reason, String severity) {
        this(ruleName, reason, severity, List.of());
    }
}
