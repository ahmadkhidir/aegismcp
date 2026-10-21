package dev.aegismcp.gateway.anomaly;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Anomaly rule detecting rapid repeated tool bursts exceeding acceptable frequency limits.
 * Protects against automated tool looping and rapid-fire exfiltration / resource starvation.
 * Anchors: FEAT-004, NFR-003.
 */
public class ToolBurstRule implements AnomalyRule {

    public static final int DEFAULT_MAX_CALLS_THRESHOLD = 5;
    public static final Duration DEFAULT_BURST_WINDOW = Duration.ofMillis(1000);

    private final String name;
    private final int maxCallsThreshold;
    private final Duration burstWindow;
    private final String severity;

    public ToolBurstRule(String name, int maxCallsThreshold, Duration burstWindow, String severity) {
        if (maxCallsThreshold <= 0) {
            throw new IllegalArgumentException("maxCallsThreshold must be positive, got: " + maxCallsThreshold);
        }
        this.name = Objects.requireNonNull(name, "name must not be null");
        this.maxCallsThreshold = maxCallsThreshold;
        this.burstWindow = Objects.requireNonNull(burstWindow, "burstWindow must not be null");
        this.severity = severity != null ? severity : SecurityViolation.SEVERITY_HIGH;
    }

    public ToolBurstRule(int maxCallsThreshold, Duration burstWindow) {
        this("RapidToolBurstRule", maxCallsThreshold, burstWindow, SecurityViolation.SEVERITY_HIGH);
    }

    public static ToolBurstRule defaultBurstRule() {
        return new ToolBurstRule("RapidToolBurstRule", DEFAULT_MAX_CALLS_THRESHOLD, DEFAULT_BURST_WINDOW, SecurityViolation.SEVERITY_HIGH);
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public Optional<AnomalyDetection> evaluate(
            String agentId,
            String currentTool,
            JsonNode currentArguments,
            List<ToolInvocation> history,
            Instant now
    ) {
        Instant cutoff = now.minus(burstWindow);
        List<String> burstSequence = new ArrayList<>();

        for (ToolInvocation inv : history) {
            if (!inv.timestamp().isBefore(cutoff)) {
                burstSequence.add(inv.toolName());
            }
        }
        burstSequence.add(currentTool);

        // If including the current invocation, the burst size exceeds threshold
        if (burstSequence.size() > maxCallsThreshold) {
            String reason = "Rapid tool burst anomaly detected: " + burstSequence.size()
                    + " tool invocations within " + burstWindow.toMillis() + "ms (threshold: "
                    + maxCallsThreshold + ")";

            return Optional.of(new AnomalyDetection(
                    name,
                    reason,
                    severity,
                    burstSequence
            ));
        }

        return Optional.empty();
    }

    public int getMaxCallsThreshold() {
        return maxCallsThreshold;
    }

    public Duration getBurstWindow() {
        return burstWindow;
    }
}
