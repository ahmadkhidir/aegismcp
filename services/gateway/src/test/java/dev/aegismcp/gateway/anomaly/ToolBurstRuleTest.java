package dev.aegismcp.gateway.anomaly;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ToolBurstRule detecting rapid-fire tool call bursts.
 * Anchors: FEAT-004, NFR-003.
 */
class ToolBurstRuleTest {

    @Test
    @DisplayName("FEAT-004: Detects rapid repeated tool burst exceeding threshold")
    void testBurstThresholdExceeded() {
        ToolBurstRule rule = new ToolBurstRule("BurstRule", 3, Duration.ofMillis(1000), SecurityViolation.SEVERITY_HIGH);
        Instant t0 = Instant.parse("2026-10-21T10:00:00Z");

        // 3 prior calls within 500ms
        List<ToolInvocation> history = List.of(
                ToolInvocation.of("ping", t0),
                ToolInvocation.of("ping", t0.plusMillis(100)),
                ToolInvocation.of("ping", t0.plusMillis(200))
        );

        // 4th call at 300ms exceeds maxCallsThreshold=3
        Optional<AnomalyDetection> detection = rule.evaluate("agent-loop", "ping", null, history, t0.plusMillis(300));
        assertTrue(detection.isPresent(), "Rapid burst exceeding threshold must be detected");
        assertEquals("BurstRule", detection.get().ruleName());
        assertTrue(detection.get().reason().contains("Rapid tool burst anomaly detected"));
    }

    @Test
    @DisplayName("FEAT-004: Invocations spread outside burst window are permitted")
    void testSpreadCallsPermitted() {
        ToolBurstRule rule = new ToolBurstRule("BurstRule", 3, Duration.ofMillis(1000), SecurityViolation.SEVERITY_HIGH);
        Instant t0 = Instant.parse("2026-10-21T10:00:00Z");

        // 3 prior calls spread over several seconds
        List<ToolInvocation> history = List.of(
                ToolInvocation.of("fetch", t0),
                ToolInvocation.of("fetch", t0.plusSeconds(2)),
                ToolInvocation.of("fetch", t0.plusSeconds(4))
        );

        // Call at 5s has only 1 prior event in the last 1000ms window
        Optional<AnomalyDetection> detection = rule.evaluate("agent-normal", "fetch", null, history, t0.plusSeconds(5));
        assertTrue(detection.isEmpty());
    }
}
