package dev.aegismcp.gateway.anomaly;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ForbiddenTransitionRule detecting dangerous multi-step tool execution sequences.
 * Anchors: FEAT-004.
 */
class ForbiddenTransitionRuleTest {

    @Test
    @DisplayName("FEAT-004 AC 1: Detects and blocks private data read followed by network egress exfiltration")
    void testDataExfiltrationDetection() {
        ForbiddenTransitionRule rule = ForbiddenTransitionRule.dataExfiltrationRule(Duration.ofSeconds(60));
        Instant t0 = Instant.parse("2026-10-21T10:00:00Z");

        List<ToolInvocation> history = List.of(
                ToolInvocation.of("read_file", t0)
        );

        // Attempting external egress call within window
        Optional<AnomalyDetection> detection = rule.evaluate("agent-sec", "curl:exec", null, history, t0.plusSeconds(10));
        assertTrue(detection.isPresent(), "Should detect read_file followed by curl:exec");
        AnomalyDetection anomaly = detection.get();
        assertEquals("DataExfiltrationTransitionRule", anomaly.ruleName());
        assertEquals(SecurityViolation.SEVERITY_CRITICAL, anomaly.severity());
        assertEquals(List.of("read_file", "curl:exec"), anomaly.triggeringSequence());
    }

    @Test
    @DisplayName("FEAT-004 AC 2: Benign sequence conforming to operational patterns is permitted")
    void testBenignSequenceAllowed() {
        ForbiddenTransitionRule rule = ForbiddenTransitionRule.dataExfiltrationRule(Duration.ofSeconds(60));
        Instant t0 = Instant.parse("2026-10-21T10:00:00Z");

        List<ToolInvocation> history = List.of(
                ToolInvocation.of("read_file", t0)
        );

        // Subsequent benign internal operations
        assertTrue(rule.evaluate("agent-dev", "write_file", null, history, t0.plusSeconds(5)).isEmpty());
        assertTrue(rule.evaluate("agent-dev", "format_json", null, history, t0.plusSeconds(10)).isEmpty());
        assertTrue(rule.evaluate("agent-dev", "local_compute", null, history, t0.plusSeconds(15)).isEmpty());
    }

    @Test
    @DisplayName("FEAT-004: Invocations outside transition window do not trigger violation")
    void testTransitionWindowExpiry() {
        ForbiddenTransitionRule rule = ForbiddenTransitionRule.dataExfiltrationRule(Duration.ofSeconds(60));
        Instant t0 = Instant.parse("2026-10-21T10:00:00Z");

        List<ToolInvocation> history = List.of(
                ToolInvocation.of("database_query", t0)
        );

        // Egress call 70 seconds later (beyond 60s transition window)
        Optional<AnomalyDetection> detection = rule.evaluate("agent-dev", "external_http", null, history, t0.plusSeconds(70));
        assertTrue(detection.isEmpty(), "Should not trigger after transition window has elapsed");
    }

    @Test
    @DisplayName("FEAT-004: Detects untrusted download followed by command execution")
    void testUntrustedExecutionRule() {
        ForbiddenTransitionRule rule = ForbiddenTransitionRule.untrustedExecutionRule(Duration.ofSeconds(60));
        Instant t0 = Instant.parse("2026-10-21T10:00:00Z");

        List<ToolInvocation> history = List.of(
                ToolInvocation.of("download_file", t0)
        );

        Optional<AnomalyDetection> detection = rule.evaluate("agent-ci", "bash", null, history, t0.plusSeconds(15));
        assertTrue(detection.isPresent());
        assertEquals("UntrustedCodeExecutionRule", detection.get().ruleName());
        assertEquals(List.of("download_file", "bash"), detection.get().triggeringSequence());
    }

    @Test
    @DisplayName("FEAT-004: Custom transition rule with wildcard patterns")
    void testWildcardPatternMatching() {
        ForbiddenTransitionRule rule = new ForbiddenTransitionRule(
                "CustomVaultExfilRule",
                Set.of("vault:*", "secret_*"),
                Set.of("http_*", "webhook_*"),
                Duration.ofSeconds(30),
                SecurityViolation.SEVERITY_HIGH,
                "Vault secret egress pattern"
        );
        Instant t0 = Instant.parse("2026-10-21T10:00:00Z");

        List<ToolInvocation> history = List.of(
                ToolInvocation.of("vault:read_credential", t0)
        );

        Optional<AnomalyDetection> detection = rule.evaluate("agent-1", "webhook_post", null, history, t0.plusSeconds(5));
        assertTrue(detection.isPresent());
        assertEquals("CustomVaultExfilRule", detection.get().ruleName());
    }
}
