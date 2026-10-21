package dev.aegismcp.gateway.anomaly;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AnomalyCircuitBreaker quarantine lifecycle and manual/auto resets.
 * Anchors: FEAT-004, NFR-027.
 */
class AnomalyCircuitBreakerTest {

    @Test
    @DisplayName("FEAT-004: Tripping circuit breaker places agent in quarantine")
    void testTripAndCheckQuarantine() {
        AnomalyCircuitBreaker breaker = new AnomalyCircuitBreaker();
        assertFalse(breaker.isQuarantined("agent-1"));

        SecurityViolation violation = SecurityViolation.toolChainingAnomaly("agent-1", "Prohibited sequence", SecurityViolation.SEVERITY_CRITICAL);
        breaker.trip("agent-1", "Prohibited sequence", violation);

        assertTrue(breaker.isQuarantined("agent-1"));
        Optional<AnomalyCircuitBreaker.QuarantineRecord> record = breaker.getQuarantine("agent-1");
        assertTrue(record.isPresent());
        assertEquals("Prohibited sequence", record.get().reason());
        assertEquals(violation, record.get().violation());
    }

    @Test
    @DisplayName("FEAT-004: Manual reset restores agent operational state")
    void testManualReset() {
        AnomalyCircuitBreaker breaker = new AnomalyCircuitBreaker();
        SecurityViolation violation = SecurityViolation.toolChainingAnomaly("agent-1", "Prohibited sequence", SecurityViolation.SEVERITY_CRITICAL);
        breaker.trip("agent-1", "Prohibited sequence", violation);
        assertTrue(breaker.isQuarantined("agent-1"));

        breaker.reset("agent-1");
        assertFalse(breaker.isQuarantined("agent-1"));
        assertTrue(breaker.getQuarantine("agent-1").isEmpty());
    }

    @Test
    @DisplayName("FEAT-004: Auto-expiration of quarantine when time-bounded duration configured")
    void testQuarantineAutoExpiration() {
        AnomalyCircuitBreaker breaker = new AnomalyCircuitBreaker(Duration.ofMinutes(15));
        Instant t0 = Instant.parse("2026-10-21T10:00:00Z");

        SecurityViolation violation = SecurityViolation.toolChainingAnomaly("agent-timed", "Burst anomaly", SecurityViolation.SEVERITY_HIGH);
        breaker.trip("agent-timed", "Burst anomaly", violation, t0);

        // Within 15-minute window: quarantined
        assertTrue(breaker.isQuarantined("agent-timed", t0.plus(Duration.ofMinutes(10))));

        // After 15 minutes: automatically expired and unquarantined
        assertFalse(breaker.isQuarantined("agent-timed", t0.plus(Duration.ofMinutes(16))));
    }
}
