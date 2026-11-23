package dev.aegismcp.gateway.health;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the readiness state model behind {@code GET /ready}.
 * Anchors: C-023, FEAT-001.
 */
class GatewayReadinessTest {

    @Test
    void startingNodeRefusesTrafficWithoutFailingAnyDependency() {
        GatewayReadiness readiness = new GatewayReadiness();

        ReadinessSnapshot snapshot = readiness.snapshot();

        assertEquals(GatewayReadiness.STATUS_DOWN, snapshot.status());
        assertEquals(GatewayReadiness.REASON_STARTING, snapshot.reason());
        assertEquals(Map.of(
                "configuration", GatewayReadiness.STATUS_UP,
                "policy", GatewayReadiness.STATUS_UP,
                "auditLedger", GatewayReadiness.STATUS_UP
        ), statuses(snapshot));
        assertNotNull(Instant.parse(snapshot.timestamp()), "timestamp must be an ISO-8601 instant");
    }

    @Test
    void readyNodeReportsEveryDependencyUp() {
        GatewayReadiness readiness = new GatewayReadiness();
        readiness.markReady();

        ReadinessSnapshot snapshot = readiness.snapshot();

        assertEquals(GatewayReadiness.STATUS_UP, snapshot.status());
        assertNull(snapshot.reason());
        assertEquals(Map.of(
                "configuration", GatewayReadiness.STATUS_UP,
                "policy", GatewayReadiness.STATUS_UP,
                "auditLedger", GatewayReadiness.STATUS_UP
        ), statuses(snapshot));
    }

    @Test
    void eachDependencyFailureMapsToItsReasonAndMarksOnlyThatCheckDown() {
        assertFailureReason(GatewayReadiness.Dependency.CONFIGURATION,
                GatewayReadiness.REASON_CONFIGURATION_INVALID, "configuration");
        assertFailureReason(GatewayReadiness.Dependency.POLICY,
                GatewayReadiness.REASON_POLICY_INVALID, "policy");
        assertFailureReason(GatewayReadiness.Dependency.AUDIT_LEDGER,
                GatewayReadiness.REASON_LEDGER_UNWRITABLE, "auditLedger");
    }

    @Test
    void configurationFailureOutranksLaterFailures() {
        GatewayReadiness readiness = new GatewayReadiness();
        readiness.markReady();
        readiness.markDependencyUnhealthy(GatewayReadiness.Dependency.AUDIT_LEDGER);
        readiness.markDependencyUnhealthy(GatewayReadiness.Dependency.POLICY);
        readiness.markDependencyUnhealthy(GatewayReadiness.Dependency.CONFIGURATION);

        ReadinessSnapshot snapshot = readiness.snapshot();

        assertEquals(GatewayReadiness.STATUS_DOWN, snapshot.status());
        assertEquals(GatewayReadiness.REASON_CONFIGURATION_INVALID, snapshot.reason());
        assertEquals(GatewayReadiness.STATUS_DOWN, statuses(snapshot).get("configuration"));
        assertEquals(GatewayReadiness.STATUS_DOWN, statuses(snapshot).get("policy"));
        assertEquals(GatewayReadiness.STATUS_DOWN, statuses(snapshot).get("auditLedger"));
    }

    @Test
    void recoveredDependencyRestoresReadiness() {
        GatewayReadiness readiness = new GatewayReadiness();
        readiness.markReady();
        readiness.markDependencyUnhealthy(GatewayReadiness.Dependency.POLICY);

        readiness.markDependencyHealthy(GatewayReadiness.Dependency.POLICY);

        ReadinessSnapshot snapshot = readiness.snapshot();
        assertEquals(GatewayReadiness.STATUS_UP, snapshot.status());
        assertNull(snapshot.reason());
        assertTrue(readiness.isDependencyHealthy(GatewayReadiness.Dependency.POLICY));
    }

    @Test
    void shutdownOutranksDependencyFailures() {
        GatewayReadiness readiness = new GatewayReadiness();
        readiness.markReady();
        readiness.markDependencyUnhealthy(GatewayReadiness.Dependency.CONFIGURATION);

        readiness.markShuttingDown();

        ReadinessSnapshot snapshot = readiness.snapshot();
        assertEquals(GatewayReadiness.STATUS_DOWN, snapshot.status());
        assertEquals(GatewayReadiness.REASON_SHUTTING_DOWN, snapshot.reason());
    }

    @Test
    void restartingNodeReturnsToStarting() {
        GatewayReadiness readiness = new GatewayReadiness();
        readiness.markReady();
        readiness.markShuttingDown();

        readiness.markStarting();

        assertEquals(GatewayReadiness.REASON_STARTING, readiness.snapshot().reason());
        assertFalse(readiness.snapshot().status().equals(GatewayReadiness.STATUS_UP));
    }

    private static void assertFailureReason(
            GatewayReadiness.Dependency dependency,
            String expectedReason,
            String expectedCheckName
    ) {
        GatewayReadiness readiness = new GatewayReadiness();
        readiness.markReady();
        readiness.markDependencyUnhealthy(dependency);

        ReadinessSnapshot snapshot = readiness.snapshot();

        assertEquals(GatewayReadiness.STATUS_DOWN, snapshot.status());
        assertEquals(expectedReason, snapshot.reason());
        assertEquals(GatewayReadiness.STATUS_DOWN, statuses(snapshot).get(expectedCheckName));
        statuses(snapshot).forEach((check, status) -> {
            if (!check.equals(expectedCheckName)) {
                assertEquals(GatewayReadiness.STATUS_UP, status, check + " must stay UP");
            }
        });
    }

    private static Map<String, String> statuses(ReadinessSnapshot snapshot) {
        return snapshot.checks().entrySet().stream()
                .collect(java.util.stream.Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().status()));
    }
}
