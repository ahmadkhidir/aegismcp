package dev.aegismcp.gateway.health;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Tracks the gateway lifecycle and the health of the dependencies the readiness probe reports.
 *
 * <p>The node is ready only after startup has completed ({@link #markReady()}) and every dependency
 * check is healthy. A dependency that fails after startup keeps the node out of service until it is
 * healthy again, and shutdown begins with {@link #markShuttingDown()} so the probe answers {@code
 * 503} while the listener drains. The lifecycle and dependency states are updated from virtual
 * threads while the probe reads them, so both are thread-safe.
 *
 * <p>Anchors: C-023, FEAT-001, NFR-010.
 */
public final class GatewayReadiness {

    public static final String STATUS_UP = "UP";
    public static final String STATUS_DOWN = "DOWN";

    public static final String REASON_STARTING = "STARTING";
    public static final String REASON_CONFIGURATION_INVALID = "CONFIGURATION_INVALID";
    public static final String REASON_POLICY_INVALID = "POLICY_INVALID";
    public static final String REASON_LEDGER_UNWRITABLE = "LEDGER_UNWRITABLE";
    public static final String REASON_SHUTTING_DOWN = "SHUTTING_DOWN";

    /**
     * A dependency the readiness probe reports, with the check name in the payload and the reason
     * the node is out of service when the check fails.
     */
    public enum Dependency {
        CONFIGURATION("configuration", REASON_CONFIGURATION_INVALID),
        POLICY("policy", REASON_POLICY_INVALID),
        AUDIT_LEDGER("auditLedger", REASON_LEDGER_UNWRITABLE);

        private final String checkName;
        private final String failureReason;

        Dependency(String checkName, String failureReason) {
            this.checkName = checkName;
            this.failureReason = failureReason;
        }

        public String checkName() {
            return checkName;
        }

        public String failureReason() {
            return failureReason;
        }
    }

    /**
     * Lifecycle stage that decides the probe answer before dependency health is considered.
     */
    public enum Lifecycle {
        STARTING,
        READY,
        SHUTTING_DOWN
    }

    private final Map<Dependency, Boolean> dependencyHealth = new ConcurrentHashMap<>();
    private final AtomicReference<Lifecycle> lifecycle = new AtomicReference<>(Lifecycle.STARTING);

    public GatewayReadiness() {
        for (Dependency dependency : Dependency.values()) {
            dependencyHealth.put(dependency, Boolean.TRUE);
        }
    }

    public void markStarting() {
        lifecycle.set(Lifecycle.STARTING);
    }

    public void markReady() {
        lifecycle.set(Lifecycle.READY);
    }

    public void markShuttingDown() {
        lifecycle.set(Lifecycle.SHUTTING_DOWN);
    }

    public Lifecycle getLifecycle() {
        return lifecycle.get();
    }

    public void markDependencyUnhealthy(Dependency dependency) {
        dependencyHealth.put(Objects.requireNonNull(dependency, "dependency must not be null"), Boolean.FALSE);
    }

    public void markDependencyHealthy(Dependency dependency) {
        dependencyHealth.put(Objects.requireNonNull(dependency, "dependency must not be null"), Boolean.TRUE);
    }

    public boolean isDependencyHealthy(Dependency dependency) {
        return dependencyHealth.get(Objects.requireNonNull(dependency, "dependency must not be null")) != Boolean.FALSE;
    }

    /**
     * Builds the payload C-023 defines for the current lifecycle and dependency state.
     */
    public ReadinessSnapshot snapshot() {
        Lifecycle phase = lifecycle.get();

        String reason = null;
        if (phase == Lifecycle.STARTING) {
            reason = REASON_STARTING;
        } else if (phase == Lifecycle.SHUTTING_DOWN) {
            reason = REASON_SHUTTING_DOWN;
        } else {
            for (Dependency dependency : Dependency.values()) {
                if (!isDependencyHealthy(dependency)) {
                    reason = dependency.failureReason();
                    break;
                }
            }
        }

        Map<String, ReadinessSnapshot.Check> checks = new LinkedHashMap<>();
        for (Dependency dependency : Dependency.values()) {
            checks.put(dependency.checkName(), new ReadinessSnapshot.Check(
                    isDependencyHealthy(dependency) ? STATUS_UP : STATUS_DOWN));
        }

        return new ReadinessSnapshot(
                reason == null ? STATUS_UP : STATUS_DOWN,
                reason,
                checks,
                Instant.now().toString()
        );
    }
}
