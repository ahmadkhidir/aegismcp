package dev.aegismcp.gateway.anomaly;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dispatcher for security violation alerts generated during tool-chaining anomaly detection.
 * Integrates with SIEM, monitoring consoles, and incident response pipelines.
 * Anchors: FEAT-004, schema.md#SecurityViolation.
 */
@FunctionalInterface
public interface SecurityAlertDispatcher {

    void dispatchAlert(SecurityViolation violation);

    static SecurityAlertDispatcher noOp() {
        return violation -> {};
    }

    static SecurityAlertDispatcher logging() {
        Logger logger = LoggerFactory.getLogger(SecurityAlertDispatcher.class);
        return violation -> logger.warn(
                "SECURITY ALERT [{}]: Agent '{}' triggered {} ({}) - {}",
                violation.id(),
                violation.agentId(),
                violation.violationType(),
                violation.severity(),
                violation.details()
        );
    }
}
