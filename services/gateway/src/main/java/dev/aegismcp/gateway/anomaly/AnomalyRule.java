package dev.aegismcp.gateway.anomaly;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Inspection rule interface evaluating sliding-window tool sequences for behavioral anomalies.
 * Anchors: FEAT-004, NFR-003.
 */
@FunctionalInterface
public interface AnomalyRule {

    /**
     * Evaluates current tool call against previous session history.
     *
     * @param agentId          Identifier of the invoking agent workload
     * @param currentTool      Name of the incoming tool call
     * @param currentArguments Input JSON arguments passed to current tool call
     * @param history          Ordered list of previous tool invocations within sliding window
     * @param now              Current evaluation timestamp
     * @return AnomalyDetection if a violation pattern is matched, otherwise Optional.empty()
     */
    Optional<AnomalyDetection> evaluate(
            String agentId,
            String currentTool,
            JsonNode currentArguments,
            List<ToolInvocation> history,
            Instant now
    );

    default String name() {
        return getClass().getSimpleName();
    }

    /**
     * Returns the standard default suite of behavioral anomaly rules.
     * Includes data exfiltration chain detection, untrusted execution chains, and rapid bursts.
     */
    static List<AnomalyRule> defaultRules() {
        return List.of(
                ForbiddenTransitionRule.dataExfiltrationRule(),
                ForbiddenTransitionRule.untrustedExecutionRule(),
                ToolBurstRule.defaultBurstRule()
        );
    }
}
