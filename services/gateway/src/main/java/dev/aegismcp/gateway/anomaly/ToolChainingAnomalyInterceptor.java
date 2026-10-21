package dev.aegismcp.gateway.anomaly;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * High-performance Netty proxy pipeline interceptor enforcing multi-step tool-chaining anomaly defense.
 * Analyzes sequence context across sliding session windows, evaluates behavioral transition rules in sub-10ms,
 * trips circuit breaker on detected violations, and returns InterceptionVerdict.Block (-32001 Policy Violation).
 * Anchors: FEAT-004, C-001, NFR-001, NFR-003, NFR-027.
 */
public class ToolChainingAnomalyInterceptor implements ToolCallInterceptor {

    private final SessionSequenceTracker sessionTracker;
    private final List<AnomalyRule> rules;
    private final AnomalyCircuitBreaker circuitBreaker;
    private final SecurityAlertDispatcher alertDispatcher;
    private final Clock clock;

    public ToolChainingAnomalyInterceptor() {
        this(new SessionSequenceTracker(), AnomalyRule.defaultRules(), new AnomalyCircuitBreaker(), SecurityAlertDispatcher.logging(), Clock.systemUTC());
    }

    public ToolChainingAnomalyInterceptor(
            SessionSequenceTracker sessionTracker,
            List<AnomalyRule> rules,
            AnomalyCircuitBreaker circuitBreaker
    ) {
        this(sessionTracker, rules, circuitBreaker, SecurityAlertDispatcher.logging(), Clock.systemUTC());
    }

    public ToolChainingAnomalyInterceptor(
            SessionSequenceTracker sessionTracker,
            List<AnomalyRule> rules,
            AnomalyCircuitBreaker circuitBreaker,
            SecurityAlertDispatcher alertDispatcher,
            Clock clock
    ) {
        this.sessionTracker = Objects.requireNonNull(sessionTracker, "sessionTracker must not be null");
        this.rules = List.copyOf(Objects.requireNonNull(rules, "rules must not be null"));
        this.circuitBreaker = Objects.requireNonNull(circuitBreaker, "circuitBreaker must not be null");
        this.alertDispatcher = alertDispatcher != null ? alertDispatcher : SecurityAlertDispatcher.noOp();
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @Override
    public CompletableFuture<InterceptionVerdict> intercept(SecurityContext context, JsonRpcRequest request) {
        // Fast-path: non-tool calls (initialize, ping, tools/list, etc.) pass through directly
        if (request == null || !request.isToolCall()) {
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        }

        String agentId = extractAgentId(context);
        Instant now = clock.instant();

        // 1. Check Circuit Breaker / Agent Quarantine Status
        if (circuitBreaker.isQuarantined(agentId, now)) {
            String quarantineReason = circuitBreaker.getQuarantineReason(agentId, now);
            return CompletableFuture.completedFuture(
                    InterceptionVerdict.block(JsonRpcError.policyViolation("Agent session is quarantined: " + quarantineReason))
            );
        }

        String toolName = request.toolName();
        JsonNode arguments = request.toolArguments();

        // 2. Retrieve recent sliding-window session history
        List<ToolInvocation> history = sessionTracker.getRecentInvocations(agentId, now);

        // 3. Evaluate behavioral anomaly rules (NFR-003: sub-10ms evaluation)
        for (AnomalyRule rule : rules) {
            Optional<AnomalyDetection> detection = rule.evaluate(agentId, toolName, arguments, history, now);
            if (detection.isPresent()) {
                AnomalyDetection anomaly = detection.get();

                // Construct SecurityViolation record per schema.md#SecurityViolation
                SecurityViolation violation = SecurityViolation.toolChainingAnomaly(
                        agentId,
                        anomaly.reason(),
                        anomaly.severity()
                );

                // Trip circuit breaker placing agent in quarantine
                circuitBreaker.trip(agentId, anomaly.reason(), violation, now);

                // Dispatch security alert
                alertDispatcher.dispatchAlert(violation);

                // Fail-closed with -32001 Policy Violation (C-001 -> HTTP 403)
                return CompletableFuture.completedFuture(
                        InterceptionVerdict.block(JsonRpcError.policyViolation(anomaly.reason()))
                );
            }
        }

        // 4. Benign invocation: record event in session sliding-window and allow execution
        sessionTracker.recordInvocation(agentId, new ToolInvocation(toolName, arguments, now), now);
        return CompletableFuture.completedFuture(InterceptionVerdict.allow());
    }

    private String extractAgentId(SecurityContext context) {
        if (context != null && context.identity() != null && context.identity().agentId() != null) {
            return context.identity().agentId();
        }
        return "anonymous";
    }

    public SessionSequenceTracker getSessionTracker() {
        return sessionTracker;
    }

    public List<AnomalyRule> getRules() {
        return rules;
    }

    public AnomalyCircuitBreaker getCircuitBreaker() {
        return circuitBreaker;
    }

    public SecurityAlertDispatcher getAlertDispatcher() {
        return alertDispatcher;
    }
}
