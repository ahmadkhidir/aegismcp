package dev.aegismcp.gateway.killswitch;

import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sliding-window rate detector and automated circuit breaker protecting against infinite agent invocation loops.
 * Conforms to FEAT-010 specification (> 100 tool calls within 10 seconds).
 * Automatically trips and quarantines runaway agents in KillSwitchManager.
 * Anchors: FEAT-010, C-001.
 */
public class InvocationVelocityCircuitBreaker implements ToolCallInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(InvocationVelocityCircuitBreaker.class);

    public static final int DEFAULT_MAX_CALLS_THRESHOLD = 100;
    public static final Duration DEFAULT_WINDOW_DURATION = Duration.ofSeconds(10);

    private final KillSwitchManager killSwitchManager;
    private final int maxCallsThreshold;
    private final Duration windowDuration;
    private final GatewayMetrics metrics;

    // agentId -> sliding window timestamps
    private final ConcurrentHashMap<String, Deque<Instant>> invocationWindows = new ConcurrentHashMap<>();

    public InvocationVelocityCircuitBreaker(KillSwitchManager killSwitchManager) {
        this(killSwitchManager, DEFAULT_MAX_CALLS_THRESHOLD, DEFAULT_WINDOW_DURATION, null);
    }

    public InvocationVelocityCircuitBreaker(KillSwitchManager killSwitchManager, int maxCallsThreshold, Duration windowDuration) {
        this(killSwitchManager, maxCallsThreshold, windowDuration, null);
    }

    public InvocationVelocityCircuitBreaker(KillSwitchManager killSwitchManager, int maxCallsThreshold,
                                           Duration windowDuration, GatewayMetrics metrics) {
        if (maxCallsThreshold <= 0) {
            throw new IllegalArgumentException("maxCallsThreshold must be positive, got: " + maxCallsThreshold);
        }
        this.killSwitchManager = Objects.requireNonNull(killSwitchManager, "killSwitchManager must not be null");
        this.maxCallsThreshold = maxCallsThreshold;
        this.windowDuration = Objects.requireNonNull(windowDuration, "windowDuration must not be null");
        this.metrics = metrics;
    }

    public int getMaxCallsThreshold() {
        return maxCallsThreshold;
    }

    public Duration getWindowDuration() {
        return windowDuration;
    }

    /**
     * Records a tool call invocation and checks if velocity threshold is breached.
     *
     * @param agentId   agent workload identifier
     * @param timestamp invocation timestamp
     * @return true if circuit breaker tripped, false otherwise
     */
    public boolean recordInvocation(String agentId, Instant timestamp) {
        if (agentId == null) {
            return false;
        }

        Instant now = (timestamp != null) ? timestamp : Instant.now();
        Instant cutoff = now.minus(windowDuration);

        Deque<Instant> window = invocationWindows.computeIfAbsent(agentId, k -> new ArrayDeque<>());
        int currentCount;
        synchronized (window) {
            while (!window.isEmpty() && window.peekFirst().isBefore(cutoff)) {
                window.pollFirst();
            }
            window.addLast(now);
            currentCount = window.size();
        }

        if (currentCount > maxCallsThreshold) {
            String reason = "Invocation velocity breached: " + currentCount + " tool calls within "
                    + windowDuration.toSeconds() + "s (threshold: " + maxCallsThreshold + ")";
            logger.error("CIRCUIT BREAKER TRIPPED for agent '{}': {}", agentId, reason);

            killSwitchManager.quarantine(KillTargetType.AGENT, agentId, reason);
            if (metrics != null) {
                metrics.recordBlockedViolation();
            }
            return true;
        }

        return false;
    }

    /**
     * Returns the current sliding window invocation count for an agent.
     */
    public int getInvocationCount(String agentId, Instant now) {
        if (agentId == null) {
            return 0;
        }
        Deque<Instant> window = invocationWindows.get(agentId);
        if (window == null) {
            return 0;
        }
        Instant cutoff = (now != null ? now : Instant.now()).minus(windowDuration);
        synchronized (window) {
            while (!window.isEmpty() && window.peekFirst().isBefore(cutoff)) {
                window.pollFirst();
            }
            return window.size();
        }
    }

    /**
     * Resets invocation window tracking for an agent.
     */
    public void reset(String agentId) {
        if (agentId != null) {
            invocationWindows.remove(agentId);
        }
    }

    /**
     * Resets all sliding windows.
     */
    public void resetAll() {
        invocationWindows.clear();
    }

    @Override
    public CompletableFuture<InterceptionVerdict> intercept(SecurityContext context, JsonRpcRequest request) {
        // Only evaluate tool call invocations (e.g. tools/call)
        if (request == null || !request.isToolCall()) {
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        }

        String agentId = (context != null && context.identity() != null)
                ? context.identity().agentId()
                : "anonymous";

        // Check if agent is already quarantined
        if (killSwitchManager.isAgentQuarantined(agentId)) {
            if (metrics != null) {
                metrics.recordBlockedViolation();
            }
            return CompletableFuture.completedFuture(InterceptionVerdict.block(
                    new JsonRpcError(-32001, "Policy Violation: Agent '" + agentId + "' is quarantined by emergency kill-switch")
            ));
        }

        Instant timestamp = (context != null && context.receivedAt() != null) ? context.receivedAt() : Instant.now();
        boolean tripped = recordInvocation(agentId, timestamp);

        if (tripped) {
            return CompletableFuture.completedFuture(InterceptionVerdict.block(
                    new JsonRpcError(-32001, "Policy Violation: Invocation velocity circuit breaker tripped for agent '"
                            + agentId + "' (> " + maxCallsThreshold + " calls in " + windowDuration.toSeconds() + "s)")
            ));
        }

        return CompletableFuture.completedFuture(InterceptionVerdict.allow());
    }
}
