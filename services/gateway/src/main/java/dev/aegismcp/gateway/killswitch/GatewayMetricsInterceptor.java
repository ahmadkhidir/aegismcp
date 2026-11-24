package dev.aegismcp.gateway.killswitch;

import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;

/**
 * Feeds the fleet counters C-009 and C-010 report from the terminal outcome of each intercepted tool
 * call: the call is counted when it enters the chain, and a stage that refuses it records one
 * blocked violation.
 *
 * <p>The observer wraps the whole interceptor chain from the outside, so a call blocked by the kill
 * switch, the velocity breaker, validation, policy, or the anomaly rules is counted exactly as an
 * allowed one is, and no stage records the same call a second time. The verdict is passed through
 * untouched: this class adds counting, not a decision.
 *
 * <p>A cancelled future is not a violation — the client went away before a decision was reached —
 * and an exception thrown by a stage is a fail-closed refusal, which is the blocked outcome the
 * console renders for the same call.
 *
 * <p>Anchors: FEAT-008, FEAT-010, C-009, C-010, C-020.
 */
public final class GatewayMetricsInterceptor implements ToolCallInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(GatewayMetricsInterceptor.class);

    private final ToolCallInterceptor delegate;
    private final GatewayMetrics metrics;

    public GatewayMetricsInterceptor(ToolCallInterceptor delegate, GatewayMetrics metrics) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.metrics = Objects.requireNonNull(metrics, "metrics must not be null");
    }

    @Override
    public CompletableFuture<InterceptionVerdict> intercept(SecurityContext context, JsonRpcRequest request) {
        if (request == null || !request.isToolCall()) {
            return delegate.intercept(context, request);
        }

        metrics.recordToolCall();

        CompletableFuture<InterceptionVerdict> verdict;
        try {
            verdict = delegate.intercept(context, request);
        } catch (RuntimeException e) {
            // A stage that threw refused the call before any upstream execution; the proxy answers
            // the fail-closed row, so it is a blocked violation like any other refusal.
            metrics.recordBlockedViolation();
            throw e;
        }

        verdict.whenComplete((result, error) -> recordOutcome(result, error));
        return verdict;
    }

    private void recordOutcome(InterceptionVerdict verdict, Throwable error) {
        try {
            if (error instanceof CancellationException) {
                return;
            }
            if (error != null || verdict instanceof InterceptionVerdict.Block) {
                metrics.recordBlockedViolation();
            }
        } catch (RuntimeException e) {
            // Counting must never change the verdict the caller receives.
            logger.error("Failed to record the gateway metrics outcome", e);
        }
    }
}
