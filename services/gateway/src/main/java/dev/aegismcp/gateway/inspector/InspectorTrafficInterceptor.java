package dev.aegismcp.gateway.inspector;

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
 * Observes the terminal verdict of every intercepted {@code tools/call} and broadcasts it as one
 * {@code traffic} event (C-002).
 *
 * <p>The observer wraps the whole interceptor chain instead of sitting inside it, so a call blocked
 * by the kill switch, the velocity breaker, validation, policy, or the anomaly rules is reported with
 * the same shape as an allowed one — the inspector is meant to show refusals, which is exactly what a
 * stage inside the chain would never see. The verdict itself is passed through untouched: this class
 * adds observation, not a decision.
 *
 * <p>A call suspended for human approval has already been reported as {@code PENDING_APPROVAL} at the
 * moment its ticket was created; when the human decision later releases the future, the observation
 * is already claimed and no second event is emitted for the same call.
 *
 * <p>Anchors: FEAT-008, NFR-005, C-002.
 */
public final class InspectorTrafficInterceptor implements ToolCallInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(InspectorTrafficInterceptor.class);

    private final ToolCallInterceptor delegate;
    private final TrafficObservations observations;
    private final InspectorEventStream eventStream;
    private final TrafficEventFactory events;

    public InspectorTrafficInterceptor(
            ToolCallInterceptor delegate,
            TrafficObservations observations,
            InspectorEventStream eventStream,
            TrafficEventFactory events
    ) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.observations = Objects.requireNonNull(observations, "observations must not be null");
        this.eventStream = Objects.requireNonNull(eventStream, "eventStream must not be null");
        this.events = Objects.requireNonNull(events, "events must not be null");
    }

    @Override
    public CompletableFuture<InterceptionVerdict> intercept(SecurityContext context, JsonRpcRequest request) {
        if (request == null || !request.isToolCall() || context == null) {
            return delegate.intercept(context, request);
        }

        TrafficObservations.Observation observation = observations.begin(context, request);
        CompletableFuture<InterceptionVerdict> verdict;
        try {
            verdict = delegate.intercept(context, request);
        } catch (RuntimeException e) {
            observations.complete(observation.requestId());
            throw e;
        }
        verdict.whenComplete((result, error) -> recordOutcome(observation, result, error));
        return verdict;
    }

    private void recordOutcome(
            TrafficObservations.Observation observation,
            InterceptionVerdict verdict,
            Throwable error
    ) {
        String requestId = observation.requestId();
        try {
            if (observation.isPublished()) {
                return;
            }
            if (error instanceof CancellationException) {
                // The client went away before a decision was reached; there is no decision to show.
                return;
            }
            // A stage that threw refused the call before any upstream execution, which is the same
            // fail-closed outcome the console renders for a block.
            TrafficDecision decision = error != null || verdict instanceof InterceptionVerdict.Block
                    ? TrafficDecision.BLOCKED
                    : TrafficDecision.ALLOWED;
            eventStream.publishTraffic(events.create(observation, decision));
        } catch (RuntimeException e) {
            logger.error("Failed to broadcast the live traffic event for request {}", requestId, e);
        } finally {
            observations.complete(requestId);
        }
    }
}
