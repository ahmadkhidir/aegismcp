package dev.aegismcp.gateway.inspector;

import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.policy.DeclarativePolicyInterceptor;
import dev.aegismcp.gateway.policy.PolicyEvaluationResult;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * Approval handler that reports a suspended tool call to the live inspector.
 *
 * <p>It delegates the ticket lifecycle to the approval manager unchanged and then closes the gap the
 * approval stage otherwise hides: a call that is neither allowed nor blocked yet. The observation is
 * claimed as {@code PENDING_APPROVAL} at the moment the ticket exists, so the inspector shows the
 * call as waiting for a human while the request future stays suspended, and the approval observer
 * publishes the later {@code approved}, {@code rejected}, or {@code expired} event that closes it.
 *
 * <p>Anchors: FEAT-006, FEAT-008, C-002.
 */
public final class InspectorApprovalHandler implements DeclarativePolicyInterceptor.ApprovalHandler {

    private static final Logger logger = LoggerFactory.getLogger(InspectorApprovalHandler.class);

    private final DeclarativePolicyInterceptor.ApprovalHandler delegate;
    private final TrafficObservations observations;
    private final InspectorEventStream eventStream;
    private final TrafficEventFactory events;

    public InspectorApprovalHandler(
            DeclarativePolicyInterceptor.ApprovalHandler delegate,
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
    public CompletableFuture<InterceptionVerdict> handleApproval(
            SecurityContext context,
            JsonRpcRequest request,
            PolicyEvaluationResult result
    ) {
        CompletableFuture<InterceptionVerdict> verdict = delegate.handleApproval(context, request, result);
        try {
            TrafficObservations.Observation observation =
                    context != null ? observations.find(context.requestId()) : null;
            if (observation != null && observation.markPublished()) {
                eventStream.publishTraffic(events.create(observation, TrafficDecision.PENDING_APPROVAL));
            }
        } catch (RuntimeException e) {
            // The ticket exists and the call is suspended; a failed broadcast must not cancel it.
            logger.warn("Failed to broadcast the pending approval traffic event", e);
        }
        return verdict;
    }
}
