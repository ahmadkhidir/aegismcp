package dev.aegismcp.gateway.inspector;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.codec.JsonRpcRequest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Per-request state shared by the three instrumentation points of one intercepted tool call: the
 * interceptor that brackets the chain, the policy evaluator that names the matched rule, and the
 * approval handler that suspends the call.
 *
 * <p>The state is keyed by the request id the edge already assigns through {@link SecurityContext},
 * so concurrent calls never share an observation, and it is removed when the chain reaches its
 * terminal verdict. A suspended call keeps its observation until the human decision releases the
 * future, which the approval manager always does at or before its TTL.
 *
 * <p>Anchors: FEAT-008, C-002.
 */
public final class TrafficObservations {

    private final ConcurrentHashMap<String, Observation> active = new ConcurrentHashMap<>();

    /** Starts observing one intercepted tool call. */
    public Observation begin(SecurityContext context, JsonRpcRequest request) {
        Observation observation = new Observation(context, request);
        active.put(observation.requestId(), observation);
        return observation;
    }

    /** Finds the observation for a request, or {@code null} when the call was not observed. */
    public Observation find(String requestId) {
        return requestId != null ? active.get(requestId) : null;
    }

    /** Releases the observation once its call is fully accounted for. */
    public void complete(String requestId) {
        if (requestId != null) {
            active.remove(requestId);
        }
    }

    /**
     * One intercepted {@code tools/call} between the moment the chain accepted it and the moment it
     * reached a terminal verdict.
     */
    public static final class Observation {
        private final String requestId;
        private final String agentId;
        private final String toolName;
        private final JsonNode arguments;
        private final Instant receivedAt;
        private final Set<String> matchedRuleIds = ConcurrentHashMap.newKeySet();
        private final AtomicBoolean published = new AtomicBoolean();

        private Observation(SecurityContext context, JsonRpcRequest request) {
            Objects.requireNonNull(context, "context must not be null");
            Objects.requireNonNull(request, "request must not be null");
            this.requestId = context.requestId();
            AgentIdentity identity = context.identity();
            this.agentId = identity != null && identity.agentId() != null
                    ? identity.agentId()
                    : "anonymous";
            this.toolName = request.toolName() != null ? request.toolName() : request.method();
            this.arguments = request.toolArguments();
            this.receivedAt = context.receivedAt() != null ? context.receivedAt() : Instant.now();
        }

        public String requestId() {
            return requestId;
        }

        public String agentId() {
            return agentId;
        }

        public String toolName() {
            return toolName;
        }

        public JsonNode arguments() {
            return arguments;
        }

        public Instant receivedAt() {
            return receivedAt;
        }

        public List<String> matchedRuleIds() {
            List<String> rules = new ArrayList<>(matchedRuleIds);
            rules.sort(String::compareTo);
            return List.copyOf(rules);
        }

        void recordRule(String ruleId) {
            if (ruleId != null && !ruleId.isBlank()) {
                matchedRuleIds.add(ruleId);
            }
        }

        /**
         * Claims the single event this call is owed. A call suspended for approval claims it when the
         * ticket is created, so the later allow or block the human decision produces does not emit a
         * second, contradictory traffic event.
         */
        boolean markPublished() {
            return published.compareAndSet(false, true);
        }

        boolean isPublished() {
            return published.get();
        }
    }
}
