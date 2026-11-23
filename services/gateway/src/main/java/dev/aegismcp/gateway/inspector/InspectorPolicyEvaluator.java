package dev.aegismcp.gateway.inspector;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyEvaluationResult;
import dev.aegismcp.gateway.policy.PolicyEvaluator;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.validation.DynamicParameterValidator;

import java.util.Objects;

/**
 * Policy evaluator that names, for the live inspector, which rule decided a tool call.
 *
 * <p>The evaluation is delegated unchanged, so authorization behavior and latency stay exactly what
 * the policy stage does today; the only addition is recording the matched rule id on the observation
 * the traffic interceptor opened for the same request. The inspector's {@code matchedRuleIds} is
 * therefore the real rule that allowed, denied, or suspended the call rather than a re-evaluation
 * that might disagree with the decision actually enforced.
 *
 * <p>Anchors: FEAT-002, FEAT-008, C-002.
 */
public final class InspectorPolicyEvaluator extends PolicyEvaluator {

    private final TrafficObservations observations;

    public InspectorPolicyEvaluator(
            PolicyCache policyCache,
            DynamicParameterValidator parameterValidator,
            TrafficObservations observations
    ) {
        super(policyCache, parameterValidator);
        this.observations = Objects.requireNonNull(observations, "observations must not be null");
    }

    @Override
    public PolicyEvaluationResult evaluate(SecurityContext context, String toolName, JsonNode arguments) {
        PolicyEvaluationResult result = super.evaluate(context, toolName, arguments);
        if (context != null && result != null) {
            TrafficObservations.Observation observation = observations.find(context.requestId());
            if (observation != null) {
                observation.recordRule(result.ruleId());
            }
        }
        return result;
    }
}
