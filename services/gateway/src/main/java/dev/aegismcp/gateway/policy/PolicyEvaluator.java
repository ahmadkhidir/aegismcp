package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Fail-closed least-privilege tool execution evaluator.
 * Evaluates tool name and argument constraints against active in-memory policy ASTs.
 * Returns deterministic {@link PolicyEvaluationResult} with sub-millisecond evaluation latency.
 * Anchors: FEAT-002, NFR-001, NFR-027.
 */
public class PolicyEvaluator {

    private static final Logger logger = LoggerFactory.getLogger(PolicyEvaluator.class);

    private final PolicyCache policyCache;

    public PolicyEvaluator(PolicyCache policyCache) {
        this.policyCache = Objects.requireNonNull(policyCache, "policyCache must not be null");
    }

    /**
     * Evaluates an intercepted tool call within a {@link SecurityContext}.
     */
    public PolicyEvaluationResult evaluate(SecurityContext context, String toolName, JsonNode arguments) {
        AgentIdentity identity = context != null ? context.identity() : null;
        return evaluate(identity, toolName, arguments);
    }

    /**
     * Evaluates a tool call for a given {@link AgentIdentity}.
     * Enforces fail-closed posture: unmapped identities or undeclared tools are denied.
     */
    public PolicyEvaluationResult evaluate(AgentIdentity identity, String toolName, JsonNode arguments) {
        String agentId = identity != null ? identity.agentId() : "anonymous";
        String spiffeId = identity != null ? identity.spiffeId() : null;

        // 1. Resolve active policy AST from cache
        PolicyAst policy = policyCache.getPolicyForAgent(agentId, spiffeId);
        if (policy == null) {
            String denial = "Fail-closed: No active security policy assigned for agent '" + agentId + "'";
            logger.warn("Security policy denial: {}", denial);
            return PolicyEvaluationResult.deny(denial, null, null, false);
        }

        // 2. Validate tool presence against policy rules
        if (toolName == null || toolName.isBlank()) {
            return PolicyEvaluationResult.deny("Missing tool name in tools/call request", policy.id(), null, false);
        }

        PolicyRule matchedRule = policy.findMatchingRule(toolName);
        if (matchedRule == null) {
            String denial = "Fail-closed: Tool '" + toolName + "' is not permitted in policy '" + policy.id() + "'";
            logger.warn("Unauthorized tool invocation attempt: agent='{}', tool='{}', policy='{}'", agentId, toolName, policy.id());
            return PolicyEvaluationResult.deny(denial, policy.id(), null, false);
        }

        // 3. Check explicit rule-level DENY
        if (matchedRule.action() == PolicyVerdict.DENY) {
            String denial = "Tool execution '" + toolName + "' denied by rule '" + matchedRule.id() + "' in policy '" + policy.id() + "'";
            logger.info("Tool invocation denied by rule: {}", denial);
            return PolicyEvaluationResult.deny(denial, policy.id(), matchedRule.id(), false);
        }

        // 4. Evaluate argument constraints
        if (!matchedRule.constraints().isEmpty()) {
            StringBuilder violationDetails = new StringBuilder();
            for (ArgumentConstraint constraint : matchedRule.constraints()) {
                if (!constraint.evaluate(arguments, violationDetails)) {
                    String reason = "Argument constraint violation: " + violationDetails;
                    logger.warn("Tool call argument constraint violated: agent='{}', tool='{}', details='{}'",
                            agentId, toolName, reason);
                    return PolicyEvaluationResult.deny(reason, policy.id(), matchedRule.id(), true);
                }
            }
        }

        // 5. Check HITL approval requirement
        if (matchedRule.action() == PolicyVerdict.REQUIRE_APPROVAL || matchedRule.isRequireApproval()) {
            String msg = "Tool execution '" + toolName + "' requires human-in-the-loop approval per policy rule '" + matchedRule.id() + "'";
            logger.info("Tool invocation suspended for approval: {}", msg);
            return PolicyEvaluationResult.requireApproval(msg, policy.id(), matchedRule.id());
        }

        // 6. Whitelist tool call verified and allowed
        logger.debug("Tool invocation allowed: agent='{}', tool='{}', policy='{}', rule='{}'",
                agentId, toolName, policy.id(), matchedRule.id());
        return PolicyEvaluationResult.allow(policy.id(), matchedRule.id());
    }

    public PolicyCache getPolicyCache() {
        return policyCache;
    }
}
