package dev.aegismcp.gateway.policy;

import java.util.Objects;

/**
 * Result of evaluating an incoming tool invocation against declarative security policies.
 * Anchors: FEAT-002, NFR-027.
 */
public record PolicyEvaluationResult(
        PolicyVerdict verdict,
        String reason,
        String policyId,
        String ruleId,
        boolean argumentViolation
) {
    public PolicyEvaluationResult {
        Objects.requireNonNull(verdict, "verdict must not be null");
    }

    public static PolicyEvaluationResult allow(String policyId, String ruleId) {
        return new PolicyEvaluationResult(PolicyVerdict.ALLOW, "Tool call authorized by policy", policyId, ruleId, false);
    }

    public static PolicyEvaluationResult deny(String reason, String policyId, String ruleId, boolean argumentViolation) {
        return new PolicyEvaluationResult(PolicyVerdict.DENY, reason, policyId, ruleId, argumentViolation);
    }

    public static PolicyEvaluationResult requireApproval(String reason, String policyId, String ruleId) {
        return new PolicyEvaluationResult(PolicyVerdict.REQUIRE_APPROVAL, reason, policyId, ruleId, false);
    }

    public boolean isAllowed() {
        return verdict == PolicyVerdict.ALLOW;
    }

    public boolean isDenied() {
        return verdict == PolicyVerdict.DENY;
    }

    public boolean isRequireApproval() {
        return verdict == PolicyVerdict.REQUIRE_APPROVAL;
    }
}
