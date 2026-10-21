package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Pre-compiled Abstract Syntax Tree (AST) representing a parsed security policy.
 * Evaluates rules with sub-millisecond in-memory lookups.
 * Anchors: FEAT-002, NFR-001, NFR-027.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PolicyAst {

    private final String id;
    private final String name;
    private final String version;
    private final List<String> targetAgents;
    private final PolicyVerdict defaultAction;
    private final List<PolicyRule> rules;
    private final Double actionThreshold;

    @JsonCreator
    public PolicyAst(
            @JsonProperty("id") String id,
            @JsonProperty("name") String name,
            @JsonProperty("version") String version,
            @JsonProperty("targetAgents") List<String> targetAgents,
            @JsonProperty("target_agents") List<String> targetAgentsSnake,
            @JsonProperty("defaultAction") Object defaultActionObj,
            @JsonProperty("default_action") Object defaultActionSnake,
            @JsonProperty("rules") List<PolicyRule> rules,
            @JsonProperty("actionThreshold") Double actionThreshold,
            @JsonProperty("action_threshold") Double actionThresholdSnake
    ) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("Policy 'id' is required");
        }
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Policy 'name' is required");
        }
        if (version == null || version.isBlank()) {
            throw new IllegalArgumentException("Policy 'version' is required");
        }
        this.id = id.trim();
        this.name = name.trim();
        this.version = version.trim();

        List<String> agents = targetAgents != null ? targetAgents : targetAgentsSnake;
        this.targetAgents = agents != null && !agents.isEmpty() ? List.copyOf(agents) : List.of("*");

        Object defAction = defaultActionObj != null ? defaultActionObj : defaultActionSnake;
        if (defAction != null) {
            String actStr = String.valueOf(defAction).trim().toUpperCase(Locale.ROOT);
            this.defaultAction = switch (actStr) {
                case "ALLOW", "PERMIT" -> PolicyVerdict.ALLOW;
                case "DENY", "BLOCK", "REJECT" -> PolicyVerdict.DENY;
                case "REQUIRE_APPROVAL", "REQUIREAPPROVAL" -> PolicyVerdict.REQUIRE_APPROVAL;
                default -> PolicyVerdict.DENY;
            };
        } else {
            // Fail-closed default stance per NFR-027
            this.defaultAction = PolicyVerdict.DENY;
        }

        this.rules = rules != null ? List.copyOf(rules) : Collections.emptyList();
        this.actionThreshold = actionThreshold != null ? actionThreshold : actionThresholdSnake;
    }

    public String id() {
        return id;
    }

    public String name() {
        return name;
    }

    public String version() {
        return version;
    }

    public List<String> targetAgents() {
        return targetAgents;
    }

    public PolicyVerdict defaultAction() {
        return defaultAction;
    }

    public List<PolicyRule> rules() {
        return rules;
    }

    public Double actionThreshold() {
        return actionThreshold;
    }

    /**
     * Checks if this policy applies to the given agent identity or SPIFFE ID.
     */
    public boolean matchesAgent(String agentId, String spiffeId) {
        for (String target : targetAgents) {
            if ("*".equals(target)) {
                return true;
            }
            if (agentId != null && matchesPattern(target, agentId)) {
                return true;
            }
            if (spiffeId != null && matchesPattern(target, spiffeId)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesPattern(String pattern, String value) {
        if (pattern.equalsIgnoreCase(value)) {
            return true;
        }
        if (pattern.contains("*") || pattern.contains("?")) {
            String regex = "^" + Pattern.quote(pattern)
                    .replace("*", "\\E.*\\Q")
                    .replace("?", "\\E.\\Q") + "$";
            return Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(value).matches();
        }
        return false;
    }

    /**
     * Finds the first policy rule matching the target tool name.
     */
    public PolicyRule findMatchingRule(String toolName) {
        if (toolName == null) {
            return null;
        }
        for (PolicyRule rule : rules) {
            if (rule.matchesTool(toolName)) {
                return rule;
            }
        }
        return null;
    }
}
