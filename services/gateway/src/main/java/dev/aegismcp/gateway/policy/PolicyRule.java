package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Single declarative tool policy rule within a SecurityPolicy AST.
 * Anchors: FEAT-002, NFR-027.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PolicyRule {

    private final String id;
    private final String tool;
    private final PolicyVerdict action;
    private final boolean requireApproval;
    private final List<ArgumentConstraint> constraints;
    private final Double actionThreshold;
    private final String description;

    // Compiled wildcard pattern for tool matching
    private final Pattern compiledToolPattern;

    @JsonCreator
    public PolicyRule(
            @JsonProperty("id") String id,
            @JsonProperty(value = "tool", required = true) String tool,
            @JsonProperty("action") Object actionObj,
            @JsonProperty("requireApproval") Boolean requireApproval,
            @JsonProperty("require_approval") Boolean requireApprovalSnake,
            @JsonProperty("constraints") List<ArgumentConstraint> constraints,
            @JsonProperty("actionThreshold") Double actionThreshold,
            @JsonProperty("action_threshold") Double actionThresholdSnake,
            @JsonProperty("description") String description
    ) {
        this.id = id != null && !id.isBlank() ? id : "rule-" + UUID.randomUUID().toString().substring(0, 8);
        this.tool = Objects.requireNonNull(tool, "tool pattern must not be null").trim();

        boolean approvalRequired = Boolean.TRUE.equals(requireApproval) || Boolean.TRUE.equals(requireApprovalSnake);

        PolicyVerdict resolvedAction = PolicyVerdict.ALLOW;
        if (actionObj != null) {
            String actStr = String.valueOf(actionObj).trim().toUpperCase(Locale.ROOT);
            resolvedAction = switch (actStr) {
                case "ALLOW", "PERMIT" -> PolicyVerdict.ALLOW;
                case "DENY", "BLOCK", "REJECT" -> PolicyVerdict.DENY;
                case "REQUIRE_APPROVAL", "REQUIREAPPROVAL", "APPROVAL", "HITL" -> PolicyVerdict.REQUIRE_APPROVAL;
                default -> throw new IllegalArgumentException("Unknown policy rule action: " + actionObj);
            };
        } else if (approvalRequired) {
            resolvedAction = PolicyVerdict.REQUIRE_APPROVAL;
        }

        this.action = approvalRequired ? PolicyVerdict.REQUIRE_APPROVAL : resolvedAction;
        this.requireApproval = approvalRequired || this.action == PolicyVerdict.REQUIRE_APPROVAL;
        this.constraints = constraints != null ? List.copyOf(constraints) : Collections.emptyList();
        this.actionThreshold = actionThreshold != null ? actionThreshold : actionThresholdSnake;
        this.description = description;

        // Compile tool pattern if it contains wildcards
        if (this.tool.contains("*") || this.tool.contains("?")) {
            String regex = "^" + Pattern.quote(this.tool)
                    .replace("*", "\\E.*\\Q")
                    .replace("?", "\\E.\\Q") + "$";
            this.compiledToolPattern = Pattern.compile(regex);
        } else {
            this.compiledToolPattern = null;
        }
    }

    public PolicyRule(String tool, PolicyVerdict action, List<ArgumentConstraint> constraints) {
        this(null, tool, action, false, false, constraints, null, null, null);
    }

    public String id() {
        return id;
    }

    public String tool() {
        return tool;
    }

    public PolicyVerdict action() {
        return action;
    }

    public boolean isRequireApproval() {
        return requireApproval;
    }

    public List<ArgumentConstraint> constraints() {
        return constraints;
    }

    public Double actionThreshold() {
        return actionThreshold;
    }

    public String description() {
        return description;
    }

    /**
     * Checks if the given tool name matches this rule's target tool or glob pattern.
     */
    public boolean matchesTool(String targetTool) {
        if (targetTool == null) {
            return false;
        }
        if ("*".equals(tool)) {
            return true;
        }
        if (compiledToolPattern != null) {
            return compiledToolPattern.matcher(targetTool).matches();
        }
        return tool.equalsIgnoreCase(targetTool);
    }
}
