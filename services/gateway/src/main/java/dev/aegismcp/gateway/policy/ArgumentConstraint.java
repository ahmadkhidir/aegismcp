package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Declarative rule constraining tool arguments (e.g., path prefix, regex pattern, allowed domains, max rows).
 * Pre-compiles regular expressions and numeric thresholds for sub-millisecond AST evaluation.
 * Anchors: FEAT-002, NFR-001, NFR-024.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ArgumentConstraint {

    private final String argument;
    private final ConstraintOperator operator;
    private final Object rawValue;
    private final boolean optional;

    // Compiled lookup structures for sub-millisecond evaluation
    private final Pattern compiledPattern;
    private final Set<String> compiledSet;
    private final Double compiledNumber;

    @JsonCreator
    public ArgumentConstraint(
            @JsonProperty(value = "argument", required = true) String argument,
            @JsonProperty(value = "operator", required = true) Object operatorObj,
            @JsonProperty(value = "value", required = true) Object rawValue,
            @JsonProperty("optional") Boolean optional
    ) {
        this.argument = Objects.requireNonNull(argument, "argument must not be null").trim();
        Objects.requireNonNull(operatorObj, "operator must not be null");
        Objects.requireNonNull(rawValue, "value must not be null");

        this.operator = (operatorObj instanceof ConstraintOperator co)
                ? co
                : ConstraintOperator.fromString(String.valueOf(operatorObj));
        this.rawValue = rawValue;
        this.optional = Boolean.TRUE.equals(optional);

        // Precompile patterns or sets
        Pattern p = null;
        Set<String> s = null;
        Double n = null;

        if (this.operator == ConstraintOperator.MATCHES_REGEX) {
            try {
                p = Pattern.compile(String.valueOf(rawValue));
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException("Invalid regex pattern in constraint for argument '" + argument + "': " + rawValue, e);
            }
        } else if (this.operator == ConstraintOperator.IN || this.operator == ConstraintOperator.NOT_IN) {
            s = new HashSet<>();
            if (rawValue instanceof Iterable<?> iterable) {
                for (Object item : iterable) {
                    if (item != null) {
                        s.add(String.valueOf(item));
                    }
                }
            } else if (rawValue instanceof JsonNode jn && jn.isArray()) {
                for (JsonNode elem : jn) {
                    s.add(elem.asText());
                }
            } else {
                s.add(String.valueOf(rawValue));
            }
        } else if (this.operator == ConstraintOperator.LESS_THAN || this.operator == ConstraintOperator.LESS_THAN_OR_EQUAL
                || this.operator == ConstraintOperator.GREATER_THAN || this.operator == ConstraintOperator.GREATER_THAN_OR_EQUAL) {
            try {
                n = Double.parseDouble(String.valueOf(rawValue));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Numeric value required for constraint operator " + this.operator + ": " + rawValue);
            }
        }

        this.compiledPattern = p;
        this.compiledSet = s;
        this.compiledNumber = n;
    }

    public ArgumentConstraint(String argument, ConstraintOperator operator, Object value) {
        this(argument, operator, value, false);
    }

    public String argument() {
        return argument;
    }

    public ConstraintOperator operator() {
        return operator;
    }

    public Object value() {
        return rawValue;
    }

    public boolean isOptional() {
        return optional;
    }

    /**
     * Evaluates this constraint against tool argument node.
     * Returns true if compliant, false if violated (and appends reason to violationDetails if non-null).
     */
    public boolean evaluate(JsonNode arguments, StringBuilder violationDetails) {
        JsonNode targetNode = resolveArgumentNode(arguments, argument);

        if (targetNode == null || targetNode.isNull() || targetNode.isMissingNode()) {
            if (optional) {
                return true;
            }
            if (violationDetails != null) {
                violationDetails.append("Missing required argument: '").append(argument).append("'");
            }
            return false;
        }

        boolean passed = switch (operator) {
            case STARTS_WITH -> targetNode.isTextual() && targetNode.asText().startsWith(String.valueOf(rawValue));
            case ENDS_WITH -> targetNode.isTextual() && targetNode.asText().endsWith(String.valueOf(rawValue));
            case CONTAINS -> targetNode.isTextual() && targetNode.asText().contains(String.valueOf(rawValue));
            case EQUALS -> matchesEquality(targetNode, rawValue);
            case NOT_EQUALS -> !matchesEquality(targetNode, rawValue);
            case MATCHES_REGEX -> targetNode.isTextual() && compiledPattern.matcher(targetNode.asText()).matches();
            case IN -> matchesInSet(targetNode, compiledSet);
            case NOT_IN -> !matchesInSet(targetNode, compiledSet);
            case LESS_THAN -> targetNode.isNumber() && targetNode.asDouble() < compiledNumber;
            case LESS_THAN_OR_EQUAL -> targetNode.isNumber() && targetNode.asDouble() <= compiledNumber;
            case GREATER_THAN -> targetNode.isNumber() && targetNode.asDouble() > compiledNumber;
            case GREATER_THAN_OR_EQUAL -> targetNode.isNumber() && targetNode.asDouble() >= compiledNumber;
        };

        if (!passed && violationDetails != null) {
            violationDetails.append("Argument '").append(argument).append("' with value '")
                    .append(targetNode.asText()).append("' violated constraint: ")
                    .append(operator).append(" ").append(rawValue);
        }

        return passed;
    }

    private static JsonNode resolveArgumentNode(JsonNode root, String path) {
        if (root == null || path == null) {
            return null;
        }
        if (!path.contains(".")) {
            return root.get(path);
        }
        String[] parts = path.split("\\.");
        JsonNode current = root;
        for (String part : parts) {
            if (current == null || !current.has(part)) {
                return null;
            }
            current = current.get(part);
        }
        return current;
    }

    private static boolean matchesEquality(JsonNode node, Object expected) {
        if (node.isNumber() && expected instanceof Number n) {
            return Double.compare(node.asDouble(), n.doubleValue()) == 0;
        }
        if (node.isBoolean() && expected instanceof Boolean b) {
            return node.asBoolean() == b;
        }
        return Objects.equals(node.asText(), String.valueOf(expected));
    }

    private static boolean matchesInSet(JsonNode node, Set<String> set) {
        if (node == null || set == null) {
            return false;
        }
        if (node.isArray()) {
            for (JsonNode item : node) {
                if (!set.contains(item.asText())) {
                    return false;
                }
            }
            return true;
        }
        return set.contains(node.asText());
    }
}
