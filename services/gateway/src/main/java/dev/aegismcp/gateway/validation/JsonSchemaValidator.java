package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Strict JSON schema validator enforcing MCP tool parameter contracts.
 * Validates data types, required properties, enums, constraints, and prohibited additional properties.
 * Anchors: FEAT-012, NFR-024.
 */
public class JsonSchemaValidator {

    public List<ValidationViolation> validate(JsonNode schema, JsonNode arguments) {
        List<ValidationViolation> violations = new ArrayList<>();
        if (schema == null || schema.isEmpty() || schema.isNull()) {
            // Missing/empty schema fallback per FEAT-012 edge cases: pass generic schema check
            return violations;
        }

        JsonNode schemaTypeNode = schema.get("type");
        String expectedRootType = schemaTypeNode != null ? schemaTypeNode.asText() : "object";

        if ("object".equalsIgnoreCase(expectedRootType)) {
            if (arguments != null && !arguments.isObject() && !arguments.isNull()) {
                violations.add(ValidationViolation.schemaViolation(
                        "arguments",
                        "Root parameters type mismatch: expected object, got " + getNodeType(arguments),
                        arguments.asText()
                ));
                return violations;
            }
        }

        // Validate required properties
        JsonNode requiredNode = schema.get("required");
        if (requiredNode != null && requiredNode.isArray()) {
            for (JsonNode req : requiredNode) {
                String reqProp = req.asText();
                if (arguments == null || !arguments.has(reqProp) || arguments.get(reqProp).isNull()) {
                    violations.add(ValidationViolation.schemaViolation(
                            reqProp,
                            "Missing required property: '" + reqProp + "'",
                            null
                    ));
                }
            }
        }

        if (arguments == null || !arguments.isObject()) {
            return violations;
        }

        JsonNode propertiesNode = schema.get("properties");
        boolean additionalPropertiesBlocked = schema.has("additionalProperties") && !schema.get("additionalProperties").asBoolean();

        Iterator<Map.Entry<String, JsonNode>> fields = arguments.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            String propName = field.getKey();
            JsonNode propValue = field.getValue();

            JsonNode propSchema = (propertiesNode != null) ? propertiesNode.get(propName) : null;
            if (propSchema != null) {
                validateProperty(propName, propValue, propSchema, violations);
            } else if (additionalPropertiesBlocked) {
                violations.add(ValidationViolation.schemaViolation(
                        propName,
                        "Unexpected property '" + propName + "' not allowed by tool schema",
                        propValue.asText()
                ));
            }
        }

        return violations;
    }

    private void validateProperty(String propName, JsonNode value, JsonNode propSchema, List<ValidationViolation> violations) {
        if (value == null || value.isNull()) {
            return;
        }

        JsonNode typeNode = propSchema.get("type");
        if (typeNode != null) {
            String expectedType = typeNode.asText().toLowerCase();
            boolean typeValid = checkType(expectedType, value);
            if (!typeValid) {
                violations.add(ValidationViolation.schemaViolation(
                        propName,
                        "Parameter '" + propName + "' type mismatch: expected " + expectedType + ", got " + getNodeType(value),
                        value.asText()
                ));
                return;
            }
        }

        // Enum check
        JsonNode enumNode = propSchema.get("enum");
        if (enumNode != null && enumNode.isArray()) {
            boolean matched = false;
            for (JsonNode enumVal : enumNode) {
                if (enumVal.asText().equals(value.asText())) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                violations.add(ValidationViolation.schemaViolation(
                        propName,
                        "Parameter '" + propName + "' value is not an allowed enum constant",
                        value.asText()
                ));
            }
        }

        // Numeric bounds check
        if (value.isNumber()) {
            double numVal = value.asDouble();
            if (propSchema.has("minimum")) {
                double min = propSchema.get("minimum").asDouble();
                if (numVal < min) {
                    violations.add(ValidationViolation.schemaViolation(
                            propName,
                            "Parameter '" + propName + "' value " + numVal + " is below minimum " + min,
                            value.asText()
                    ));
                }
            }
            if (propSchema.has("maximum")) {
                double max = propSchema.get("maximum").asDouble();
                if (numVal > max) {
                    violations.add(ValidationViolation.schemaViolation(
                            propName,
                            "Parameter '" + propName + "' value " + numVal + " exceeds maximum " + max,
                            value.asText()
                    ));
                }
            }
        }

        // String length / pattern check
        if (value.isTextual()) {
            String text = value.asText();
            if (propSchema.has("minLength") && text.length() < propSchema.get("minLength").asInt()) {
                violations.add(ValidationViolation.schemaViolation(
                        propName,
                        "Parameter '" + propName + "' length is below minLength",
                        text
                ));
            }
            if (propSchema.has("maxLength") && text.length() > propSchema.get("maxLength").asInt()) {
                violations.add(ValidationViolation.schemaViolation(
                        propName,
                        "Parameter '" + propName + "' length exceeds maxLength",
                        text
                ));
            }
            if (propSchema.has("pattern")) {
                String regex = propSchema.get("pattern").asText();
                try {
                    if (!Pattern.compile(regex).matcher(text).matches()) {
                        violations.add(ValidationViolation.schemaViolation(
                                propName,
                                "Parameter '" + propName + "' does not match required pattern: " + regex,
                                text
                        ));
                    }
                } catch (Exception ignored) {
                }
            }
        }

        // Array items check
        if (value.isArray() && propSchema.has("items")) {
            JsonNode itemsSchema = propSchema.get("items");
            int idx = 0;
            for (JsonNode item : value) {
                validateProperty(propName + "[" + idx + "]", item, itemsSchema, violations);
                idx++;
            }
        }

        // Nested object check
        if (value.isObject() && propSchema.has("properties")) {
            validate(propSchema, value).forEach(violations::add);
        }
    }

    private boolean checkType(String expectedType, JsonNode value) {
        return switch (expectedType) {
            case "string" -> value.isTextual();
            case "integer" -> value.isIntegralNumber();
            case "number" -> value.isNumber();
            case "boolean" -> value.isBoolean();
            case "array" -> value.isArray();
            case "object" -> value.isObject();
            default -> true;
        };
    }

    private String getNodeType(JsonNode node) {
        if (node.isTextual()) return "string";
        if (node.isIntegralNumber()) return "integer";
        if (node.isFloatingPointNumber()) return "number";
        if (node.isBoolean()) return "boolean";
        if (node.isArray()) return "array";
        if (node.isObject()) return "object";
        if (node.isNull()) return "null";
        return "unknown";
    }
}
