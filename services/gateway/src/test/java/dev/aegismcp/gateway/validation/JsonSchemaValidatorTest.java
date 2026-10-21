package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying JSON schema validation rules.
 * Anchors: FEAT-012 AC 1, NFR-024.
 */
class JsonSchemaValidatorTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private JsonSchemaValidator validator;

    @BeforeEach
    void setUp() {
        validator = new JsonSchemaValidator();
    }

    @Test
    @DisplayName("FEAT-012 AC 1: Valid arguments conforming to schema pass validation")
    void testValidArgumentsPass() throws Exception {
        String schemaJson = """
                {
                  "type": "object",
                  "properties": {
                    "path": { "type": "string" },
                    "limit": { "type": "integer" },
                    "active": { "type": "boolean" }
                  },
                  "required": ["path", "limit"]
                }
                """;
        var schema = mapper.readTree(schemaJson);

        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/workspace/data.csv");
        args.put("limit", 50);
        args.put("active", true);

        List<ValidationViolation> violations = validator.validate(schema, args);
        assertTrue(violations.isEmpty(), "Expected no violations for valid payload");
    }

    @Test
    @DisplayName("FEAT-012 AC 1: Type mismatch (string passed instead of integer) is rejected")
    void testTypeMismatchRejected() throws Exception {
        String schemaJson = """
                {
                  "type": "object",
                  "properties": {
                    "count": { "type": "integer" }
                  },
                  "required": ["count"]
                }
                """;
        var schema = mapper.readTree(schemaJson);

        ObjectNode args = mapper.createObjectNode();
        args.put("count", "not-a-number");

        List<ValidationViolation> violations = validator.validate(schema, args);
        assertEquals(1, violations.size());
        assertTrue(violations.get(0).message().contains("type mismatch"));
        assertTrue(violations.get(0).message().contains("expected integer, got string"));
    }

    @Test
    @DisplayName("FEAT-012 AC 1: Missing required property is rejected")
    void testMissingRequiredPropertyRejected() throws Exception {
        String schemaJson = """
                {
                  "type": "object",
                  "properties": {
                    "targetFile": { "type": "string" },
                    "retries": { "type": "integer" }
                  },
                  "required": ["targetFile", "retries"]
                }
                """;
        var schema = mapper.readTree(schemaJson);

        ObjectNode args = mapper.createObjectNode();
        args.put("targetFile", "output.txt");
        // 'retries' omitted

        List<ValidationViolation> violations = validator.validate(schema, args);
        assertEquals(1, violations.size());
        assertEquals("retries", violations.get(0).parameterName());
        assertTrue(violations.get(0).message().contains("Missing required property"));
    }

    @Test
    @DisplayName("FEAT-012: Additional properties rejected when additionalProperties is false")
    void testAdditionalPropertiesRejected() throws Exception {
        String schemaJson = """
                {
                  "type": "object",
                  "properties": {
                    "username": { "type": "string" }
                  },
                  "required": ["username"],
                  "additionalProperties": false
                }
                """;
        var schema = mapper.readTree(schemaJson);

        ObjectNode args = mapper.createObjectNode();
        args.put("username", "alice");
        args.put("unexpectedField", "injectedPayload");

        List<ValidationViolation> violations = validator.validate(schema, args);
        assertEquals(1, violations.size());
        assertEquals("unexpectedField", violations.get(0).parameterName());
        assertTrue(violations.get(0).message().contains("Unexpected property"));
    }

    @Test
    @DisplayName("FEAT-012: Enum validation verifies allowable values")
    void testEnumValidation() throws Exception {
        String schemaJson = """
                {
                  "type": "object",
                  "properties": {
                    "format": { "type": "string", "enum": ["JSON", "CSV", "XML"] }
                  }
                }
                """;
        var schema = mapper.readTree(schemaJson);

        ObjectNode args = mapper.createObjectNode();
        args.put("format", "YAML");

        List<ValidationViolation> violations = validator.validate(schema, args);
        assertEquals(1, violations.size());
        assertTrue(violations.get(0).message().contains("not an allowed enum constant"));
    }

    @Test
    @DisplayName("FEAT-012 Edge Case: Missing or empty schema falls back gracefully")
    void testMissingSchemaFallback() {
        ObjectNode args = mapper.createObjectNode();
        args.put("param", "value");

        List<ValidationViolation> violations = validator.validate(null, args);
        assertTrue(violations.isEmpty(), "Null schema should not produce schema violations");

        violations = validator.validate(mapper.createObjectNode(), args);
        assertTrue(violations.isEmpty(), "Empty schema should not produce schema violations");
    }
}
