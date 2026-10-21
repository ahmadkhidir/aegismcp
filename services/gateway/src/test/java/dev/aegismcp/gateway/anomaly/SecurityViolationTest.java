package dev.aegismcp.gateway.anomaly;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying SecurityViolation conforms to schema.md#SecurityViolation.
 * Anchors: FEAT-004, schema.md#SecurityViolation.
 */
class SecurityViolationTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("schema.md#SecurityViolation: Serializes and deserializes all required fields")
    void testSerializationRoundTrip() throws Exception {
        SecurityViolation violation = SecurityViolation.toolChainingAnomaly(
                "spiffe://cluster.local/ns/prod/sa/support-agent",
                "Forbidden sequence: read_file -> curl:exec",
                SecurityViolation.SEVERITY_CRITICAL
        );

        String json = mapper.writeValueAsString(violation);
        assertNotNull(json);
        assertTrue(json.contains("\"agentId\":\"spiffe://cluster.local/ns/prod/sa/support-agent\""));
        assertTrue(json.contains("\"violationType\":\"tool_chaining_anomaly\""));
        assertTrue(json.contains("\"severity\":\"critical\""));
        assertTrue(json.contains("\"details\":\"Forbidden sequence: read_file -> curl:exec\""));

        SecurityViolation deserialized = mapper.readValue(json, SecurityViolation.class);
        assertEquals(violation.id(), deserialized.id());
        assertEquals(violation.agentId(), deserialized.agentId());
        assertEquals(violation.violationType(), deserialized.violationType());
        assertEquals(violation.blockHash(), deserialized.blockHash());
        assertEquals(violation.severity(), deserialized.severity());
        assertEquals(violation.details(), deserialized.details());
        assertEquals(violation.createdAt(), deserialized.createdAt());
    }

    @Test
    @DisplayName("schema.md#SecurityViolation: Rejects null required properties")
    void testValidationRequiredProperties() {
        assertThrows(NullPointerException.class, () ->
                new SecurityViolation(null, "agent", "type", "hash", "crit", "det", "time")
        );
        assertThrows(NullPointerException.class, () ->
                new SecurityViolation("id", null, "type", "hash", "crit", "det", "time")
        );
        assertThrows(NullPointerException.class, () ->
                new SecurityViolation("id", "agent", null, "hash", "crit", "det", "time")
        );
    }
}
