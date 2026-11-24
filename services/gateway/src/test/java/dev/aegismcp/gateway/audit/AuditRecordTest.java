package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AuditRecord data model and canonical hashing.
 * Anchors: FEAT-007, schema.md#AuditBlock.
 */
class AuditRecordTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("FEAT-007: AuditRecord calculates deterministic SHA-256 hash")
    void testAuditRecordHashDeterministic() {
        AuditRecord record1 = AuditRecord.of(
                "rec-001",
                "2026-10-21T08:00:00Z",
                "agent-1",
                "filesystem_read",
                "allow",
                0,
                1.5,
                "{\"path\": \"/workspace/file.txt\"}"
        );

        AuditRecord record2 = AuditRecord.of(
                "rec-001",
                "2026-10-21T08:00:00Z",
                "agent-1",
                "filesystem_read",
                "allow",
                0,
                1.5,
                "{\"path\": \"/workspace/file.txt\"}"
        );

        assertNotNull(record1.getRecordHash());
        assertEquals(64, record1.getRecordHash().length());
        assertEquals(record1.getRecordHash(), record2.getRecordHash());
        assertEquals(record1, record2);
    }

    @Test
    @DisplayName("FEAT-007: Modifying any field alters the record SHA-256 hash")
    void testFieldModificationAltersHash() {
        AuditRecord original = AuditRecord.of(
                "rec-001",
                "2026-10-21T08:00:00Z",
                "agent-1",
                "filesystem_read",
                "allow",
                0,
                1.5,
                "{\"path\": \"/workspace/file.txt\"}"
        );

        AuditRecord modified = AuditRecord.of(
                "rec-001",
                "2026-10-21T08:00:00Z",
                "agent-1",
                "filesystem_read",
                "block", // altered decision
                0,
                1.5,
                "{\"path\": \"/workspace/file.txt\"}"
        );

        assertNotEquals(original.getRecordHash(), modified.getRecordHash());
    }

    @Test
    @DisplayName("FEAT-007: AuditRecord serializes and deserializes cleanly via Jackson")
    void testSerializationRoundTrip() throws Exception {
        AuditRecord original = AuditRecord.create(
                "agent-analyst",
                "sql_query",
                "allow",
                2,
                3.4,
                "{\"query\": \"SELECT 1\"}"
        );

        String json = mapper.writeValueAsString(original);
        AuditRecord deserialized = mapper.readValue(json, AuditRecord.class);

        assertEquals(original.getRecordId(), deserialized.getRecordId());
        assertEquals(original.getAgentId(), deserialized.getAgentId());
        assertEquals(original.getToolName(), deserialized.getToolName());
        assertEquals(original.getDecision(), deserialized.getDecision());
        assertEquals(original.getRedactionCount(), deserialized.getRedactionCount());
        assertEquals(original.getLatencyMs(), deserialized.getLatencyMs());
        assertEquals(original.getPayloadSummary(), deserialized.getPayloadSummary());
        assertEquals(original.getRecordHash(), deserialized.getRecordHash());
        assertEquals(original.getArgumentsHash(), deserialized.getArgumentsHash());
        assertNull(deserialized.getReviewedBy());
    }

    @Test
    @DisplayName("C-013: the sealed reviewer and arguments digest survive serialization and stay bound to the hash")
    void testSealedReviewFieldsRoundTripAndAlterTheHash() throws Exception {
        String argumentsHash = ArgumentDigest.of(mapper.readTree("{\"environment\":\"production\"}"));
        AuditRecord approved = AuditRecord.create("agent-deploy", "deploy_prod", "allow", 0, 2.0,
                "status=200", argumentsHash, "operator@aegis.test");

        assertTrue(approved.getRecordHash().matches("[0-9a-f]{64}"));
        assertEquals(argumentsHash, approved.getArgumentsHash());
        assertEquals("operator@aegis.test", approved.getReviewedBy());

        AuditRecord deserialized = mapper.readValue(mapper.writeValueAsString(approved), AuditRecord.class);
        assertEquals("operator@aegis.test", deserialized.getReviewedBy());
        assertEquals(argumentsHash, deserialized.getArgumentsHash());
        assertEquals(approved.getRecordHash(), deserialized.getRecordHash());

        // The same interaction without a reviewer is a different sealed record.
        AuditRecord unreviewed = AuditRecord.create("agent-deploy", "deploy_prod", "allow", 0, 2.0,
                "status=200", argumentsHash, null);
        assertNotEquals(approved.getRecordHash(), unreviewed.getRecordHash());
        assertNull(unreviewed.getReviewedBy());

        // A different arguments digest is a different sealed record too.
        AuditRecord otherArguments = AuditRecord.of(approved.getRecordId(), approved.getTimestamp(),
                approved.getAgentId(), approved.getToolName(), approved.getDecision(),
                approved.getRedactionCount(), approved.getLatencyMs(), approved.getPayloadSummary(),
                ArgumentDigest.of(mapper.readTree("{\"environment\":\"staging\"}")),
                approved.getReviewedBy());
        assertNotEquals(approved.getRecordHash(), otherArguments.getRecordHash());
    }
}
