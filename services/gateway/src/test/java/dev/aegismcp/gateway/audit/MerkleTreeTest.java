package dev.aegismcp.gateway.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Merkle tree calculator over audit records.
 * Anchors: FEAT-007, schema.md#AuditBlock.
 */
class MerkleTreeTest {

    @Test
    @DisplayName("FEAT-007: Empty records list returns deterministic empty root hash")
    void testEmptyRecords() {
        String root1 = MerkleTree.computeRoot(Collections.emptyList());
        String root2 = MerkleTree.computeRoot(null);

        assertEquals(MerkleTree.EMPTY_ROOT, root1);
        assertEquals(MerkleTree.EMPTY_ROOT, root2);
        assertEquals(64, root1.length());
    }

    @Test
    @DisplayName("FEAT-007: Single record root matches the leaf record hash")
    void testSingleRecord() {
        AuditRecord record = AuditRecord.create("agent-1", "tool-a", "allow", 0, 1.0, "arg1");
        String root = MerkleTree.computeRoot(List.of(record));

        assertEquals(record.getRecordHash(), root);
    }

    @Test
    @DisplayName("FEAT-007: Even and odd number of records compute deterministic Merkle root")
    void testEvenAndOddRecords() {
        AuditRecord r1 = AuditRecord.create("agent-1", "tool-1", "allow", 0, 1.0, "p1");
        AuditRecord r2 = AuditRecord.create("agent-1", "tool-2", "block", 1, 2.0, "p2");
        AuditRecord r3 = AuditRecord.create("agent-2", "tool-3", "allow", 0, 0.8, "p3");

        // 2 records (even)
        String rootEven = MerkleTree.computeRoot(List.of(r1, r2));
        assertNotNull(rootEven);
        assertEquals(64, rootEven.length());

        // 3 records (odd: duplicate last leaf at first level)
        String rootOdd = MerkleTree.computeRoot(List.of(r1, r2, r3));
        assertNotNull(rootOdd);
        assertEquals(64, rootOdd.length());
        assertNotEquals(rootEven, rootOdd);

        // Determinism check
        assertEquals(rootOdd, MerkleTree.computeRoot(List.of(r1, r2, r3)));
    }

    @Test
    @DisplayName("FEAT-007: Tampering with single record in a multi-record tree changes Merkle root")
    void testTamperChangesRoot() {
        AuditRecord r1 = AuditRecord.create("agent-1", "tool-1", "allow", 0, 1.0, "p1");
        AuditRecord r2 = AuditRecord.create("agent-1", "tool-2", "allow", 0, 1.2, "p2");
        AuditRecord r3 = AuditRecord.create("agent-1", "tool-3", "allow", 0, 1.5, "p3");

        String originalRoot = MerkleTree.computeRoot(List.of(r1, r2, r3));

        // Tamper with r2
        AuditRecord tamperedR2 = AuditRecord.of(
                r2.getRecordId(),
                r2.getTimestamp(),
                r2.getAgentId(),
                r2.getToolName(),
                "block", // tampered decision
                r2.getRedactionCount(),
                r2.getLatencyMs(),
                r2.getPayloadSummary()
        );

        String tamperedRoot = MerkleTree.computeRoot(List.of(r1, tamperedR2, r3));
        assertNotEquals(originalRoot, tamperedRoot);
    }
}
