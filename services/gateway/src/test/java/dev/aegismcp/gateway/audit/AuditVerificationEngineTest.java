package dev.aegismcp.gateway.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying hash chain calculation, 100+ block validation, and tamper detection.
 * Anchors: FEAT-007, C-007, schema.md#AuditBlock.
 */
class AuditVerificationEngineTest {

    private final AuditVerificationEngine engine = AuditVerificationEngine.getInstance();

    @Test
    @DisplayName("FEAT-007: Validates unbroken hash chain across 100+ blocks")
    void testValidateAcrossHundredBlocks() {
        try (AuditLedger ledger = new AuditLedger(1)) { // 1 record per block
            for (int i = 1; i <= 105; i++) {
                AuditRecord record = AuditRecord.create("agent-worker", "tool_" + i, "allow", 0, 1.0, "arg=" + i);
                ledger.appendSync(record);
            }

            assertEquals(106, ledger.getBlockCount()); // genesis (0) + 105 blocks
            assertEquals(105L, ledger.getLatestBlockIndex());

            AuditVerificationResult result = engine.verifyRange(ledger, 0, 105);

            assertTrue(result.valid());
            assertEquals(106, result.checkedBlocks());
            assertNull(result.brokenAtBlock());
            assertEquals(ledger.getLatestBlock().getPayloadHash(), result.merkleRoot());
            assertEquals(ledger.getLatestBlock().getBlockHash(), result.latestBlockHash());
        }
    }

    @Test
    @DisplayName("FEAT-007: Validates arbitrary sub-ranges of the audit ledger")
    void testValidateSubRange() {
        try (AuditLedger ledger = new AuditLedger(1)) {
            for (int i = 1; i <= 50; i++) {
                ledger.appendSync(AuditRecord.create("agent-sub", "tool_" + i, "allow", 0, 0.9, "{}"));
            }

            AuditVerificationResult result = engine.verifyRange(ledger, 10, 30);

            assertTrue(result.valid());
            assertEquals(21, result.checkedBlocks()); // 30 - 10 + 1
            assertNull(result.brokenAtBlock());
            assertEquals(ledger.getBlock(30).getPayloadHash(), result.merkleRoot());
            assertEquals(ledger.getBlock(30).getBlockHash(), result.latestBlockHash());
        }
    }

    @Test
    @DisplayName("FEAT-007 / C-007: Tampering single bit in historical record invalidates chain and pinpoints brokenAtBlock")
    void testTamperHistoricalRecordDetected() {
        try (AuditLedger ledger = new AuditLedger(1)) {
            for (int i = 1; i <= 20; i++) {
                ledger.appendSync(AuditRecord.create("agent-tamper", "tool_" + i, "allow", 0, 1.0, "payload-" + i));
            }

            long targetBlockIndex = 7;
            AuditBlock originalBlock = ledger.getBlock(targetBlockIndex);
            assertNotNull(originalBlock);

            // Attacker modifies decision in record from 'allow' to 'block'
            AuditRecord originalRecord = originalBlock.getRecords().get(0);
            AuditRecord tamperedRecord = AuditRecord.of(
                    originalRecord.getRecordId(),
                    originalRecord.getTimestamp(),
                    originalRecord.getAgentId(),
                    originalRecord.getToolName(),
                    "block", // tampered decision
                    originalRecord.getRedactionCount(),
                    originalRecord.getLatencyMs(),
                    originalRecord.getPayloadSummary()
            );

            // Replace block 7 with modified records while keeping original blockHash
            AuditBlock tamperedBlock = new AuditBlock(
                    originalBlock.getBlockIndex(),
                    originalBlock.getTimestamp(),
                    originalBlock.getPreviousHash(),
                    originalBlock.getPayloadHash(), // unupdated or mismatched payload hash
                    originalBlock.getBlockHash(),
                    List.of(tamperedRecord)
            );

            ledger.tamperWithBlock(targetBlockIndex, tamperedBlock);

            AuditVerificationResult result = engine.verifyRange(ledger, 0, 20);

            assertFalse(result.valid());
            assertEquals(targetBlockIndex, result.brokenAtBlock());
            assertNull(result.merkleRoot());
            assertNull(result.latestBlockHash());
        }
    }

    @Test
    @DisplayName("FEAT-007: Attacker modifying blockHash and payloadHash is caught by next block's previousHash linkage")
    void testTamperRecalculatedHeaderCaughtByLinkage() {
        try (AuditLedger ledger = new AuditLedger(1)) {
            for (int i = 1; i <= 20; i++) {
                ledger.appendSync(AuditRecord.create("agent-deep-tamper", "tool_" + i, "allow", 0, 1.0, "p-" + i));
            }

            long targetBlockIndex = 12;
            AuditBlock originalBlock = ledger.getBlock(targetBlockIndex);

            // Attacker alters payload and recalculates block 12's blockHash
            AuditRecord tamperedRecord = AuditRecord.create("agent-deep-tamper", "malicious_tool", "allow", 0, 1.0, "injected");
            AuditBlock resealedBlock = AuditBlock.seal(targetBlockIndex, originalBlock.getPreviousHash(), List.of(tamperedRecord));

            ledger.tamperWithBlock(targetBlockIndex, resealedBlock);

            // Verification across the range should fail at block 13 because block 13.previousHash != block 12.resealedBlockHash
            AuditVerificationResult result = engine.verifyRange(ledger, 0, 20);

            assertFalse(result.valid());
            assertEquals(13L, result.brokenAtBlock());
        }
    }

    @Test
    @DisplayName("FEAT-007: Tampering with Genesis block root hash fails verification at block 0")
    void testTamperGenesisBlock() {
        try (AuditLedger ledger = new AuditLedger(1)) {
            ledger.appendSync(AuditRecord.create("agent-g", "tool_init", "allow", 0, 1.0, "{}"));

            // Tamper genesis block previousHash
            AuditBlock tamperedGenesis = new AuditBlock(
                    0L,
                    "1970-01-01T00:00:00Z",
                    "deadbeef00000000000000000000000000000000000000000000000000000000",
                    MerkleTree.EMPTY_ROOT,
                    AuditBlock.calculateBlockHash(0L, "1970-01-01T00:00:00Z", "deadbeef00000000000000000000000000000000000000000000000000000000", MerkleTree.EMPTY_ROOT),
                    List.of()
            );

            ledger.tamperWithBlock(0L, tamperedGenesis);

            AuditVerificationResult result = engine.verifyRange(ledger, 0, 1);
            assertFalse(result.valid());
            assertEquals(0L, result.brokenAtBlock());
        }
    }

    @Test
    @DisplayName("C-007: Verification throws IllegalArgumentException on invalid block range")
    void testInvalidBlockRange() {
        try (AuditLedger ledger = new AuditLedger(1)) {
            ledger.appendSync(AuditRecord.create("agent-1", "tool_1", "allow", 0, 1.0, "{}"));

            // fromBlock < 0
            assertThrows(IllegalArgumentException.class, () -> engine.verifyRange(ledger, -1, 1));

            // toBlock < fromBlock
            assertThrows(IllegalArgumentException.class, () -> engine.verifyRange(ledger, 1, 0));

            // fromBlock > latestBlockIndex
            assertThrows(IllegalArgumentException.class, () -> engine.verifyRange(ledger, 5, 5));

            // toBlock > latestBlockIndex
            assertThrows(IllegalArgumentException.class, () -> engine.verifyRange(ledger, 0, 50));
        }
    }
}
