package dev.aegismcp.gateway.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Verification engine that validates cryptographic hash chain integrity and Merkle proofs
 * across any block range in the audit ledger, detecting broken chains or tampered entries.
 * Anchors: FEAT-007, C-007, schema.md#AuditBlock.
 */
public class AuditVerificationEngine {

    private static final Logger logger = LoggerFactory.getLogger(AuditVerificationEngine.class);
    private static final AuditVerificationEngine INSTANCE = new AuditVerificationEngine();

    public static AuditVerificationEngine getInstance() {
        return INSTANCE;
    }

    public AuditVerificationEngine() {
    }

    /**
     * Verifies the cryptographic integrity of the ledger across [fromBlock, toBlock].
     *
     * @param ledger the audit ledger to verify
     * @param fromBlock starting block index (inclusive)
     * @param toBlock ending block index (inclusive)
     * @return AuditVerificationResult conforming to contract C-007
     * @throws IllegalArgumentException if fromBlock or toBlock are invalid
     */
    public AuditVerificationResult verifyRange(AuditLedger ledger, long fromBlock, long toBlock) {
        Objects.requireNonNull(ledger, "ledger must not be null");

        long latestIndex = ledger.getLatestBlockIndex();
        if (fromBlock < 0) {
            throw new IllegalArgumentException("Invalid block range: fromBlock cannot be negative (" + fromBlock + ")");
        }
        if (toBlock < fromBlock) {
            throw new IllegalArgumentException("Invalid block range: toBlock (" + toBlock + ") cannot be less than fromBlock (" + fromBlock + ")");
        }
        if (fromBlock > latestIndex) {
            throw new IllegalArgumentException("Invalid block range: fromBlock (" + fromBlock + ") exceeds latest block index (" + latestIndex + ")");
        }
        if (toBlock > latestIndex) {
            throw new IllegalArgumentException("Invalid block range: toBlock (" + toBlock + ") exceeds latest block index (" + latestIndex + ")");
        }

        long checkedBlocks = 0;

        for (long i = fromBlock; i <= toBlock; i++) {
            AuditBlock block = ledger.getBlock(i);
            if (block == null) {
                logger.warn("Verification failed: block {} is missing", i);
                return AuditVerificationResult.failure(checkedBlocks, i);
            }

            checkedBlocks++;

            // 1. Verify block index consistency
            if (block.getBlockIndex() != i) {
                logger.warn("Verification failed: block at position {} has index {}", i, block.getBlockIndex());
                return AuditVerificationResult.failure(checkedBlocks, i);
            }

            // 2. Verify Merkle root of records against payloadHash
            String recalculatedPayloadHash = MerkleTree.computeRoot(block.getRecords());
            if (!Objects.equals(recalculatedPayloadHash, block.getPayloadHash())) {
                logger.warn("Verification failed: block {} payloadHash mismatch. Expected {}, actual {}",
                        i, block.getPayloadHash(), recalculatedPayloadHash);
                return AuditVerificationResult.failure(checkedBlocks, i);
            }

            // 3. Verify block header hash
            String recalculatedBlockHash = AuditBlock.calculateBlockHash(
                    block.getBlockIndex(),
                    block.getTimestamp(),
                    block.getPreviousHash(),
                    block.getPayloadHash()
            );
            if (!Objects.equals(recalculatedBlockHash, block.getBlockHash())) {
                logger.warn("Verification failed: block {} blockHash mismatch. Expected {}, actual {}",
                        i, block.getBlockHash(), recalculatedBlockHash);
                return AuditVerificationResult.failure(checkedBlocks, i);
            }

            // 4. Verify previousHash chain linkage
            if (i == 0) {
                if (!Objects.equals(AuditBlock.GENESIS_PREVIOUS_HASH, block.getPreviousHash())) {
                    logger.warn("Verification failed: genesis block previousHash is not 64 zeros: {}", block.getPreviousHash());
                    return AuditVerificationResult.failure(checkedBlocks, 0L);
                }
            } else {
                AuditBlock prevBlock = ledger.getBlock(i - 1);
                if (prevBlock == null) {
                    logger.warn("Verification failed: preceding block {} is missing for block {}", i - 1, i);
                    return AuditVerificationResult.failure(checkedBlocks, i);
                }
                if (!Objects.equals(block.getPreviousHash(), prevBlock.getBlockHash())) {
                    logger.warn("Verification failed: block {} previousHash does not link to preceding block {} hash. Block prevHash={}, preceding blockHash={}",
                            i, i - 1, block.getPreviousHash(), prevBlock.getBlockHash());
                    return AuditVerificationResult.failure(checkedBlocks, i);
                }
            }
        }

        AuditBlock latestChecked = ledger.getBlock(toBlock);
        return AuditVerificationResult.success(checkedBlocks, latestChecked.getPayloadHash(), latestChecked.getBlockHash());
    }
}
