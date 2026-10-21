package dev.aegismcp.gateway.audit;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Merkle tree calculator over audit records within an audit block.
 * Anchors: FEAT-007, schema.md#AuditBlock.
 */
public final class MerkleTree {

    public static final String EMPTY_ROOT = HashUtils.sha256Hex("");

    private MerkleTree() {
    }

    /**
     * Computes the Merkle tree root hash for a given list of audit records.
     * Returns a deterministic SHA-256 root hex string.
     */
    public static String computeRoot(List<AuditRecord> records) {
        if (records == null || records.isEmpty()) {
            return EMPTY_ROOT;
        }

        List<String> leafHashes = new ArrayList<>(records.size());
        for (AuditRecord record : records) {
            leafHashes.add(record.getRecordHash());
        }

        return computeRootFromHashes(leafHashes);
    }

    /**
     * Computes the Merkle tree root hash given a list of leaf hash strings.
     * Odd leaves at each level are duplicated per RFC 6962 / standard binary Merkle trees.
     */
    public static String computeRootFromHashes(List<String> leafHashes) {
        if (leafHashes == null || leafHashes.isEmpty()) {
            return EMPTY_ROOT;
        }

        if (leafHashes.size() == 1) {
            return leafHashes.get(0);
        }

        List<String> currentLevel = new ArrayList<>(leafHashes);

        while (currentLevel.size() > 1) {
            List<String> nextLevel = new ArrayList<>((currentLevel.size() + 1) / 2);
            for (int i = 0; i < currentLevel.size(); i += 2) {
                String left = currentLevel.get(i);
                String right = (i + 1 < currentLevel.size()) ? currentLevel.get(i + 1) : left;
                String combined = HashUtils.sha256Hex(left + right);
                nextLevel.add(combined);
            }
            currentLevel = nextLevel;
        }

        return currentLevel.get(0);
    }
}
