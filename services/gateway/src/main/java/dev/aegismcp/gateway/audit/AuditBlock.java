package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * An immutable, cryptographically hash-chained audit block sealing one or more audit records.
 * Anchors: FEAT-007, schema.md#AuditBlock.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class AuditBlock {

    public static final String GENESIS_PREVIOUS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    private final long blockIndex;
    private final String timestamp;
    private final String previousHash;
    private final String payloadHash;
    private final String blockHash;
    private final List<AuditRecord> records;

    @JsonCreator
    public AuditBlock(
            @JsonProperty("blockIndex") long blockIndex,
            @JsonProperty("timestamp") String timestamp,
            @JsonProperty("previousHash") @JsonAlias("parentHash") String previousHash,
            @JsonProperty("payloadHash") String payloadHash,
            @JsonProperty("blockHash") String blockHash,
            @JsonProperty("records") List<AuditRecord> records
    ) {
        if (blockIndex < 0) {
            throw new IllegalArgumentException("blockIndex must not be negative");
        }
        this.blockIndex = blockIndex;
        this.timestamp = Objects.requireNonNull(timestamp, "timestamp must not be null");
        this.previousHash = Objects.requireNonNull(previousHash, "previousHash must not be null");
        this.records = records != null ? List.copyOf(records) : Collections.emptyList();
        this.payloadHash = (payloadHash != null && !payloadHash.isBlank())
                ? payloadHash
                : MerkleTree.computeRoot(this.records);
        this.blockHash = (blockHash != null && !blockHash.isBlank())
                ? blockHash
                : calculateBlockHash(this.blockIndex, this.timestamp, this.previousHash, this.payloadHash);
    }

    /**
     * Constructs and seals a new block linking to the previous block hash.
     */
    public static AuditBlock seal(long blockIndex, String previousHash, List<AuditRecord> records) {
        String timestamp = Instant.now().toString();
        String payloadHash = MerkleTree.computeRoot(records);
        String blockHash = calculateBlockHash(blockIndex, timestamp, previousHash, payloadHash);
        return new AuditBlock(blockIndex, timestamp, previousHash, payloadHash, blockHash, records);
    }

    /**
     * Constructs the canonical genesis block at index 0.
     */
    public static AuditBlock genesis() {
        return genesis("1970-01-01T00:00:00Z");
    }

    /**
     * Constructs the canonical genesis block with a specific timestamp.
     */
    public static AuditBlock genesis(String timestamp) {
        List<AuditRecord> emptyRecords = Collections.emptyList();
        String payloadHash = MerkleTree.computeRoot(emptyRecords);
        String blockHash = calculateBlockHash(0L, timestamp, GENESIS_PREVIOUS_HASH, payloadHash);
        return new AuditBlock(0L, timestamp, GENESIS_PREVIOUS_HASH, payloadHash, blockHash, emptyRecords);
    }

    /**
     * Calculates the SHA-256 hash of a block header.
     */
    public static String calculateBlockHash(long blockIndex, String timestamp, String previousHash, String payloadHash) {
        String canonical = blockIndex + ":" + timestamp + ":" + previousHash + ":" + payloadHash;
        return HashUtils.sha256Hex(canonical);
    }

    @JsonProperty("blockIndex")
    public long getBlockIndex() {
        return blockIndex;
    }

    @JsonProperty("timestamp")
    public String getTimestamp() {
        return timestamp;
    }

    @JsonProperty("previousHash")
    public String getPreviousHash() {
        return previousHash;
    }

    @JsonProperty("parentHash")
    public String getParentHash() {
        return previousHash;
    }

    @JsonProperty("payloadHash")
    public String getPayloadHash() {
        return payloadHash;
    }

    @JsonProperty("blockHash")
    public String getBlockHash() {
        return blockHash;
    }

    @JsonProperty("records")
    public List<AuditRecord> getRecords() {
        return records;
    }

    // Convenience getters matching docs/AegisMCP/schema.md#AuditBlock entity fields
    @JsonProperty("agentId")
    public String getAgentId() {
        if (!records.isEmpty()) {
            return records.get(0).getAgentId();
        }
        return "system";
    }

    @JsonProperty("toolName")
    public String getToolName() {
        if (records.size() == 1) {
            return records.get(0).getToolName();
        } else if (records.size() > 1) {
            return "batch";
        }
        return "none";
    }

    @JsonProperty("decision")
    public String getDecision() {
        if (!records.isEmpty()) {
            return records.get(0).getDecision();
        }
        return "allow";
    }

    @JsonProperty("redactionCount")
    public int getRedactionCount() {
        int count = 0;
        for (AuditRecord r : records) {
            count += r.getRedactionCount();
        }
        return count;
    }

    @JsonProperty("latencyMs")
    public double getLatencyMs() {
        if (records.isEmpty()) {
            return 0.0;
        }
        double sum = 0.0;
        for (AuditRecord r : records) {
            sum += r.getLatencyMs();
        }
        return sum / records.size();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditBlock that = (AuditBlock) o;
        return blockIndex == that.blockIndex &&
                Objects.equals(timestamp, that.timestamp) &&
                Objects.equals(previousHash, that.previousHash) &&
                Objects.equals(payloadHash, that.payloadHash) &&
                Objects.equals(blockHash, that.blockHash) &&
                Objects.equals(records, that.records);
    }

    @Override
    public int hashCode() {
        return Objects.hash(blockIndex, timestamp, previousHash, payloadHash, blockHash, records);
    }

    @Override
    public String toString() {
        return "AuditBlock{" +
                "blockIndex=" + blockIndex +
                ", timestamp='" + timestamp + '\'' +
                ", previousHash='" + previousHash + '\'' +
                ", payloadHash='" + payloadHash + '\'' +
                ", blockHash='" + blockHash + '\'' +
                ", recordsCount=" + records.size() +
                '}';
    }
}
