package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Result of audit ledger verification conforming to contract C-007.
 * Anchors: C-007, FEAT-007.
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public record AuditVerificationResult(
        @JsonProperty("valid") boolean valid,
        @JsonProperty("checkedBlocks") long checkedBlocks,
        @JsonProperty("merkleRoot") String merkleRoot,
        @JsonProperty("latestBlockHash") String latestBlockHash,
        @JsonProperty("brokenAtBlock") Long brokenAtBlock
) {

    @JsonCreator
    public AuditVerificationResult(
            @JsonProperty("valid") boolean valid,
            @JsonProperty("checkedBlocks") long checkedBlocks,
            @JsonProperty("merkleRoot") String merkleRoot,
            @JsonProperty("latestBlockHash") String latestBlockHash,
            @JsonProperty("brokenAtBlock") Long brokenAtBlock
    ) {
        this.valid = valid;
        this.checkedBlocks = checkedBlocks;
        this.merkleRoot = merkleRoot;
        this.latestBlockHash = latestBlockHash;
        this.brokenAtBlock = brokenAtBlock;
    }

    public static AuditVerificationResult success(long checkedBlocks, String merkleRoot, String latestBlockHash) {
        return new AuditVerificationResult(true, checkedBlocks, merkleRoot, latestBlockHash, null);
    }

    public static AuditVerificationResult failure(long checkedBlocks, long brokenAtBlock) {
        return new AuditVerificationResult(false, checkedBlocks, null, null, brokenAtBlock);
    }
}
