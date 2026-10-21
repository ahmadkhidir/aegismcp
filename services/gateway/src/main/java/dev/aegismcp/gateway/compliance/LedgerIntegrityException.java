package dev.aegismcp.gateway.compliance;

/**
 * Exception thrown when cryptographic ledger verification detects corrupted or modified historical blocks.
 * Maps to HTTP 409 Conflict per contract C-011 and FEAT-011.
 * Anchors: C-011, FEAT-011.
 */
public class LedgerIntegrityException extends RuntimeException {

    private final Long brokenAtBlock;

    public LedgerIntegrityException(String message, Long brokenAtBlock) {
        super(message);
        this.brokenAtBlock = brokenAtBlock;
    }

    public Long getBrokenAtBlock() {
        return brokenAtBlock;
    }
}
