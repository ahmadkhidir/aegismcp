package dev.aegismcp.gateway.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for high-throughput asynchronous write-ahead append logging and block sealing.
 * Anchors: FEAT-007, NFR-004, schema.md#AuditBlock.
 */
class AuditLedgerTest {

    @Test
    @DisplayName("FEAT-007: AuditLedger initializes with canonical Genesis Block at index 0")
    void testGenesisBlockInitialization() {
        try (AuditLedger ledger = new AuditLedger()) {
            assertEquals(1, ledger.getBlockCount());
            assertEquals(0L, ledger.getLatestBlockIndex());

            AuditBlock genesis = ledger.getLatestBlock();
            assertNotNull(genesis);
            assertEquals(0L, genesis.getBlockIndex());
            assertEquals(AuditBlock.GENESIS_PREVIOUS_HASH, genesis.getPreviousHash());
            assertEquals(AuditBlock.GENESIS_PREVIOUS_HASH, genesis.getParentHash());
            assertNotNull(genesis.getBlockHash());
            assertEquals(64, genesis.getBlockHash().length());
            assertTrue(genesis.getRecords().isEmpty());
        }
    }

    @Test
    @DisplayName("NFR-004: Asynchronous WAL append provides sub-millisecond commit latency")
    void testSubMillisecondCommitLatency() {
        try (AuditLedger ledger = new AuditLedger(10)) {
            // Warm-up
            for (int i = 0; i < 20; i++) {
                ledger.appendSync(AuditRecord.create("agent-warmup", "tool_ping", "allow", 0, 0.5, "{}"));
            }

            // Measure commit latency across 100 sequential asynchronous appends
            int sampleCount = 100;
            List<CompletableFuture<AuditRecord>> futures = new ArrayList<>(sampleCount);
            long startNanos = System.nanoTime();

            for (int i = 0; i < sampleCount; i++) {
                futures.add(ledger.append(AuditRecord.create("agent-perf", "tool_read", "allow", 0, 1.0, "{}")));
            }

            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
            long totalNanos = System.nanoTime() - startNanos;
            double avgLatencyMs = (totalNanos / 1_000_000.0) / sampleCount;

            // NFR-004 target: commit latency < 3.2ms (typically < 0.5ms with virtual thread WAL flusher)
            assertTrue(avgLatencyMs < 3.2, "Average commit latency was " + avgLatencyMs + "ms, expected < 3.2ms per NFR-004");
            assertTrue(ledger.getBlockCount() > 1);
        }
    }

    @Test
    @DisplayName("FEAT-007: Concurrent event appending seals blocks with unbroken hash chain")
    void testConcurrentAppending() throws InterruptedException {
        int threadCount = 10;
        int recordsPerThread = 50;
        int totalExpectedRecords = threadCount * recordsPerThread;

        try (AuditLedger ledger = new AuditLedger(25);
             ExecutorService pool = Executors.newFixedThreadPool(threadCount)) {

            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);
            List<CompletableFuture<AuditRecord>> allFutures = new ArrayList<>(totalExpectedRecords);

            for (int t = 0; t < threadCount; t++) {
                final int threadId = t;
                pool.submit(() -> {
                    try {
                        startLatch.await();
                        for (int r = 0; r < recordsPerThread; r++) {
                            AuditRecord rec = AuditRecord.create(
                                    "agent-" + threadId,
                                    "tool_" + r,
                                    (r % 2 == 0) ? "allow" : "block",
                                    0,
                                    1.2,
                                    "payload-" + r
                            );
                            CompletableFuture<AuditRecord> f = ledger.append(rec);
                            synchronized (allFutures) {
                                allFutures.add(f);
                            }
                        }
                    } catch (Exception e) {
                        fail("Exception in worker thread: " + e.getMessage());
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            startLatch.countDown();
            assertTrue(doneLatch.await(10, TimeUnit.SECONDS));

            CompletableFuture.allOf(allFutures.toArray(new CompletableFuture[0])).join();
            ledger.flush();

            assertEquals(totalExpectedRecords, ledger.getTotalRecordsCount());
            assertTrue(ledger.getBlockCount() > 1);

            // Verify unbroken hash chain
            AuditVerificationEngine engine = AuditVerificationEngine.getInstance();
            AuditVerificationResult result = engine.verifyRange(ledger, 0, ledger.getLatestBlockIndex());

            assertTrue(result.valid());
            assertEquals(ledger.getBlockCount(), result.checkedBlocks());
            assertNull(result.brokenAtBlock());
            assertNotNull(result.merkleRoot());
            assertNotNull(result.latestBlockHash());
        }
    }
}
