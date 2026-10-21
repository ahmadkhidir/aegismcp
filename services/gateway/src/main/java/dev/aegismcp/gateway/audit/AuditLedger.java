package dev.aegismcp.gateway.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

/**
 * High-throughput asynchronous write-ahead append log (WAL) and tamper-evident ledger.
 * Utilizes a lock-free concurrent queue and virtual-thread batch flusher to guarantee
 * sub-millisecond commit latency per NFR-004.
 * Anchors: FEAT-007, NFR-004, schema.md#AuditBlock.
 */
public class AuditLedger implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(AuditLedger.class);
    private static final int DEFAULT_MAX_BATCH_SIZE = 100;
    private static final long DRAIN_PARK_NANOS = 50_000L; // 50 microseconds

    private final int maxBatchSize;
    private final ConcurrentNavigableMap<Long, AuditBlock> blocks = new ConcurrentSkipListMap<>();
    private final ConcurrentLinkedQueue<AppendTask> ingressQueue = new ConcurrentLinkedQueue<>();
    private final AtomicReference<AuditBlock> latestBlock;
    private final AtomicLong nextBlockIndex;
    private final AtomicLong totalRecordsCount = new AtomicLong(0);

    private final AtomicBoolean running = new AtomicBoolean(true);
    private final Thread flusherThread;
    private final Object sealLock = new Object();

    public record AppendTask(AuditRecord record, CompletableFuture<AuditRecord> future) {
    }

    public AuditLedger() {
        this(DEFAULT_MAX_BATCH_SIZE);
    }

    public AuditLedger(int maxBatchSize) {
        this.maxBatchSize = Math.max(1, maxBatchSize);
        AuditBlock genesis = AuditBlock.genesis();
        this.blocks.put(genesis.getBlockIndex(), genesis);
        this.latestBlock = new AtomicReference<>(genesis);
        this.nextBlockIndex = new AtomicLong(1L);

        // Background flusher using Loom virtual thread for lock-free batch draining
        this.flusherThread = Thread.ofVirtual()
                .name("audit-ledger-wal-flusher")
                .start(this::drainLoop);
    }

    /**
     * Appends an audit record asynchronously to the ledger.
     * Enqueue is lock-free and returns immediately with a CompletableFuture.
     */
    public CompletableFuture<AuditRecord> append(AuditRecord record) {
        Objects.requireNonNull(record, "record must not be null");
        CompletableFuture<AuditRecord> future = new CompletableFuture<>();
        ingressQueue.offer(new AppendTask(record, future));
        LockSupport.unpark(flusherThread);
        return future;
    }

    /**
     * Appends an audit record synchronously, awaiting block commit.
     */
    public AuditRecord appendSync(AuditRecord record) {
        return append(record).join();
    }

    /**
     * Continuous drain loop executed by the virtual thread worker.
     */
    private void drainLoop() {
        List<AppendTask> batch = new ArrayList<>(maxBatchSize);

        while (running.get() || !ingressQueue.isEmpty()) {
            AppendTask task;
            while (batch.size() < maxBatchSize && (task = ingressQueue.poll()) != null) {
                batch.add(task);
            }

            if (!batch.isEmpty()) {
                commitBatch(batch);
                batch.clear();
            } else {
                // Low-overhead parking with microsecond wakeups
                LockSupport.parkNanos(DRAIN_PARK_NANOS);
            }
        }
    }

    /**
     * Seals a batch of records into an immutable AuditBlock and completes their futures.
     */
    private void commitBatch(List<AppendTask> tasks) {
        synchronized (sealLock) {
            long index = nextBlockIndex.getAndIncrement();
            String prevHash = latestBlock.get().getBlockHash();

            List<AuditRecord> records = new ArrayList<>(tasks.size());
            for (AppendTask task : tasks) {
                records.add(task.record());
            }

            AuditBlock block = AuditBlock.seal(index, prevHash, records);
            blocks.put(index, block);
            latestBlock.set(block);
            totalRecordsCount.addAndGet(records.size());

            // Fulfill caller futures
            for (AppendTask task : tasks) {
                task.future().complete(task.record());
            }
        }
    }

    /**
     * Immediately flushes all queued records into sealed blocks.
     */
    public void flush() {
        List<AppendTask> drain = new ArrayList<>();
        AppendTask task;
        while ((task = ingressQueue.poll()) != null) {
            drain.add(task);
            if (drain.size() >= maxBatchSize) {
                commitBatch(drain);
                drain.clear();
            }
        }
        if (!drain.isEmpty()) {
            commitBatch(drain);
        }
    }

    /**
     * Retrieves an audit block by its index.
     */
    public AuditBlock getBlock(long index) {
        return blocks.get(index);
    }

    /**
     * Retrieves a contiguous range of audit blocks [fromIndex, toIndex].
     */
    public List<AuditBlock> getBlocks(long fromIndex, long toIndex) {
        if (fromIndex < 0 || toIndex < fromIndex) {
            throw new IllegalArgumentException("Invalid range: fromIndex=" + fromIndex + ", toIndex=" + toIndex);
        }
        ConcurrentNavigableMap<Long, AuditBlock> subMap = blocks.subMap(fromIndex, true, toIndex, true);
        return new ArrayList<>(subMap.values());
    }

    /**
     * Returns the latest sealed audit block in the ledger.
     */
    public AuditBlock getLatestBlock() {
        return latestBlock.get();
    }

    /**
     * Returns the latest block index.
     */
    public long getLatestBlockIndex() {
        return latestBlock.get().getBlockIndex();
    }

    /**
     * Returns total number of blocks in ledger, including genesis block.
     */
    public long getBlockCount() {
        return blocks.size();
    }

    /**
     * Returns total number of audit records sealed in ledger.
     */
    public long getTotalRecordsCount() {
        return totalRecordsCount.get();
    }

    /**
     * Testing utility to replace a block at a given index with a modified/tampered block.
     */
    public void tamperWithBlock(long index, AuditBlock tamperedBlock) {
        synchronized (sealLock) {
            blocks.put(index, tamperedBlock);
            if (latestBlock.get().getBlockIndex() == index) {
                latestBlock.set(tamperedBlock);
            }
        }
    }

    @Override
    public void close() {
        if (running.compareAndSet(true, false)) {
            LockSupport.unpark(flusherThread);
            try {
                flusherThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            flush();
        }
    }
}
