package dev.aegismcp.gateway.dlp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies NFR-002: outbound secret and PII scrubbing adds 1.2 ms p50 / 2.8 ms p95 / 5.5 ms p99 for
 * the declared response-size mix at 2,000 responses per second on one gateway node.
 *
 * <p>NFR-002 defines the measured interval, and this harness measures exactly that interval: from
 * the instant a response's complete upstream body enters the scrub boundary to the instant its
 * sanitized body is available for delivery. The clock starts before the body is handed to the
 * worker, so the worker-dispatch wait between admission and the start of the scan is inside the
 * measurement, not outside it. It ends when the scanner has returned a sanitized payload, which is
 * the earliest point at which the gateway could write that response onward.
 *
 * <p>The load model is the row's own: 2,000 responses per second offered on one node for 4,000
 * responses, whose declared mix is 90% at 4 KB, 8% at 64 KB, 1.75% at 256 KB, and 0.25% at the 1 MB
 * ceiling. The classes are spread across the run rather than batched, so no class is measured only
 * while the machine is warm or only while it is recovering. Percentiles are computed over every
 * admitted response; a response that was rejected, failed, or never produced a sanitized body is
 * not counted as served, and the run fails if any admitted response was not served.
 *
 * <p>The scan is dispatched to a virtual-thread-per-task executor, the same shape as the shipped
 * {@link DlpOutboundHandler} worker, so the dispatch wait being measured is the one the gateway
 * actually incurs. Anchors: NFR-002, FEAT-005.
 */
class DlpScrubberThroughputTest {

    private static final Logger logger = LoggerFactory.getLogger(DlpScrubberThroughputTest.class);

    /** Names the exact interval this harness measures; every latency assertion carries it. */
    private static final String BOUNDARY =
            "the interval from a complete upstream body entering the scrub boundary to its "
                    + "sanitized body becoming available, including worker-dispatch wait";

    /** NFR-002 targets, in milliseconds. */
    private static final double P50_BUDGET_MS = 1.2;
    private static final double P95_BUDGET_MS = 2.8;
    private static final double P99_BUDGET_MS = 5.5;

    /** NFR-002 load model. */
    private static final int TARGET_RPS = 2_000;
    private static final int REQUESTS = 4_000;
    /** Allowance for pacer scheduling when asserting the offered rate; not a latency budget. */
    private static final double OFFERED_RATE_TOLERANCE = 0.01;

    /** NFR-002 declared size mix: 90% / 8% / 1.75% / 0.25% of 4,000 responses. */
    private static final int SMALL_BYTES = 4 * 1024;
    private static final int MEDIUM_BYTES = 64 * 1024;
    private static final int LARGE_BYTES = 256 * 1024;
    private static final int MAX_BYTES = 1024 * 1024;
    private static final int[] CLASS_BYTES = {SMALL_BYTES, MEDIUM_BYTES, LARGE_BYTES, MAX_BYTES};
    private static final int[] CLASS_COUNTS = {3_600, 320, 70, 10};

    @Test
    @Timeout(180)
    @DisplayName("NFR-002: added scrub latency stays inside budget across the full scrub boundary")
    void testAddedLatencyAcrossScrubBoundary() throws Exception {
        DlpScrubber scrubber = DlpScrubber.getInstance();
        byte[][] payloads = {
                payload(SMALL_BYTES, 1),
                payload(MEDIUM_BYTES, 101),
                payload(LARGE_BYTES, 1_009),
                payload(MAX_BYTES, 9_973),
        };
        int[] plan = admissionPlan();

        warmUp(scrubber, payloads);

        long[] admitted = new long[REQUESTS];
        long[] scanStarted = new long[REQUESTS];
        long[] sanitizedAt = new long[REQUESTS];
        boolean[] served = new boolean[REQUESTS];
        int[] classOf = new int[REQUESTS];
        AtomicInteger dropped = new AtomicInteger();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        CountDownLatch settled = new CountDownLatch(REQUESTS);

        // Same dispatch shape as the shipped DlpOutboundHandler: one virtual thread per response,
        // so the wait this harness measures is the wait the gateway pays.
        ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        Thread admissions = new Thread(
                () -> admitAll(scrubber, payloads, plan, admitted, scanStarted, sanitizedAt, served,
                        classOf, dropped, failure, settled, workers),
                "nfr-002-admission");
        admissions.setDaemon(true);

        long runStarted = System.nanoTime();
        admissions.start();
        assertTrue(settled.await(120, TimeUnit.SECONDS),
                "The NFR-002 run did not settle: " + settled.getCount()
                        + " of " + REQUESTS + " responses are still in the scrub boundary after 120 s");
        admissions.join(TimeUnit.SECONDS.toMillis(10));
        workers.shutdownNow();
        long runMicros = (System.nanoTime() - runStarted) / 1_000;

        if (failure.get() != null) {
            throw new AssertionError("The scrub boundary failed under load", failure.get());
        }

        int servedCount = 0;
        for (boolean responseServed : served) {
            if (responseServed) {
                servedCount++;
            }
        }
        assertEquals(0, dropped.get(),
                "No admitted response may be dropped or rejected at the scrub boundary: "
                        + dropped.get() + " of " + REQUESTS + " were dropped");
        assertEquals(REQUESTS, servedCount,
                "Every admitted response must come back with a sanitized body (" + BOUNDARY + "): "
                        + servedCount + " of " + REQUESTS + " were served");

        assertTrue(admitted[REQUESTS - 1] > admitted[0],
                "The run admitted its responses at distinct instants");
        double offeredRps = (REQUESTS - 1) / ((admitted[REQUESTS - 1] - admitted[0]) / 1e9);
        double floorRps = TARGET_RPS * (1.0 - OFFERED_RATE_TOLERANCE);
        assertTrue(offeredRps >= floorRps,
                "The run must offer NFR-002's 2,000 responses/s on one node: 4,000 responses were "
                        + "admitted at " + String.format("%.1f", offeredRps)
                        + "/s, below the " + String.format("%.1f", floorRps)
                        + "/s floor (2,000/s less a 1% pacer allowance)");

        for (int index = 0; index < CLASS_COUNTS.length; index++) {
            int count = 0;
            for (int responseClass : classOf) {
                if (responseClass == index) {
                    count++;
                }
            }
            assertEquals(CLASS_COUNTS[index], count,
                    "The run must admit NFR-002's declared size mix: the " + CLASS_BYTES[index]
                            + " B class carried " + count + " responses, not " + CLASS_COUNTS[index]);
        }

        long[] latencies = new long[REQUESTS];
        for (int i = 0; i < REQUESTS; i++) {
            latencies[i] = sanitizedAt[i] - admitted[i];
        }
        double p50 = percentileMs(latencies, 0.50);
        double p95 = percentileMs(latencies, 0.95);
        double p99 = percentileMs(latencies, 0.99);

        double[] dispatch = new double[REQUESTS];
        double[] scan = new double[REQUESTS];
        for (int i = 0; i < REQUESTS; i++) {
            dispatch[i] = (scanStarted[i] - admitted[i]) / 1e6;
            scan[i] = (sanitizedAt[i] - scanStarted[i]) / 1e6;
        }

        System.out.printf(
                "NFR-002 scrub boundary run: %d responses at %.1f/s offered (target %d/s), "
                        + "%d served, %d dropped, wall %.3fs%n",
                REQUESTS, offeredRps, TARGET_RPS, servedCount, dropped.get(),
                runMicros / 1e6);
        System.out.printf(
                "NFR-002 added latency, %s: p50=%.3f ms p95=%.3f ms p99=%.3f ms "
                        + "(budgets %.1f / %.1f / %.1f ms)%n",
                BOUNDARY, p50, p95, p99, P50_BUDGET_MS, P95_BUDGET_MS, P99_BUDGET_MS);
        System.out.printf(
                "NFR-002 boundary split: dispatch p50=%.3f p99=%.3f ms, scrub p50=%.3f p99=%.3f ms%n",
                percentileMsOf(dispatch, 0.50), percentileMsOf(dispatch, 0.99),
                percentileMsOf(scan, 0.50), percentileMsOf(scan, 0.99));
        reportPerClass(latencies, classOf);

        logger.info("NFR-002 full-boundary run: {} responses at {} rps; p50={} ms p95={} ms p99={} ms",
                REQUESTS, TARGET_RPS, p50, p95, p99);

        assertTrue(p50 <= P50_BUDGET_MS, () -> String.format(
                "NFR-002 p50 %.3f ms exceeds the %.1f ms budget over %d responses (%s)",
                p50, P50_BUDGET_MS, REQUESTS, BOUNDARY));
        assertTrue(p95 <= P95_BUDGET_MS, () -> String.format(
                "NFR-002 p95 %.3f ms exceeds the %.1f ms budget over %d responses (%s)",
                p95, P95_BUDGET_MS, REQUESTS, BOUNDARY));
        assertTrue(p99 <= P99_BUDGET_MS, () -> String.format(
                "NFR-002 p99 %.3f ms exceeds the %.1f ms budget over %d responses (%s)",
                p99, P99_BUDGET_MS, REQUESTS, BOUNDARY));
    }

    @Test
    @DisplayName("NFR-002: the 1 MB ceiling class is scrubbed, not merely fast")
    void testCeilingPayloadIsScrubbed() {
        DlpScrubber scrubber = DlpScrubber.getInstance();
        byte[] maximum = payload(MAX_BYTES, 9_973);
        assertTrue(maximum.length >= MAX_BYTES);

        byte[] scrubbed = scrubber.scrub(maximum);
        String body = new String(scrubbed, StandardCharsets.UTF_8);

        assertFalse(body.contains("AKIAIOSFODNN7EXAMPLE"),
                "A credential must not survive the 1 MB class");
        assertFalse(body.contains("admin@corp.net"),
                "Personal data must not survive the 1 MB class");
        assertTrue(body.contains("[REDACTED_SECRET:AWS_KEY]"));
        assertTrue(body.contains("[REDACTED_PII:EMAIL]"));
    }

    /**
     * Offers the declared mix at NFR-002's rate on one node. Each response is admitted 500 µs after
     * the previous one, and its sanitized body is produced on a worker; the admission instant is
     * recorded before dispatch so the worker-dispatch wait is part of the measured interval.
     */
    private static void admitAll(
            DlpScrubber scrubber,
            byte[][] payloads,
            int[] plan,
            long[] admitted,
            long[] scanStarted,
            long[] sanitizedAt,
            boolean[] served,
            int[] classOf,
            AtomicInteger dropped,
            AtomicReference<Throwable> failure,
            CountDownLatch settled,
            ExecutorService workers) {
        long intervalNanos = 1_000_000_000L / TARGET_RPS;
        long start = System.nanoTime() + 50_000_000L;
        try {
            for (int index = 0; index < REQUESTS; index++) {
                long due = start + index * intervalNanos;
                long now = System.nanoTime();
                long wait = due - now;
                if (wait > 200_000L) {
                    // Park for the bulk of the wait, then spin the last fraction so the admission
                    // instants stay on the 500 µs grid; parkNanos alone is too coarse for it.
                    LockSupport.parkNanos(wait - 150_000L);
                }
                while (System.nanoTime() < due) {
                    Thread.onSpinWait();
                }

                int responseClass = plan[index];
                byte[] body = payloads[responseClass];
                classOf[index] = responseClass;
                admitted[index] = System.nanoTime();
                int slot = index;
                try {
                    workers.execute(() -> {
                        try {
                            scanStarted[slot] = System.nanoTime();
                            DlpScrubResult<byte[]> result = scrubber.scrubWithReport(body);
                            byte[] sanitized = result.payload();
                            sanitizedAt[slot] = System.nanoTime();
                            served[slot] = sanitized != null && sanitized.length > 0;
                        } catch (Throwable t) {
                            failure.compareAndSet(null, t);
                        } finally {
                            settled.countDown();
                        }
                    });
                } catch (RejectedExecutionException e) {
                    dropped.incrementAndGet();
                    settled.countDown();
                }
            }
        } catch (Throwable t) {
            failure.compareAndSet(null, t);
            while (settled.getCount() > 0) {
                settled.countDown();
            }
        }
    }

    /** Runs the walk over every class so the measurement does not include first-use compilation. */
    private static void warmUp(DlpScrubber scrubber, byte[][] payloads) {
        for (int round = 0; round < 200; round++) {
            scrubber.scrub(payloads[round % 4]);
        }
        for (int round = 0; round < 20; round++) {
            scrubber.scrub(payloads[3]);
        }
    }

    /**
     * The declared mix spread across the run: 3,600 / 320 / 70 / 10, shuffled with a fixed seed so
     * every run measures the same sequence and no class arrives in a single batch.
     */
    private static int[] admissionPlan() {
        int[] plan = new int[REQUESTS];
        int cursor = 0;
        for (int responseClass = 0; responseClass < CLASS_COUNTS.length; responseClass++) {
            for (int count = 0; count < CLASS_COUNTS[responseClass]; count++) {
                plan[cursor++] = responseClass;
            }
        }
        Random spread = new Random(20261124L);
        for (int i = plan.length - 1; i > 0; i--) {
            int j = spread.nextInt(i + 1);
            int swap = plan[i];
            plan[i] = plan[j];
            plan[j] = swap;
        }
        return plan;
    }

    private static void reportPerClass(long[] latencies, int[] classOf) {
        for (int responseClass = 0; responseClass < CLASS_BYTES.length; responseClass++) {
            int count = 0;
            long[] samples = new long[REQUESTS];
            for (int i = 0; i < latencies.length; i++) {
                if (classOf[i] == responseClass) {
                    samples[count++] = latencies[i];
                }
            }
            long[] sorted = Arrays.copyOf(samples, count);
            System.out.printf(
                    "NFR-002 %7d B class: n=%4d (%.2f%%) p50=%.3f ms p95=%.3f ms p99=%.3f ms%n",
                    CLASS_BYTES[responseClass], count, 100.0 * count / REQUESTS,
                    percentileMs(sorted, 0.50), percentileMs(sorted, 0.95),
                    percentileMs(sorted, 0.99));
        }
    }

    private static double percentileMs(long[] values, double percentile) {
        if (values.length == 0) {
            return Double.NaN;
        }
        long[] sorted = Arrays.copyOf(values, values.length);
        Arrays.sort(sorted);
        int index = (int) Math.ceil(sorted.length * percentile) - 1;
        return sorted[Math.max(0, Math.min(index, sorted.length - 1))] / 1e6;
    }

    private static double percentileMsOf(double[] values, double percentile) {
        if (values.length == 0) {
            return Double.NaN;
        }
        double[] sorted = Arrays.copyOf(values, values.length);
        Arrays.sort(sorted);
        int index = (int) Math.ceil(sorted.length * percentile) - 1;
        return sorted[Math.max(0, Math.min(index, sorted.length - 1))];
    }

    /**
     * Builds a JSON tool response of roughly {@code bytes} characters with a credential and a
     * personal address near the end, so a scanner that only inspects a prefix fails visibly.
     */
    private static byte[] payload(int bytes, int records) {
        StringBuilder sb = new StringBuilder(bytes + 256);
        sb.append("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"records\":[");
        String template = "{\"id\":%d,\"status\":\"active\",\"data\":\"Standard MCP agent tool output buffer with operation log entry.\"},";
        int i = 0;
        while (sb.length() < bytes) {
            sb.append(String.format(template, i));
            i++;
        }
        sb.append("{\"id\":").append(records)
                .append(",\"note\":\"AWS key AKIAIOSFODNN7EXAMPLE and contact admin@corp.net\"}");
        sb.append("]}}");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }
}
