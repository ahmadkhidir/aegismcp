package dev.aegismcp.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Performance and latency benchmark test suite verifying NFR-001 (sub-5ms P99 proxy overhead).
 * Anchors: NFR-001, FEAT-001, C-001.
 */
class Phase1PerformanceLatencyBenchmarkTest {

    private static final Logger logger = LoggerFactory.getLogger(Phase1PerformanceLatencyBenchmarkTest.class);

    private static final int WARMUP_ITERATIONS = 1_000;
    private static final int BENCHMARK_ITERATIONS = 2_500;
    private static final double NFR_001_P99_THRESHOLD_MS = 5.0;

    private E2EGatewayFixture fixture;
    private HttpClient client;
    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void setUp() throws InterruptedException {
        fixture = new E2EGatewayFixture();
        client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    @AfterEach
    void tearDown() {
        if (fixture != null) {
            fixture.close();
        }
    }

    @Test
    @DisplayName("NFR-001: Proxy pipeline P99 latency overhead < 5ms under warm load")
    void testProxyPipelineP99LatencyUnderWarmLoad() throws Exception {
        URI rpcUri = URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc");

        String payload = """
                {
                  "jsonrpc": "2.0",
                  "id": 1,
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"test": "benchmark", "timestamp": 123456789}
                  }
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(rpcUri)
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer agent-bench-token")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

        // Prime pipeline with warm-up requests to ensure JIT tier-4 optimization and socket pooling
        logger.info("Executing {} warm-up iterations...", WARMUP_ITERATIONS);
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            HttpResponse<String> resp = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, resp.statusCode());
        }

        logger.info("Warm-up complete. Executing {} benchmark iterations...", BENCHMARK_ITERATIONS);

        long[] latenciesNanos = new long[BENCHMARK_ITERATIONS];

        for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
            long start = System.nanoTime();
            HttpResponse<String> resp = client.send(request, HttpResponse.BodyHandlers.ofString());
            long elapsed = System.nanoTime() - start;

            latenciesNanos[i] = elapsed;
            assertEquals(200, resp.statusCode());
        }

        // Calculate and log latency percentiles
        Arrays.sort(latenciesNanos);

        double minMs = latenciesNanos[0] / 1_000_000.0;
        double p50Ms = latenciesNanos[(int) (BENCHMARK_ITERATIONS * 0.50)] / 1_000_000.0;
        double p90Ms = latenciesNanos[(int) (BENCHMARK_ITERATIONS * 0.90)] / 1_000_000.0;
        double p95Ms = latenciesNanos[(int) (BENCHMARK_ITERATIONS * 0.95)] / 1_000_000.0;
        double p99Ms = latenciesNanos[(int) (BENCHMARK_ITERATIONS * 0.99)] / 1_000_000.0;
        double maxMs = latenciesNanos[BENCHMARK_ITERATIONS - 1] / 1_000_000.0;

        logger.info("=== AegisMCP NFR-001 Proxy Latency Benchmark Results ===");
        logger.info("Samples:     {}", BENCHMARK_ITERATIONS);
        logger.info("Min:         {%.3f} ms", minMs);
        logger.info("P50 Median:  {%.3f} ms", p50Ms);
        logger.info("P90:         {%.3f} ms", p90Ms);
        logger.info("P95:         {%.3f} ms", p95Ms);
        logger.info("P99:         {%.3f} ms (SLA Target: < 5.0ms)", p99Ms);
        logger.info("Max:         {%.3f} ms", maxMs);
        logger.info("=========================================================");

        System.out.printf("AegisMCP Proxy Latency Benchmark - Min: %.3f ms | P50: %.3f ms | P90: %.3f ms | P95: %.3f ms | P99: %.3f ms | Max: %.3f ms%n",
                minMs, p50Ms, p90Ms, p95Ms, p99Ms, maxMs);

        assertTrue(p99Ms < NFR_001_P99_THRESHOLD_MS,
                String.format("NFR-001 Violation: P99 latency overhead must be under %.1f ms, actual: %.3f ms",
                        NFR_001_P99_THRESHOLD_MS, p99Ms));
    }
}
