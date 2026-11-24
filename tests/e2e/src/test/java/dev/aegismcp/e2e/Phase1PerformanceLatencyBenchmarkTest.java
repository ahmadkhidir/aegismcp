package dev.aegismcp.e2e;

import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * NFR-001 added-latency benchmark against the launched artifact.
 *
 * <p>Added latency is the proxy round-trip minus the direct-upstream round-trip for the same payload,
 * host, and client, measured after warm-up. The percentiles and their thresholds are the NFR-001
 * row: 0.8 ms p50, 2.2 ms p95, 4.8 ms p99. Every sample and every failing case is reported; nothing
 * is discarded or retried.
 */
class Phase1PerformanceLatencyBenchmarkTest extends ArtifactTest {

    private static final int WARM_UP_SAMPLES = 100;
    private static final int SAMPLES = 400;

    private static final double P50_LIMIT_MS = 0.8;  // NFR-001
    private static final double P95_LIMIT_MS = 2.2;  // NFR-001
    private static final double P99_LIMIT_MS = 4.8;  // NFR-001

    @Test
    @DisplayName("NFR-001: reports added p50/p95/p99 latency against a direct-upstream baseline")
    void reportsAddedLatency() throws Exception {
        // Both legs are plaintext so the reported delta is the proxy stage, not TLS termination.
        try (GatewayHarness harness = start(
                dev.aegismcp.e2e.fixtures.GatewayOptions.defaults().tlsEnabled(false))) {
            benchmark(harness);
        }
    }

    private void benchmark(GatewayHarness harness) throws Exception {
        String payload = GatewayHarness.toolCall("bench", "echo", "{\"message\":\"nfr-001\"}");
        URI upstream = URI.create(harness.upstream().url());
        URI proxy = URI.create(harness.url("/mcp/v1/rpc"));
        var client = harness.anonymousClient();

        // One agent identity per sample so the behavioural burst rule, which is not part of the
        // NFR-001 measurement, cannot quarantine the benchmark session mid-run.
        String[] tokens = new String[WARM_UP_SAMPLES + SAMPLES];
        for (int i = 0; i < tokens.length; i++) {
            tokens[i] = harness.agentToken("benchmark-agent-" + i);
        }

        for (int i = 0; i < WARM_UP_SAMPLES; i++) {
            direct(client, upstream, payload);
            proxied(client, proxy, tokens[i], payload);
        }

        double[] added = new double[SAMPLES];
        List<Integer> failures = new ArrayList<>();
        for (int i = 0; i < SAMPLES; i++) {
            long directStart = System.nanoTime();
            direct(client, upstream, payload);
            long directMicros = (System.nanoTime() - directStart) / 1_000;

            long proxyStart = System.nanoTime();
            proxied(client, proxy, tokens[WARM_UP_SAMPLES + i], payload);
            long proxyMicros = (System.nanoTime() - proxyStart) / 1_000;

            added[i] = (proxyMicros - directMicros) / 1_000.0;
            if (added[i] < 0) {
                added[i] = 0;
            }
        }

        double[] sorted = added.clone();
        Arrays.sort(sorted);
        double p50 = percentile(sorted, 0.50);
        double p95 = percentile(sorted, 0.95);
        double p99 = percentile(sorted, 0.99);
        for (int i = 0; i < sorted.length; i++) {
            if (sorted[i] > P99_LIMIT_MS) {
                failures.add(i);
            }
        }

        System.out.printf(
                "NFR-001 added latency: samples=%d p50=%.3fms p95=%.3fms p99=%.3fms "
                        + "(limits %.1f/%.1f/%.1fms) failing=%d%n",
                SAMPLES, p50, p95, p99, P50_LIMIT_MS, P95_LIMIT_MS, P99_LIMIT_MS, failures.size());

        assertTrue(p50 <= P50_LIMIT_MS,
                () -> "NFR-001 p50 " + p50 + "ms exceeds " + P50_LIMIT_MS + "ms over " + SAMPLES + " samples");
        assertTrue(p95 <= P95_LIMIT_MS,
                () -> "NFR-001 p95 " + p95 + "ms exceeds " + P95_LIMIT_MS + "ms over " + SAMPLES + " samples");
        assertTrue(p99 <= P99_LIMIT_MS,
                () -> "NFR-001 p99 " + p99 + "ms exceeds " + P99_LIMIT_MS + "ms over " + SAMPLES
                        + " samples; failing samples: " + failures);
    }

    private static void direct(java.net.http.HttpClient client, URI uri, String payload) throws Exception {
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Direct upstream answered " + response.statusCode());
        }
    }

    private static void proxied(java.net.http.HttpClient client, URI uri, String token, String payload)
            throws Exception {
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Gateway answered " + response.statusCode() + ": " + response.body());
        }
    }

    private static double percentile(double[] sorted, double quantile) {
        if (sorted.length == 0) {
            return Double.NaN;
        }
        int index = (int) Math.ceil(quantile * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(index, sorted.length - 1))];
    }
}
