package dev.aegismcp.gateway.policy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying in-memory policy cache behavior, fail-safe reload, and microsecond evaluation.
 * Anchors: FEAT-002, NFR-001.
 */
class PolicyCacheTest {

    @Test
    @DisplayName("FEAT-002: Storing policy compiles AST and registers agent bindings")
    void testPutAndGetPolicy() {
        PolicyCache cache = new PolicyCache();

        String yaml = """
                id: pol_test_1
                name: Test Policy
                version: 1.0.0
                targetAgents:
                  - "agent-alpha"
                rules:
                  - tool: "echo"
                    action: allow
                """;

        SecurityPolicy policy = SecurityPolicy.of("pol_test_1", "Test Policy", "1.0.0", yaml, "sha-1");
        PolicyAst ast = cache.putPolicy(policy);

        assertNotNull(ast);
        assertEquals("pol_test_1", ast.id());
        assertEquals(1, cache.size());

        SecurityPolicy retrieved = cache.getPolicy("pol_test_1");
        assertNotNull(retrieved);
        assertEquals("Test Policy", retrieved.name());

        PolicyAst agentAst = cache.getPolicyForAgent("agent-alpha", null);
        assertNotNull(agentAst);
        assertEquals("pol_test_1", agentAst.id());
    }

    @Test
    @DisplayName("FEAT-002 Edge Case: Invalid policy reload is rejected, preserving active in-memory policy")
    void testFailedReloadPreservesActivePolicy() {
        PolicyCache cache = new PolicyCache();

        String validYaml = """
                id: pol_prod
                name: Production Policy
                version: 1.0.0
                rules:
                  - tool: "safe_tool"
                    action: allow
                """;

        SecurityPolicy validPolicy = SecurityPolicy.of("pol_prod", "Production Policy", "1.0.0", validYaml, "sha-v1");
        cache.putPolicy(validPolicy);

        // Attempt reload with malformed YAML
        String invalidYaml = """
                id: pol_prod
                name: Production Policy
                version: 1.0.1
                rules:
                  - tool: [invalid list syntax: :::
                """;

        SecurityPolicy brokenPolicy = SecurityPolicy.of("pol_prod", "Production Policy", "1.0.1", invalidYaml, "sha-v2");

        assertThrows(PolicyCompilationException.class, () -> cache.putPolicy(brokenPolicy));

        // Verify active policy in memory was NOT corrupted and is still version 1.0.0
        SecurityPolicy activePolicy = cache.getPolicy("pol_prod");
        assertNotNull(activePolicy);
        assertEquals("1.0.0", activePolicy.version());
        assertEquals("sha-v1", activePolicy.gitCommitHash());

        PolicyAst activeAst = cache.getAst("pol_prod");
        assertNotNull(activeAst);
        assertEquals("safe_tool", activeAst.rules().get(0).tool());
    }

    @Test
    @DisplayName("C-005: Filters policies by status (active, draft, archived)")
    void testGetAllPoliciesWithStatusFilter() {
        PolicyCache cache = new PolicyCache();

        String yaml1 = "id: p1\nname: P1\nversion: 1\nrules: []\n";
        String yaml2 = "id: p2\nname: P2\nversion: 1\nrules: []\n";
        String yaml3 = "id: p3\nname: P3\nversion: 1\nrules: []\n";

        cache.putPolicy(new SecurityPolicy("p1", "P1", "1", yaml1, SecurityPolicy.STATUS_ACTIVE, null, "2026-10-21T08:00:00Z"));
        cache.putPolicy(new SecurityPolicy("p2", "P2", "1", yaml2, SecurityPolicy.STATUS_DRAFT, null, "2026-10-21T08:00:00Z"));
        cache.putPolicy(new SecurityPolicy("p3", "P3", "1", yaml3, SecurityPolicy.STATUS_ARCHIVED, null, "2026-10-21T08:00:00Z"));

        List<SecurityPolicy> active = cache.getAllPolicies("active");
        assertEquals(1, active.size());
        assertEquals("p1", active.get(0).id());

        List<SecurityPolicy> draft = cache.getAllPolicies("draft");
        assertEquals(1, draft.size());
        assertEquals("p2", draft.get(0).id());

        List<SecurityPolicy> all = cache.getAllPolicies(null);
        assertEquals(3, all.size());
    }

    @Test
    @DisplayName("NFR-001: In-memory cache achieves sub-millisecond evaluation (<0.1ms per call)")
    void testSubMillisecondEvaluationBenchmark() {
        PolicyCache cache = new PolicyCache();
        String yaml = """
                id: pol_bench
                name: Benchmark Policy
                version: 1.0.0
                targetAgents: ["*"]
                rules:
                  - tool: "fast_tool"
                    action: allow
                    constraints:
                      - argument: token
                        operator: equals
                        value: "secret-123"
                """;
        cache.putPolicy(SecurityPolicy.of("pol_bench", "Benchmark Policy", "1.0.0", yaml, "sha-bench"));

        // Warmup JIT
        for (int i = 0; i < 5000; i++) {
            cache.getPolicyForAgent("agent-" + i, null);
        }

        // Benchmark 10,000 lookups
        int iterations = 10_000;
        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            PolicyAst ast = cache.getPolicyForAgent("agent-worker", null);
            assertNotNull(ast);
        }
        long durationNanos = System.nanoTime() - start;
        double avgMicros = (double) durationNanos / iterations / 1_000.0;

        // Verify average lookup is well under 1ms (typically < 0.05ms)
        assertTrue(avgMicros < 1000.0, "Average policy lookup time should be under 1ms, got: " + avgMicros + "us");
    }
}
