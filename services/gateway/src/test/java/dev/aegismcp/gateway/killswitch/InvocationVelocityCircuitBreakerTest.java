package dev.aegismcp.gateway.killswitch;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying sliding-window invocation velocity tracking and automatic circuit breaker trips.
 * Anchors: FEAT-010, C-001.
 */
class InvocationVelocityCircuitBreakerTest {

    private KillSwitchManager killSwitchManager;
    private GatewayMetrics metrics;
    private InvocationVelocityCircuitBreaker circuitBreaker;

    @BeforeEach
    void setUp() {
        killSwitchManager = new KillSwitchManager();
        metrics = new GatewayMetrics();
        // Lower threshold for fast testing: 5 calls in 10 seconds
        circuitBreaker = new InvocationVelocityCircuitBreaker(killSwitchManager, 5, Duration.ofSeconds(10), metrics);
    }

    private SecurityContext createSecurityContext(String agentId, Instant timestamp) {
        AgentIdentity identity = new AgentIdentity(agentId, "spiffe://aegismcp.dev/agent/" + agentId, "token-xyz", true);
        return new SecurityContext("req-" + System.nanoTime(), identity, new InetSocketAddress("127.0.0.1", 12345), timestamp);
    }

    private JsonRpcRequest createToolCall(String toolName) {
        ObjectNode params = JsonNodeFactory.instance.objectNode();
        params.put("name", toolName);
        params.set("arguments", JsonNodeFactory.instance.objectNode());
        return new JsonRpcRequest(JsonRpcId.of(1), JsonRpcRequest.METHOD_TOOLS_CALL, params);
    }

    @Test
    @DisplayName("FEAT-010: Normal invocation rate below threshold passes through cleanly")
    void testNormalInvocationRateAllowed() throws Exception {
        Instant now = Instant.now();
        SecurityContext ctx = createSecurityContext("benign-agent", now);
        JsonRpcRequest req = createToolCall("safe:calc");

        for (int i = 0; i < 5; i++) {
            InterceptionVerdict verdict = circuitBreaker.intercept(ctx, req).get();
            assertInstanceOf(InterceptionVerdict.Allow.class, verdict);
        }

        assertEquals(5, circuitBreaker.getInvocationCount("benign-agent", now));
        assertFalse(killSwitchManager.isAgentQuarantined("benign-agent"));
    }

    @Test
    @DisplayName("FEAT-010: Rapid tool burst exceeding threshold trips circuit breaker and auto-quarantines rogue agent")
    void testRapidBurstTripsCircuitBreakerAndQuarantines() throws Exception {
        Instant now = Instant.now();
        SecurityContext ctx = createSecurityContext("looping-agent", now);
        JsonRpcRequest req = createToolCall("fetch:data");

        // First 5 invocations are allowed
        for (int i = 0; i < 5; i++) {
            InterceptionVerdict verdict = circuitBreaker.intercept(ctx, req).get();
            assertInstanceOf(InterceptionVerdict.Allow.class, verdict);
        }

        // 6th invocation breaches threshold (> 5 calls in 10s)
        InterceptionVerdict tripVerdict = circuitBreaker.intercept(ctx, req).get();
        assertInstanceOf(InterceptionVerdict.Block.class, tripVerdict);
        InterceptionVerdict.Block block = (InterceptionVerdict.Block) tripVerdict;
        assertEquals(-32001, block.error().code());
        assertTrue(block.error().message().contains("circuit breaker tripped"));

        // Agent is now quarantined in KillSwitchManager
        assertTrue(killSwitchManager.isAgentQuarantined("looping-agent"));
        assertEquals(1, metrics.getBlockedViolations24h());

        // Subsequent call is blocked immediately by quarantine check
        InterceptionVerdict subVerdict = circuitBreaker.intercept(ctx, req).get();
        assertInstanceOf(InterceptionVerdict.Block.class, subVerdict);
        assertTrue(((InterceptionVerdict.Block) subVerdict).error().message().contains("is quarantined"));
    }

    @Test
    @DisplayName("FEAT-010: Default configuration supports > 100 tool calls in 10s per specification")
    void testDefaultThresholdConfiguration() {
        InvocationVelocityCircuitBreaker defaultBreaker = new InvocationVelocityCircuitBreaker(killSwitchManager);
        assertEquals(100, defaultBreaker.getMaxCallsThreshold());
        assertEquals(Duration.ofSeconds(10), defaultBreaker.getWindowDuration());

        Instant now = Instant.now();
        String agent = "spec-bot";

        // 100 calls do not trip
        for (int i = 0; i < 100; i++) {
            boolean tripped = defaultBreaker.recordInvocation(agent, now.plusMillis(i * 10));
            assertFalse(tripped);
        }
        assertFalse(killSwitchManager.isAgentQuarantined(agent));

        // 101st call trips
        boolean tripped = defaultBreaker.recordInvocation(agent, now.plusMillis(1010));
        assertTrue(tripped);
        assertTrue(killSwitchManager.isAgentQuarantined(agent));
    }

    @Test
    @DisplayName("FEAT-010: Other benign agents continue executing while rogue agent is quarantined")
    void testBenignAgentUnaffectedByRogueAgentQuarantine() throws Exception {
        Instant now = Instant.now();
        SecurityContext rogueCtx = createSecurityContext("rogue-agent", now);
        SecurityContext benignCtx = createSecurityContext("good-agent", now);
        JsonRpcRequest req = createToolCall("test:tool");

        // Trip breaker for rogue agent
        for (int i = 0; i < 6; i++) {
            circuitBreaker.intercept(rogueCtx, req).get();
        }
        assertTrue(killSwitchManager.isAgentQuarantined("rogue-agent"));

        // Good agent can still execute tool calls
        InterceptionVerdict verdict = circuitBreaker.intercept(benignCtx, req).get();
        assertInstanceOf(InterceptionVerdict.Allow.class, verdict);
        assertFalse(killSwitchManager.isAgentQuarantined("good-agent"));
    }

    @Test
    @DisplayName("FEAT-010: Non-tool calls bypass velocity counting")
    void testNonToolCallsBypass() throws Exception {
        Instant now = Instant.now();
        SecurityContext ctx = createSecurityContext("agent-bypass", now);
        JsonRpcRequest listReq = new JsonRpcRequest(JsonRpcId.of(1), "tools/list", null);

        for (int i = 0; i < 20; i++) {
            InterceptionVerdict verdict = circuitBreaker.intercept(ctx, listReq).get();
            assertInstanceOf(InterceptionVerdict.Allow.class, verdict);
        }

        assertEquals(0, circuitBreaker.getInvocationCount("agent-bypass", now));
        assertFalse(killSwitchManager.isAgentQuarantined("agent-bypass"));
    }

    @Test
    @DisplayName("FEAT-010: Sliding window expires timestamps older than window duration")
    void testWindowExpiration() {
        Instant t0 = Instant.parse("2026-10-21T10:00:00Z");
        String agent = "time-travel-agent";

        // Record 4 calls at t0
        for (int i = 0; i < 4; i++) {
            circuitBreaker.recordInvocation(agent, t0);
        }
        assertEquals(4, circuitBreaker.getInvocationCount(agent, t0));

        // Advance by 15 seconds (exceeding 10s window)
        Instant t1 = t0.plusSeconds(15);
        circuitBreaker.recordInvocation(agent, t1);

        // Older 4 calls are expired; only the 1 call remains
        assertEquals(1, circuitBreaker.getInvocationCount(agent, t1));
        assertFalse(killSwitchManager.isAgentQuarantined(agent));
    }

    @Test
    @DisplayName("FEAT-010: Reset clears invocation count")
    void testResetClearsWindow() {
        Instant now = Instant.now();
        String agent = "reset-agent";

        circuitBreaker.recordInvocation(agent, now);
        assertEquals(1, circuitBreaker.getInvocationCount(agent, now));

        circuitBreaker.reset(agent);
        assertEquals(0, circuitBreaker.getInvocationCount(agent, now));
    }
}
