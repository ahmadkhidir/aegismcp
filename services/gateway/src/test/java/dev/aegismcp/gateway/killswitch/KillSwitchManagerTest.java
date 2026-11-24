package dev.aegismcp.gateway.killswitch;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying multi-granularity emergency kill-switch quarantine and lockdown enforcement.
 * Anchors: FEAT-010, C-001, C-008.
 */
class KillSwitchManagerTest {

    private KillSwitchManager killSwitchManager;
    private ToolCallInterceptor interceptor;

    @BeforeEach
    void setUp() {
        killSwitchManager = new KillSwitchManager();
        interceptor = killSwitchManager.asInterceptor();
    }

    private SecurityContext createSecurityContext(String agentId) {
        AgentIdentity identity = new AgentIdentity(agentId, "spiffe://aegismcp.dev/agent/" + agentId, "token-123", true);
        return new SecurityContext("req-1", identity, new InetSocketAddress("127.0.0.1", 54321), Instant.now());
    }

    private JsonRpcRequest createToolCall(String toolName) {
        ObjectNode params = JsonNodeFactory.instance.objectNode();
        params.put("name", toolName);
        params.set("arguments", JsonNodeFactory.instance.objectNode().put("path", "/tmp/test"));
        return new JsonRpcRequest(JsonRpcId.of(1), JsonRpcRequest.METHOD_TOOLS_CALL, params);
    }

    @Test
    @DisplayName("FEAT-010 / C-008: Global lockdown blocks all incoming tool calls")
    void testGlobalLockdownBlocksAllToolCalls() throws Exception {
        assertFalse(killSwitchManager.isGlobalLockdown());

        SecurityContext ctx = createSecurityContext("agent-alpha");
        JsonRpcRequest req = createToolCall("filesystem:read");

        // Allowed before lockdown
        CompletableFuture<InterceptionVerdict> verdictFuture = interceptor.intercept(ctx, req);
        assertInstanceOf(InterceptionVerdict.Allow.class, verdictFuture.get());

        // Activate global lockdown
        QuarantineResult result = killSwitchManager.quarantine(KillTargetType.GLOBAL, "global", "Suspected cluster-wide breach");
        assertEquals(QuarantineStatus.LOCKDOWN, result.status());
        assertTrue(killSwitchManager.isGlobalLockdown());

        // Blocked after lockdown
        CompletableFuture<InterceptionVerdict> blockedFuture = interceptor.intercept(ctx, req);
        InterceptionVerdict verdict = blockedFuture.get();
        assertInstanceOf(InterceptionVerdict.Block.class, verdict);
        InterceptionVerdict.Block block = (InterceptionVerdict.Block) verdict;
        assertEquals(-32001, block.error().code());
        assertTrue(block.error().message().contains("Global emergency lockdown is active"));
    }

    @Test
    @DisplayName("FEAT-010 / C-008: Global lockdown severs active transport channels")
    void testGlobalLockdownSeversChannels() {
        EmbeddedChannel ch1 = new EmbeddedChannel();
        EmbeddedChannel ch2 = new EmbeddedChannel();
        assertTrue(ch1.isOpen());
        assertTrue(ch2.isOpen());

        killSwitchManager.registerSession("agent-1", ch1);
        killSwitchManager.registerSession("agent-2", ch2);

        int affected = killSwitchManager.activateGlobalLockdown("Threat containment");
        assertEquals(2, affected);
        assertFalse(ch1.isOpen());
        assertFalse(ch2.isOpen());
    }

    @Test
    @DisplayName("FEAT-010 / C-008: Per-agent quarantine blocks targeted agent while allowing benign agents")
    void testPerAgentQuarantine() throws Exception {
        SecurityContext rogueCtx = createSecurityContext("rogue-bot");
        SecurityContext benignCtx = createSecurityContext("benign-bot");
        JsonRpcRequest req = createToolCall("database:query");

        // Quarantine rogue-bot
        QuarantineResult result = killSwitchManager.quarantine(KillTargetType.AGENT, "rogue-bot", "Exceeded velocity limit");
        assertEquals(QuarantineStatus.QUARANTINED, result.status());
        assertTrue(killSwitchManager.isAgentQuarantined("rogue-bot"));
        assertFalse(killSwitchManager.isAgentQuarantined("benign-bot"));

        // Rogue agent is blocked
        InterceptionVerdict rogueVerdict = interceptor.intercept(rogueCtx, req).get();
        assertInstanceOf(InterceptionVerdict.Block.class, rogueVerdict);
        InterceptionVerdict.Block block = (InterceptionVerdict.Block) rogueVerdict;
        assertEquals(-32001, block.error().code());
        assertTrue(block.error().message().contains("Agent 'rogue-bot' is quarantined"));

        // Benign agent is permitted
        InterceptionVerdict benignVerdict = interceptor.intercept(benignCtx, req).get();
        assertInstanceOf(InterceptionVerdict.Allow.class, benignVerdict);
    }

    @Test
    @DisplayName("FEAT-010 / C-008: Per-agent quarantine severs only targeted agent's sessions")
    void testPerAgentQuarantineSeversSpecificSessions() {
        EmbeddedChannel rogueChannel = new EmbeddedChannel();
        EmbeddedChannel benignChannel = new EmbeddedChannel();

        killSwitchManager.registerSession("rogue-bot", rogueChannel);
        killSwitchManager.registerSession("benign-bot", benignChannel);

        int affected = killSwitchManager.quarantineAgent("rogue-bot", "Rogue process");
        assertEquals(1, affected);
        assertFalse(rogueChannel.isOpen());
        assertTrue(benignChannel.isOpen());

        benignChannel.close();
    }

    @Test
    @DisplayName("FEAT-010 / C-008: Per-tool quarantine blocks target tool across all agents")
    void testPerToolQuarantine() throws Exception {
        SecurityContext ctx = createSecurityContext("agent-1");
        JsonRpcRequest dangerousTool = createToolCall("bash:exec");
        JsonRpcRequest safeTool = createToolCall("docs:search");

        killSwitchManager.quarantine(KillTargetType.TOOL, "bash:exec", "Zero-day vulnerability discovered");
        assertTrue(killSwitchManager.isToolQuarantined("bash:exec"));
        assertFalse(killSwitchManager.isToolQuarantined("docs:search"));

        // Dangerous tool is blocked
        InterceptionVerdict blocked = interceptor.intercept(ctx, dangerousTool).get();
        assertInstanceOf(InterceptionVerdict.Block.class, blocked);
        assertTrue(((InterceptionVerdict.Block) blocked).error().message().contains("Tool 'bash:exec' is quarantined"));

        // Safe tool is permitted
        InterceptionVerdict allowed = interceptor.intercept(ctx, safeTool).get();
        assertInstanceOf(InterceptionVerdict.Allow.class, allowed);
    }

    @Test
    @DisplayName("FEAT-010 / C-008: Server quarantine severs server connections and blocks mapped tools")
    void testServerQuarantine() throws Exception {
        EmbeddedChannel serverChannel = new EmbeddedChannel();
        killSwitchManager.registerSession("agent-1", "mcp-server-postgres", serverChannel);
        killSwitchManager.registerToolServerMapping("pg_query", "mcp-server-postgres");

        SecurityContext ctx = createSecurityContext("agent-1");
        JsonRpcRequest pgTool = createToolCall("pg_query");

        QuarantineResult result = killSwitchManager.quarantine(KillTargetType.SERVER, "mcp-server-postgres", "Upstream server compromised");
        assertEquals(QuarantineStatus.SEVERED, result.status());
        assertEquals(1, result.affectedSessions());
        assertFalse(serverChannel.isOpen());
        assertTrue(killSwitchManager.isServerQuarantined("mcp-server-postgres"));

        // Invocation targeting tool mapped to compromised server is blocked
        InterceptionVerdict verdict = interceptor.intercept(ctx, pgTool).get();
        assertInstanceOf(InterceptionVerdict.Block.class, verdict);
        assertTrue(((InterceptionVerdict.Block) verdict).error().message().contains("Upstream server 'mcp-server-postgres' is severed"));
    }

    @Test
    @DisplayName("FEAT-010: Reset restores normal operations across targets")
    void testResetRestoresOperations() throws Exception {
        SecurityContext ctx = createSecurityContext("agent-test");
        JsonRpcRequest req = createToolCall("tool-test");

        killSwitchManager.quarantineAgent("agent-test", "Testing");
        killSwitchManager.quarantineTool("tool-test", "Testing");
        killSwitchManager.activateGlobalLockdown("Testing");

        assertTrue(killSwitchManager.hasActiveQuarantines());

        // Reset all
        killSwitchManager.resetAll();

        assertFalse(killSwitchManager.isGlobalLockdown());
        assertFalse(killSwitchManager.isAgentQuarantined("agent-test"));
        assertFalse(killSwitchManager.isToolQuarantined("tool-test"));
        assertFalse(killSwitchManager.hasActiveQuarantines());

        // Invocations succeed again
        InterceptionVerdict verdict = interceptor.intercept(ctx, req).get();
        assertInstanceOf(InterceptionVerdict.Allow.class, verdict);
    }

    @Test
    @DisplayName("C-009 / C-010: the attached metrics report live session and agent counts")
    void testAttachedMetricsReportLiveSessionCounts() {
        GatewayMetrics metrics = new GatewayMetrics();
        killSwitchManager.attachMetrics(metrics);

        // Nothing has connected yet: the counters are zero rather than seeded.
        assertEquals(0, metrics.getActiveConnections());
        assertEquals(0, metrics.getActiveAgents());

        EmbeddedChannel first = new EmbeddedChannel();
        EmbeddedChannel second = new EmbeddedChannel();
        EmbeddedChannel third = new EmbeddedChannel();
        killSwitchManager.registerSession("agent-1", first);
        killSwitchManager.registerSession("agent-1", second);
        killSwitchManager.registerSession("agent-2", third);

        assertEquals(3, metrics.getActiveConnections());
        assertEquals(2, metrics.getActiveAgents());

        second.close();
        assertEquals(2, metrics.getActiveConnections());
        assertEquals(2, metrics.getActiveAgents());

        killSwitchManager.quarantineAgent("agent-1", "containment");
        assertEquals(1, metrics.getActiveConnections());
        assertEquals(1, metrics.getActiveAgents());

        third.close();
        assertEquals(0, metrics.getActiveConnections());
        assertEquals(0, metrics.getActiveAgents());
    }

    @Test
    @DisplayName("C-010 / C-008: an alias is addressable but never counted as a second agent")
    void testAgentAliasIsNotCounted() {
        GatewayMetrics metrics = new GatewayMetrics();
        killSwitchManager.attachMetrics(metrics);
        String workloadId = "ns/agents/sa/support-bot";
        String spiffeUri = "spiffe://cluster.local/ns/agents/sa/support-bot";

        EmbeddedChannel first = new EmbeddedChannel();
        killSwitchManager.registerSession(workloadId, first);
        killSwitchManager.registerAgentAlias(spiffeUri, workloadId);

        assertEquals(1, metrics.getActiveConnections());
        assertEquals(1, metrics.getActiveAgents());
        assertTrue(killSwitchManager.hasAgentSession(spiffeUri));

        first.close();
        assertEquals(0, metrics.getActiveConnections());
        assertEquals(0, metrics.getActiveAgents());
        assertFalse(killSwitchManager.hasAgentSession(spiffeUri));

        // A second register/close cycle starts from zero, not from a leaked or doubled count.
        EmbeddedChannel second = new EmbeddedChannel();
        killSwitchManager.registerSession(workloadId, second);
        killSwitchManager.registerAgentAlias(spiffeUri, workloadId);
        assertEquals(1, metrics.getActiveConnections());
        assertEquals(1, metrics.getActiveAgents());

        second.close();
        assertEquals(0, metrics.getActiveConnections());
        assertEquals(0, metrics.getActiveAgents());
    }

    @Test
    @DisplayName("C-010: a channel that re-registers under another identity is counted once")
    void testChannelReassignedToAnotherIdentityIsCountedOnce() {
        GatewayMetrics metrics = new GatewayMetrics();
        killSwitchManager.attachMetrics(metrics);
        EmbeddedChannel channel = new EmbeddedChannel();

        killSwitchManager.registerSession("agent-1", channel);
        assertEquals(1, metrics.getActiveAgents());

        killSwitchManager.registerSession("agent-2", channel);
        assertEquals(1, metrics.getActiveAgents(), "one live channel is one distinct identity");
        assertFalse(killSwitchManager.hasAgentSession("agent-1"));
        assertTrue(killSwitchManager.hasAgentSession("agent-2"));

        channel.close();
        assertEquals(0, metrics.getActiveAgents());
        assertEquals(0, metrics.getActiveConnections());
    }
}
