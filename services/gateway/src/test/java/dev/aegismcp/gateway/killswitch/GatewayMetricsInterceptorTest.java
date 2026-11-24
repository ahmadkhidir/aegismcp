package dev.aegismcp.gateway.killswitch;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests verifying that the C-009 and C-010 fleet counters are fed by the terminal outcome of
 * each intercepted tool call, and that no call is counted twice.
 *
 * <p>Anchors: FEAT-008, FEAT-010, C-009, C-010, C-020.
 */
class GatewayMetricsInterceptorTest {

    private GatewayMetrics metrics;
    private JsonRpcRequest toolCall;

    @BeforeEach
    void setUp() {
        metrics = new GatewayMetrics();
        ObjectNode params = JsonNodeFactory.instance.objectNode();
        params.put("name", "filesystem:read");
        params.set("arguments", JsonNodeFactory.instance.objectNode());
        toolCall = new JsonRpcRequest(JsonRpcId.of(1), JsonRpcRequest.METHOD_TOOLS_CALL, params);
    }

    private SecurityContext context() {
        return new SecurityContext("req-1",
                new AgentIdentity("agent-alpha", "spiffe://aegismcp.dev/agent/agent-alpha", "token", true),
                new InetSocketAddress("127.0.0.1", 54321), Instant.now());
    }

    @Test
    @DisplayName("C-009 / C-010: an allowed tool call increments the request and tool-call counters once")
    void countsAnAllowedToolCall() {
        ToolCallInterceptor chain = new GatewayMetricsInterceptor(
                (context, request) -> CompletableFuture.completedFuture(InterceptionVerdict.allow()), metrics);

        assertInstanceOf(InterceptionVerdict.Allow.class, chain.intercept(context(), toolCall).join());

        assertEquals(1, metrics.getTotalRequests24h());
        assertEquals(1, metrics.getToolCalls24h());
        assertEquals(0, metrics.getBlockedViolations24h());
        assertEquals(1, metrics.buildTimeseries().buckets().get(23).toolCalls());
    }

    @Test
    @DisplayName("C-010: a refused tool call is counted as one blocked violation, not two")
    void countsABlockedToolCallOnce() {
        ToolCallInterceptor chain = new GatewayMetricsInterceptor(
                (context, request) -> CompletableFuture.completedFuture(
                        InterceptionVerdict.block(JsonRpcError.policyViolation("quarantined"))), metrics);

        assertInstanceOf(InterceptionVerdict.Block.class, chain.intercept(context(), toolCall).join());

        assertEquals(1, metrics.getToolCalls24h());
        assertEquals(1, metrics.getBlockedViolations24h());
        assertEquals(1, metrics.buildTimeseries().buckets().get(23).blockedViolations());
    }

    @Test
    @DisplayName("C-010: a stage that throws is a fail-closed refusal and is counted as blocked")
    void countsAThrownStageAsBlocked() {
        ToolCallInterceptor chain = new GatewayMetricsInterceptor(
                (context, request) -> {
                    throw new IllegalStateException("stage failed");
                }, metrics);

        assertThrows(IllegalStateException.class, () -> chain.intercept(context(), toolCall));

        assertEquals(1, metrics.getToolCalls24h());
        assertEquals(1, metrics.getBlockedViolations24h());
    }

    @Test
    @DisplayName("C-009: non-tool JSON-RPC requests are not counted as intercepted tool calls")
    void ignoresNonToolCalls() {
        ToolCallInterceptor chain = new GatewayMetricsInterceptor(
                (context, request) -> CompletableFuture.completedFuture(InterceptionVerdict.allow()), metrics);
        JsonRpcRequest listRequest = new JsonRpcRequest(JsonRpcId.of(2), "tools/list", null);

        chain.intercept(context(), listRequest).join();

        assertEquals(0, metrics.getTotalRequests24h());
        assertEquals(0, metrics.getToolCalls24h());
        assertEquals(0, metrics.getBlockedViolations24h());
    }
}
