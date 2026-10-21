package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying Netty proxy pipeline integration via {@link DeclarativePolicyInterceptor}.
 * Anchors: FEAT-001, FEAT-002, C-001, NFR-027.
 */
class DeclarativePolicyInterceptorTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private PolicyCache cache;
    private PolicyEvaluator evaluator;
    private DeclarativePolicyInterceptor interceptor;

    private static final String POLICY_YAML = """
            id: pol_gateway_integration
            name: Gateway Integration Policy
            version: 1.0.0
            targetAgents: ["*"]
            rules:
              - id: rule_read
                tool: file_read
                action: allow
                constraints:
                  - argument: path
                    operator: starts_with
                    value: "/app/data"
              - id: rule_sensitive
                tool: admin_reset
                action: require_approval
            """;

    @BeforeEach
    void setUp() {
        cache = new PolicyCache();
        evaluator = new PolicyEvaluator(cache);
        interceptor = new DeclarativePolicyInterceptor(evaluator);

        cache.putPolicy(SecurityPolicy.of("pol_gateway_integration", "Gateway Integration Policy", "1.0.0", POLICY_YAML, "sha-gw"));
    }

    private SecurityContext createContext(String agentId) {
        return SecurityContext.of(
                AgentIdentity.fromBearer(agentId),
                new InetSocketAddress("10.0.0.1", 54321)
        );
    }

    @Test
    @DisplayName("FEAT-002 / C-001: Authorized tool call yields InterceptionVerdict.Allow")
    void testAuthorizedToolCallYieldsAllow() throws ExecutionException, InterruptedException {
        SecurityContext context = createContext("agent-123");

        ObjectNode params = mapper.createObjectNode();
        params.put("name", "file_read");
        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/app/data/config.json");
        params.set("arguments", args);

        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of("req-1"), JsonRpcRequest.METHOD_TOOLS_CALL, params);

        CompletableFuture<InterceptionVerdict> future = interceptor.intercept(context, request);
        InterceptionVerdict verdict = future.get();

        assertInstanceOf(InterceptionVerdict.Allow.class, verdict);
    }

    @Test
    @DisplayName("FEAT-002 / C-001: Unauthorized tool yields InterceptionVerdict.Block (-32001 Policy Violation)")
    void testUnauthorizedToolYieldsBlock() throws ExecutionException, InterruptedException {
        SecurityContext context = createContext("agent-123");

        ObjectNode params = mapper.createObjectNode();
        params.put("name", "forbidden_tool");

        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of("req-2"), JsonRpcRequest.METHOD_TOOLS_CALL, params);

        CompletableFuture<InterceptionVerdict> future = interceptor.intercept(context, request);
        InterceptionVerdict verdict = future.get();

        assertInstanceOf(InterceptionVerdict.Block.class, verdict);
        InterceptionVerdict.Block block = (InterceptionVerdict.Block) verdict;
        assertEquals(JsonRpcError.POLICY_VIOLATION, block.error().code());
        assertTrue(block.error().message().contains("Policy Violation"));
        assertTrue(block.error().message().contains("is not permitted in policy"));
    }

    @Test
    @DisplayName("FEAT-002: Argument constraint violation yields InterceptionVerdict.Block")
    void testArgumentViolationYieldsBlock() throws ExecutionException, InterruptedException {
        SecurityContext context = createContext("agent-123");

        ObjectNode params = mapper.createObjectNode();
        params.put("name", "file_read");
        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/root/secrets.env"); // Violates /app/data prefix
        params.set("arguments", args);

        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of("req-3"), JsonRpcRequest.METHOD_TOOLS_CALL, params);

        CompletableFuture<InterceptionVerdict> future = interceptor.intercept(context, request);
        InterceptionVerdict verdict = future.get();

        assertInstanceOf(InterceptionVerdict.Block.class, verdict);
        InterceptionVerdict.Block block = (InterceptionVerdict.Block) verdict;
        assertEquals(JsonRpcError.POLICY_VIOLATION, block.error().code());
        assertTrue(block.error().message().contains("Argument constraint violation"));
    }

    @Test
    @DisplayName("FEAT-001: Non-tool call passes through without policy evaluation")
    void testNonToolCallPassesThrough() throws ExecutionException, InterruptedException {
        SecurityContext context = createContext("agent-123");
        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of("ping-1"), "ping", mapper.createObjectNode());

        CompletableFuture<InterceptionVerdict> future = interceptor.intercept(context, request);
        InterceptionVerdict verdict = future.get();

        assertInstanceOf(InterceptionVerdict.Allow.class, verdict);
    }

    @Test
    @DisplayName("FEAT-002 / FEAT-006: Custom ApprovalHandler invoked on REQUIRE_APPROVAL verdict")
    void testApprovalHandlerInvoked() throws ExecutionException, InterruptedException {
        AtomicBoolean approvalInvoked = new AtomicBoolean(false);
        DeclarativePolicyInterceptor customInterceptor = new DeclarativePolicyInterceptor(
                evaluator,
                (ctx, req, res) -> {
                    approvalInvoked.set(true);
                    assertEquals("admin_reset", req.toolName());
                    return CompletableFuture.completedFuture(
                            InterceptionVerdict.block(JsonRpcError.approvalTimedOut("Suspended for HITL"))
                    );
                }
        );

        SecurityContext context = createContext("agent-123");
        ObjectNode params = mapper.createObjectNode();
        params.put("name", "admin_reset");

        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of("req-4"), JsonRpcRequest.METHOD_TOOLS_CALL, params);

        CompletableFuture<InterceptionVerdict> future = customInterceptor.intercept(context, request);
        InterceptionVerdict verdict = future.get();

        assertTrue(approvalInvoked.get());
        assertInstanceOf(InterceptionVerdict.Block.class, verdict);
        assertEquals(JsonRpcError.APPROVAL_TIMED_OUT, ((InterceptionVerdict.Block) verdict).error().code());
    }
}
