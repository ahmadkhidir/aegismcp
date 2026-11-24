package dev.aegismcp.gateway.proxy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import dev.aegismcp.gateway.policy.DeclarativePolicyInterceptor;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyEvaluator;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * C-001 makes {@code tools/call} and {@code resources/read} policy-bearing. These tests pin the
 * resource-read path: it reaches the whole interceptor chain, the chain decides against
 * {@code resources/read} with the resource params as its arguments, the upstream still receives the
 * original {@code resources/read} envelope, and every terminal outcome is audited.
 *
 * <p>Anchors: FEAT-001, FEAT-002, FEAT-004, FEAT-012, C-001, NFR-027.
 */
class McpProxyHandlerPolicyBearingTest {

    private static final String RESOURCE_URI = "file:///workspace/reports/q3.txt";

    private static final String RESOURCE_POLICY = """
            id: pol_resources
            name: Resource Read Policy
            version: 1.0.0
            targetAgents: ["*"]
            rules:
              - id: rule_resource_read
                tool: resources/read
                action: allow
                constraints:
                  - argument: uri
                    operator: starts_with
                    value: "file:///workspace"
            """;

    private static final String APPROVAL_POLICY = """
            id: pol_resources_approval
            name: Resource Read Approval Policy
            version: 1.0.0
            targetAgents: ["*"]
            rules:
              - id: rule_resource_read_approval
                tool: resources/read
                action: require_approval
            """;

    private static final String NO_RESOURCE_POLICY = """
            id: pol_no_resource_rule
            name: Policy Without A Resource Rule
            version: 1.0.0
            targetAgents: ["*"]
            rules:
              - id: rule_echo
                tool: echo
                action: allow
            """;

    private final ObjectMapper mapper = new ObjectMapper();
    private final JsonRpcCodec codec = new JsonRpcCodec();
    private final List<String> audits = new CopyOnWriteArrayList<>();
    private ExecutorService executor;

    @BeforeEach
    void setUp() {
        executor = Executors.newSingleThreadExecutor();
    }

    @AfterEach
    void tearDown() {
        executor.shutdownNow();
    }

    private McpProxyHandler.AuditTrail auditTrail() {
        return (agentId, toolName, decision, latencyMs, summary, argumentsHash, reviewedBy) ->
                audits.add(agentId + "|" + toolName + "|" + decision + "|" + summary);
    }

    private EmbeddedChannel createChannel(ToolCallInterceptor interceptor, UpstreamClient upstream) {
        McpProxyHandler handler = new McpProxyHandler(
                McpProxyHandler.DEFAULT_RPC_PATH,
                codec,
                interceptor,
                upstream,
                executor,
                false,
                auditTrail(),
                false);
        return new EmbeddedChannel(handler);
    }

    private FullHttpResponse sendRequest(EmbeddedChannel channel, String payload) {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                McpProxyHandler.DEFAULT_RPC_PATH,
                Unpooled.wrappedBuffer(payload.getBytes(StandardCharsets.UTF_8)));
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        request.headers().set(HttpHeaderNames.CONTENT_LENGTH, payload.getBytes(StandardCharsets.UTF_8).length);
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Bearer agent-resources");

        channel.writeInbound(request);
        channel.runPendingTasks();

        long deadline = System.currentTimeMillis() + 2_000;
        FullHttpResponse response;
        while (System.currentTimeMillis() < deadline) {
            channel.runPendingTasks();
            response = channel.readOutbound();
            if (response != null) {
                return response;
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return null;
    }

    private static String resourcesRead(String id, String uri) {
        return "{\"jsonrpc\":\"2.0\",\"id\":\"" + id + "\",\"method\":\"resources/read\","
                + "\"params\":{\"uri\":\"" + uri + "\"}}";
    }

    private JsonRpcResponse decode(FullHttpResponse response) {
        byte[] body = new byte[response.content().readableBytes()];
        response.content().readBytes(body);
        return codec.decodeResponse(body);
    }

    private DeclarativePolicyInterceptor policyChain(String policyId, String policyYaml,
                                                     DeclarativePolicyInterceptor.ApprovalHandler approval) {
        PolicyCache cache = new PolicyCache();
        cache.putPolicy(SecurityPolicy.of(policyId, "Resource Read Policy", "1.0.0", policyYaml, "test"));
        return new DeclarativePolicyInterceptor(new PolicyEvaluator(cache), approval);
    }

    @Test
    @DisplayName("C-001 / FEAT-002: an allowed resources/read is decided by policy and forwarded as a resource read")
    void allowedResourcesReadTraversesTheChainAndKeepsItsEnvelope() throws Exception {
        AtomicReference<JsonRpcRequest> chained = new AtomicReference<>();
        ToolCallInterceptor observingAllow = (context, request) -> {
            chained.set(request);
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        };
        AtomicReference<JsonRpcRequest> forwarded = new AtomicReference<>();
        EmbeddedChannel channel = createChannel(observingAllow, (context, request) -> {
            forwarded.set(request);
            ObjectNode result = mapper.createObjectNode();
            result.put("contents", "quarterly numbers");
            return CompletableFuture.completedFuture(JsonRpcResponse.success(request.id(), result));
        });

        FullHttpResponse response = sendRequest(channel, resourcesRead("res-1", RESOURCE_URI));

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());
        JsonRpcResponse rpcResponse = decode(response);
        assertTrue(rpcResponse.isSuccess());
        assertEquals("res-1", ((JsonRpcId.StringId) rpcResponse.id()).stringValue());

        JsonRpcRequest chainRequest = chained.get();
        assertNotNull(chainRequest, "resources/read must reach the interceptor chain");
        assertEquals(JsonRpcRequest.METHOD_TOOLS_CALL, chainRequest.method(),
                "the chain evaluates a tools/call projection");
        assertEquals("resources/read", chainRequest.toolName(), "the policy target is the method name");
        assertEquals(RESOURCE_URI, chainRequest.toolArguments().path("uri").asText(),
                "the resource uri is the constrained argument");

        JsonRpcRequest upstreamRequest = forwarded.get();
        assertNotNull(upstreamRequest, "the upstream receives the resource read");
        assertEquals("resources/read", upstreamRequest.method(),
                "the upstream never receives the tools/call projection");
        assertEquals(RESOURCE_URI, upstreamRequest.params().path("uri").asText());

        assertTrue(audits.stream().anyMatch(a -> a.contains("|resources/read|ALLOWED|status=200")),
                () -> "the allowed resource read is audited: " + audits);
    }

    @Test
    @DisplayName("C-001: a resources/read outside its policy is refused with 403 TOOL_NOT_PERMITTED and audited")
    void blockedResourcesReadReturnsTheContractErrorAndIsAudited() {
        EmbeddedChannel channel = createChannel(
                policyChain("pol_no_resource_rule", NO_RESOURCE_POLICY, null),
                (context, request) -> fail("A blocked resource read must never reach the upstream"));

        // resources/read is policy-bearing but this policy has no rule for it: fail closed.
        FullHttpResponse response = sendRequest(channel, resourcesRead("res-2", RESOURCE_URI));

        assertNotNull(response);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
        JsonRpcResponse rpcResponse = decode(response);
        assertTrue(rpcResponse.isError());
        assertEquals(JsonRpcError.POLICY_VIOLATION, rpcResponse.error().code());
        assertEquals(JsonRpcError.MACHINE_TOOL_NOT_PERMITTED, rpcResponse.error().machineCode());
        assertEquals("res-2", ((JsonRpcId.StringId) rpcResponse.id()).stringValue());

        assertTrue(audits.stream().anyMatch(a -> a.contains("|resources/read|BLOCKED|status=403")),
                () -> "the blocked resource read is audited: " + audits);
    }

    @Test
    @DisplayName("C-001: a resources/read violating its uri constraint is refused with ARGUMENT_CONSTRAINT_VIOLATED")
    void resourcesReadOutsideTheAllowedUriPrefixIsRefused() {
        EmbeddedChannel channel = createChannel(
                policyChain("pol_resources", RESOURCE_POLICY, null),
                (context, request) -> fail("A constrained resource read must never reach the upstream"));

        FullHttpResponse response = sendRequest(channel, resourcesRead("res-3", "file:///etc/shadow"));

        assertNotNull(response);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
        JsonRpcResponse rpcResponse = decode(response);
        assertTrue(rpcResponse.isError());
        assertEquals(JsonRpcError.POLICY_VIOLATION, rpcResponse.error().code());
        assertEquals(JsonRpcError.MACHINE_ARGUMENT_CONSTRAINT_VIOLATED, rpcResponse.error().machineCode());
    }

    @Test
    @DisplayName("C-001 / FEAT-006: an approved resources/read reaches the upstream and is audited")
    void approvedResourcesReadIsForwarded() {
        AtomicReference<JsonRpcRequest> approvalRequest = new AtomicReference<>();
        DeclarativePolicyInterceptor.ApprovalHandler approval = (context, request, result) -> {
            approvalRequest.set(request);
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        };
        AtomicReference<JsonRpcRequest> forwarded = new AtomicReference<>();
        EmbeddedChannel channel = createChannel(policyChain("pol_resources_approval", APPROVAL_POLICY, approval),
                (context, request) -> {
                    forwarded.set(request);
                    ObjectNode result = mapper.createObjectNode();
                    result.put("contents", "quarterly numbers");
                    return CompletableFuture.completedFuture(JsonRpcResponse.success(request.id(), result));
                });

        FullHttpResponse response = sendRequest(channel, resourcesRead("res-4", RESOURCE_URI));

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());
        assertNotNull(approvalRequest.get(), "the policy stage suspends the call for approval");
        assertEquals("resources/read", approvalRequest.get().toolName());
        assertEquals(RESOURCE_URI, approvalRequest.get().toolArguments().path("uri").asText());
        assertEquals("resources/read", forwarded.get().method(),
                "an approved resource read is forwarded as a resource read");
        assertTrue(audits.stream().anyMatch(a -> a.contains("|resources/read|ALLOWED|status=200")),
                () -> "the approved resource read is audited: " + audits);
    }

    @Test
    @DisplayName("C-001: a rejected approval on resources/read returns 403 APPROVAL_DENIED and never forwards")
    void rejectedResourcesReadApprovalIsRefused() {
        DeclarativePolicyInterceptor.ApprovalHandler rejection = (context, request, result) ->
                CompletableFuture.completedFuture(InterceptionVerdict.block(
                        JsonRpcError.policyViolation(JsonRpcError.MACHINE_APPROVAL_DENIED,
                                "A human reviewer rejected the suspended call")));
        EmbeddedChannel channel = createChannel(policyChain("pol_resources_approval", APPROVAL_POLICY, rejection),
                (context, request) -> fail("A rejected resource read must never reach the upstream"));

        FullHttpResponse response = sendRequest(channel, resourcesRead("res-5", RESOURCE_URI));

        assertNotNull(response);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
        JsonRpcResponse rpcResponse = decode(response);
        assertTrue(rpcResponse.isError());
        assertEquals(JsonRpcError.POLICY_VIOLATION, rpcResponse.error().code());
        assertEquals(JsonRpcError.MACHINE_APPROVAL_DENIED, rpcResponse.error().machineCode());
        assertTrue(audits.stream().anyMatch(a -> a.contains("|resources/read|BLOCKED|status=403")),
                () -> "the rejected resource read is audited: " + audits);
    }

    @Test
    @DisplayName("C-001: a modification of the tools/call projection fails closed instead of forwarding")
    void modificationOfTheProjectionFailsClosed() {
        ToolCallInterceptor modifier = (context, request) -> {
            ObjectNode params = mapper.createObjectNode();
            params.put("name", "resources/read");
            return CompletableFuture.completedFuture(InterceptionVerdict.modify(
                    new JsonRpcRequest(JsonRpcId.of("res-6"), JsonRpcRequest.METHOD_TOOLS_CALL, params)));
        };
        EmbeddedChannel channel = createChannel(modifier,
                (context, request) -> fail("An unapplied modification must never reach the upstream"));

        FullHttpResponse response = sendRequest(channel, resourcesRead("res-6", RESOURCE_URI));

        assertNotNull(response);
        assertEquals(HttpResponseStatus.INTERNAL_SERVER_ERROR, response.status());
        JsonRpcResponse rpcResponse = decode(response);
        assertTrue(rpcResponse.isError());
        assertEquals(JsonRpcError.INTERNAL_ERROR, rpcResponse.error().code());
        assertEquals(JsonRpcError.MACHINE_INTERNAL_ERROR, rpcResponse.error().machineCode());
    }

    @Test
    @DisplayName("C-001: resources/list is not policy-bearing and passes straight to the upstream")
    void resourcesListPassesThroughWithoutAPolicyDecision() {
        ToolCallInterceptor interceptor = (context, request) -> {
            fail("resources/list is not policy-bearing and must not reach the chain");
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        };
        AtomicReference<JsonRpcRequest> forwarded = new AtomicReference<>();
        EmbeddedChannel channel = createChannel(interceptor, (context, request) -> {
            forwarded.set(request);
            ObjectNode result = mapper.createObjectNode();
            result.put("resources", mapper.createArrayNode());
            return CompletableFuture.completedFuture(JsonRpcResponse.success(request.id(), result));
        });

        FullHttpResponse response = sendRequest(channel,
                "{\"jsonrpc\":\"2.0\",\"id\":\"list-1\",\"method\":\"resources/list\"}");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());
        assertNotNull(forwarded.get());
        assertEquals("resources/list", forwarded.get().method());
        assertTrue(audits.stream().anyMatch(a -> a.contains("|resources/list|ALLOWED|status=200")),
                () -> "the pass-through outcome is audited under the method name: " + audits);
    }

    @Test
    @DisplayName("C-001: a tools/call still reaches the chain unchanged")
    void toolsCallIsStillEvaluatedAsAToolCall() {
        AtomicReference<JsonRpcRequest> chained = new AtomicReference<>();
        ToolCallInterceptor interceptor = (context, request) -> {
            chained.set(request);
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        };
        AtomicReference<JsonRpcRequest> forwarded = new AtomicReference<>();
        EmbeddedChannel channel = createChannel(interceptor, (context, request) -> {
            forwarded.set(request);
            ObjectNode result = mapper.createObjectNode();
            result.put("status", "executed");
            return CompletableFuture.completedFuture(JsonRpcResponse.success(request.id(), result));
        });

        FullHttpResponse response = sendRequest(channel,
                "{\"jsonrpc\":\"2.0\",\"id\":\"tool-1\",\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/workspace/a.txt\"}}}");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());
        assertEquals("tools/call", chained.get().method());
        assertEquals("read_file", chained.get().toolName());
        assertEquals("tools/call", forwarded.get().method());
        assertFalse(audits.isEmpty(), "the allowed tool call is audited");
    }
}
