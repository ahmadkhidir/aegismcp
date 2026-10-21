package dev.aegismcp.gateway.proxy;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying Zero-Trust traffic interception and contract C-001 adherence.
 * Anchors: FEAT-001, C-001, NFR-001.
 */
class McpProxyHandlerTest {

    private JsonRpcCodec codec;
    private ExecutorService directExecutor;

    @BeforeEach
    void setUp() {
        codec = new JsonRpcCodec();
        // Use single-thread executor for deterministic embedded channel execution
        directExecutor = Executors.newSingleThreadExecutor();
    }

    private EmbeddedChannel createChannel(ToolCallInterceptor interceptor, UpstreamClient upstreamClient, boolean requireAuth) {
        McpProxyHandler handler = new McpProxyHandler(
                McpProxyHandler.DEFAULT_RPC_PATH,
                codec,
                interceptor,
                upstreamClient,
                directExecutor,
                requireAuth
        );
        return new EmbeddedChannel(handler);
    }

    private FullHttpResponse sendRequest(EmbeddedChannel channel, HttpMethod method, String uri,
                                        String payload, String authHeader, String spiffeHeader) {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                method,
                uri,
                payload != null ? Unpooled.wrappedBuffer(payload.getBytes(StandardCharsets.UTF_8)) : Unpooled.EMPTY_BUFFER
        );
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        if (payload != null) {
            request.headers().set(HttpHeaderNames.CONTENT_LENGTH, payload.getBytes(StandardCharsets.UTF_8).length);
        }
        if (authHeader != null) {
            request.headers().set(HttpHeaderNames.AUTHORIZATION, authHeader);
        }
        if (spiffeHeader != null) {
            request.headers().set(AgentIdentity.HEADER_SPIFFE_ID, spiffeHeader);
        }

        channel.writeInbound(request);
        channel.runPendingTasks();

        // Wait up to 1 second for asynchronous virtual thread executor tasks
        long deadline = System.currentTimeMillis() + 1000;
        FullHttpResponse response = null;
        while (System.currentTimeMillis() < deadline && (response = channel.readOutbound()) == null) {
            channel.runPendingTasks();
            try {
                Thread.sleep(10);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return response;
    }

    @Test
    @DisplayName("C-001 / FEAT-001: Authorized tool call forwarded and response returned (HTTP 200)")
    void testAuthorizedToolCallSuccess() {
        AtomicBoolean intercepted = new AtomicBoolean(false);
        ToolCallInterceptor interceptor = (context, req) -> {
            intercepted.set(true);
            assertEquals("filesystem_read", req.toolName());
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        };

        UpstreamClient upstream = (context, req) -> {
            ObjectNode result = codec.createObjectNode();
            result.put("content", "file content line 1");
            return CompletableFuture.completedFuture(JsonRpcResponse.success(req.id(), result));
        };

        EmbeddedChannel channel = createChannel(interceptor, upstream, false);

        String payload = """
                {
                  "jsonrpc": "2.0",
                  "id": "call-101",
                  "method": "tools/call",
                  "params": {
                    "name": "filesystem_read",
                    "arguments": { "path": "/data/report.txt" }
                  }
                }
                """;

        FullHttpResponse response = sendRequest(channel, HttpMethod.POST, "/mcp/v1/rpc", payload, null, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());
        assertTrue(intercepted.get());

        byte[] body = new byte[response.content().readableBytes()];
        response.content().readBytes(body);
        JsonRpcResponse rpcResp = codec.decodeResponse(body);

        assertTrue(rpcResp.isSuccess());
        assertEquals("call-101", ((JsonRpcId.StringId) rpcResp.id()).stringValue());
        assertEquals("file content line 1", rpcResp.result().get("content").asText());
    }

    @Test
    @DisplayName("C-001: Policy violation returns HTTP 403 Forbidden (-32001 Policy Violation)")
    void testPolicyViolationReturns403() {
        ToolCallInterceptor interceptor = (context, req) -> CompletableFuture.completedFuture(
                InterceptionVerdict.block(JsonRpcError.policyViolation("Access to /etc/shadow prohibited"))
        );

        UpstreamClient upstream = (context, req) -> fail("Upstream should not be called on policy block");

        EmbeddedChannel channel = createChannel(interceptor, upstream, false);

        String payload = """
                {
                  "jsonrpc": "2.0",
                  "id": 999,
                  "method": "tools/call",
                  "params": {
                    "name": "read_file",
                    "arguments": { "path": "/etc/shadow" }
                  }
                }
                """;

        FullHttpResponse response = sendRequest(channel, HttpMethod.POST, "/mcp/v1/rpc", payload, null, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());

        byte[] body = new byte[response.content().readableBytes()];
        response.content().readBytes(body);
        JsonRpcResponse rpcResp = codec.decodeResponse(body);

        assertTrue(rpcResp.isError());
        assertEquals(999L, ((JsonRpcId.NumberId) rpcResp.id()).numberValue());
        assertEquals(JsonRpcError.POLICY_VIOLATION, rpcResp.error().code());
        assertTrue(rpcResp.error().message().contains("Policy Violation"));
    }

    @Test
    @DisplayName("C-001: Unauthenticated request returns HTTP 401 Unauthorized (-32000 Authentication Failed)")
    void testUnauthenticatedReturns401() {
        ToolCallInterceptor interceptor = ToolCallInterceptor.allowAll();
        UpstreamClient upstream = UpstreamClient.mockEcho();

        EmbeddedChannel channel = createChannel(interceptor, upstream, true);

        String payload = """
                {
                  "jsonrpc": "2.0",
                  "id": 1,
                  "method": "tools/list"
                }
                """;

        FullHttpResponse response = sendRequest(channel, HttpMethod.POST, "/mcp/v1/rpc", payload, null, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());

        byte[] body = new byte[response.content().readableBytes()];
        response.content().readBytes(body);
        JsonRpcResponse rpcResp = codec.decodeResponse(body);

        assertTrue(rpcResp.isError());
        assertEquals(JsonRpcError.AUTHENTICATION_FAILED, rpcResp.error().code());
    }

    @Test
    @DisplayName("C-001: Valid Bearer token authenticates agent successfully")
    void testBearerTokenAuthenticationSuccess() {
        ToolCallInterceptor interceptor = (context, req) -> {
            assertTrue(context.isAuthenticated());
            assertEquals("secret-token-12345", context.identity().bearerToken());
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        };
        UpstreamClient upstream = UpstreamClient.mockEcho();

        EmbeddedChannel channel = createChannel(interceptor, upstream, true);

        String payload = """
                {
                  "jsonrpc": "2.0",
                  "id": 12,
                  "method": "tools/list"
                }
                """;

        FullHttpResponse response = sendRequest(channel, HttpMethod.POST, "/mcp/v1/rpc", payload,
                "Bearer secret-token-12345", null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());
    }

    @Test
    @DisplayName("C-001: Valid SPIFFE SVID authenticates agent workload")
    void testSpiffeAuthenticationSuccess() {
        ToolCallInterceptor interceptor = (context, req) -> {
            assertTrue(context.isAuthenticated());
            assertEquals("spiffe://aegismcp.dev/ns/prod/sa/agent-alpha", context.identity().spiffeId());
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        };
        UpstreamClient upstream = UpstreamClient.mockEcho();

        EmbeddedChannel channel = createChannel(interceptor, upstream, true);

        String payload = """
                {
                  "jsonrpc": "2.0",
                  "id": 14,
                  "method": "tools/list"
                }
                """;

        FullHttpResponse response = sendRequest(channel, HttpMethod.POST, "/mcp/v1/rpc", payload,
                null, "spiffe://aegismcp.dev/ns/prod/sa/agent-alpha");
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());
    }

    @Test
    @DisplayName("C-001: Approval timeout returns HTTP 408 Request Timeout (-32002 Approval Timed Out)")
    void testApprovalTimeoutReturns408() {
        ToolCallInterceptor interceptor = (context, req) -> {
            CompletableFuture<InterceptionVerdict> future = new CompletableFuture<>();
            future.completeExceptionally(new TimeoutException("Human approval deadline expired"));
            return future;
        };
        UpstreamClient upstream = UpstreamClient.mockEcho();

        EmbeddedChannel channel = createChannel(interceptor, upstream, false);

        String payload = """
                {
                  "jsonrpc": "2.0",
                  "id": "approve-me",
                  "method": "tools/call",
                  "params": { "name": "delete_database" }
                }
                """;

        FullHttpResponse response = sendRequest(channel, HttpMethod.POST, "/mcp/v1/rpc", payload, null, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.REQUEST_TIMEOUT, response.status());

        byte[] body = new byte[response.content().readableBytes()];
        response.content().readBytes(body);
        JsonRpcResponse rpcResp = codec.decodeResponse(body);

        assertTrue(rpcResp.isError());
        assertEquals(JsonRpcError.APPROVAL_TIMED_OUT, rpcResp.error().code());
    }

    @Test
    @DisplayName("C-001: Rate limit returns HTTP 429 Too Many Requests (-32003 Rate Limited)")
    void testRateLimitReturns429() {
        ToolCallInterceptor interceptor = (context, req) -> CompletableFuture.completedFuture(
                InterceptionVerdict.block(JsonRpcError.rateLimited("Rate limit of 100 req/min exceeded"))
        );
        UpstreamClient upstream = UpstreamClient.mockEcho();

        EmbeddedChannel channel = createChannel(interceptor, upstream, false);

        String payload = """
                {
                  "jsonrpc": "2.0",
                  "id": "rate-1",
                  "method": "tools/call",
                  "params": { "name": "scan_port" }
                }
                """;

        FullHttpResponse response = sendRequest(channel, HttpMethod.POST, "/mcp/v1/rpc", payload, null, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.TOO_MANY_REQUESTS, response.status());

        byte[] body = new byte[response.content().readableBytes()];
        response.content().readBytes(body);
        JsonRpcResponse rpcResp = codec.decodeResponse(body);

        assertTrue(rpcResp.isError());
        assertEquals(JsonRpcError.RATE_LIMITED, rpcResp.error().code());
    }

    @Test
    @DisplayName("C-001: Upstream server crash returns HTTP 502 Bad Gateway (-32004 Upstream Unavailable)")
    void testUpstreamCrashReturns502() {
        ToolCallInterceptor interceptor = ToolCallInterceptor.allowAll();
        UpstreamClient upstream = (context, req) -> {
            CompletableFuture<JsonRpcResponse> future = new CompletableFuture<>();
            future.completeExceptionally(new ConnectException("Connection refused by upstream tool server"));
            return future;
        };

        EmbeddedChannel channel = createChannel(interceptor, upstream, false);

        String payload = """
                {
                  "jsonrpc": "2.0",
                  "id": "upstream-test",
                  "method": "tools/call",
                  "params": { "name": "ping_tool" }
                }
                """;

        FullHttpResponse response = sendRequest(channel, HttpMethod.POST, "/mcp/v1/rpc", payload, null, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.BAD_GATEWAY, response.status());

        byte[] body = new byte[response.content().readableBytes()];
        response.content().readBytes(body);
        JsonRpcResponse rpcResp = codec.decodeResponse(body);

        assertTrue(rpcResp.isError());
        assertEquals(JsonRpcError.UPSTREAM_UNAVAILABLE, rpcResp.error().code());
    }

    @Test
    @DisplayName("FEAT-001: Non-tool call passes directly through to upstream")
    void testNonToolCallPassesThroughDirectly() {
        AtomicBoolean interceptorCalled = new AtomicBoolean(false);
        ToolCallInterceptor interceptor = (context, req) -> {
            interceptorCalled.set(true);
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        };

        UpstreamClient upstream = (context, req) -> {
            ObjectNode res = codec.createObjectNode();
            res.put("version", "1.0.0");
            return CompletableFuture.completedFuture(JsonRpcResponse.success(req.id(), res));
        };

        EmbeddedChannel channel = createChannel(interceptor, upstream, false);

        String payload = """
                {
                  "jsonrpc": "2.0",
                  "id": "init-1",
                  "method": "initialize",
                  "params": {}
                }
                """;

        FullHttpResponse response = sendRequest(channel, HttpMethod.POST, "/mcp/v1/rpc", payload, null, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());
        assertFalse(interceptorCalled.get(), "ToolCallInterceptor should not be called for non-tool call");
    }

    @Test
    @DisplayName("FEAT-001: Unmatched endpoints pass through to subsequent handlers")
    void testUnmatchedEndpointPassesThrough() {
        McpProxyHandler handler = new McpProxyHandler();
        EmbeddedChannel channel = new EmbeddedChannel(handler);

        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.GET,
                "/health"
        );

        assertTrue(channel.writeInbound(request));
        DefaultFullHttpRequest passedThrough = channel.readInbound();
        assertNotNull(passedThrough);
        assertEquals("/health", passedThrough.uri());
    }
}
