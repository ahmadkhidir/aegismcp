package dev.aegismcp.gateway.proxy;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.audit.ArgumentDigest;
import dev.aegismcp.gateway.codec.HttpJsonRpcDecoder;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcCodecException;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

/**
 * Netty inbound proxy handler implementing Zero-Trust streaming interception for MCP JSON-RPC 2.0.
 * Conforms to contract C-001 (POST /mcp/v1/rpc) with sub-5ms P99 non-blocking pipeline.
 * Anchors: FEAT-001, C-001, NFR-001.
 */
@ChannelHandler.Sharable
public class McpProxyHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(McpProxyHandler.class);
    public static final String DEFAULT_RPC_PATH = HttpJsonRpcDecoder.MCP_RPC_PATH;

    private final String rpcPath;
    private final JsonRpcCodec codec;
    private final ToolCallInterceptor interceptor;
    private final UpstreamClient upstreamClient;
    private final ExecutorService virtualExecutor;
    private final boolean requireAuth;
    private final boolean verifiedIdentityOnly;
    private final AuditTrail auditTrail;

    public McpProxyHandler() {
        // Fail-closed pass-through seam: the handler forwards non-owned paths untouched and refuses
        // any tool call because no interceptor chain or upstream was supplied. The shipped path is
        // assembled by AegisGatewayServer and never selects this constructor.
        this(DEFAULT_RPC_PATH, JsonRpcCodec.getInstance(),
                (context, request) -> CompletableFuture.completedFuture(InterceptionVerdict.block(
                        JsonRpcError.internalError("No interceptor chain is configured"))),
                UpstreamClient.unconfigured(), Executors.newVirtualThreadPerTaskExecutor(), false,
                AuditTrail.noop(), false);
    }

    public McpProxyHandler(ToolCallInterceptor interceptor, UpstreamClient upstreamClient) {
        this(DEFAULT_RPC_PATH, interceptor, upstreamClient, false);
    }

    public McpProxyHandler(ToolCallInterceptor interceptor, UpstreamClient upstreamClient, boolean requireAuth) {
        this(DEFAULT_RPC_PATH, interceptor, upstreamClient, requireAuth);
    }

    public McpProxyHandler(String rpcPath, ToolCallInterceptor interceptor, UpstreamClient upstreamClient, boolean requireAuth) {
        this(rpcPath, JsonRpcCodec.getInstance(), interceptor, upstreamClient,
                Executors.newVirtualThreadPerTaskExecutor(), requireAuth);
    }

    public McpProxyHandler(String rpcPath, JsonRpcCodec codec, ToolCallInterceptor interceptor,
                           UpstreamClient upstreamClient, ExecutorService virtualExecutor, boolean requireAuth) {
        this(rpcPath, codec, interceptor, upstreamClient, virtualExecutor, requireAuth,
                AuditTrail.noop(), false);
    }

    /**
     * Shipped constructor: the identity was verified at the edge and bound to the channel, and every
     * terminal outcome is recorded to the audit trail.
     */
    public McpProxyHandler(String rpcPath, JsonRpcCodec codec, ToolCallInterceptor interceptor,
                           UpstreamClient upstreamClient, ExecutorService virtualExecutor, boolean requireAuth,
                           AuditTrail auditTrail, boolean verifiedIdentityOnly) {
        super(false); // Manual retain/release control for pass-through compatibility
        this.rpcPath = Objects.requireNonNull(rpcPath, "rpcPath must not be null");
        this.codec = Objects.requireNonNull(codec, "codec must not be null");
        this.interceptor = Objects.requireNonNull(interceptor, "interceptor must not be null");
        this.upstreamClient = Objects.requireNonNull(upstreamClient, "upstreamClient must not be null");
        this.virtualExecutor = Objects.requireNonNull(virtualExecutor, "virtualExecutor must not be null");
        this.requireAuth = requireAuth;
        this.verifiedIdentityOnly = verifiedIdentityOnly;
        this.auditTrail = auditTrail != null ? auditTrail : AuditTrail.noop();
    }

    /**
     * Records a terminal outcome of one proxied request. Implementations must not persist the raw
     * tool arguments or response payload (FEAT-007, NFR-023); the summary is the method name, the
     * verdict, and the HTTP status only, while {@code argumentsHash} is the one-way digest of the
     * canonicalized arguments and {@code reviewedBy} is the verified reviewer when a human decision
     * applied (C-013, schema.md#AuditBlock).
     */
    @FunctionalInterface
    public interface AuditTrail {
        void record(String agentId, String toolName, String decision, double latencyMs,
                    String summary, String argumentsHash, String reviewedBy);

        static AuditTrail noop() {
            return (agentId, toolName, decision, latencyMs, summary, argumentsHash, reviewedBy) -> {
            };
        }
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        int queryIndex = uri.indexOf('?');
        String path = queryIndex >= 0 ? uri.substring(0, queryIndex) : uri;

        if (!rpcPath.equals(path)) {
            // Forward non-target requests (e.g. /health, /api/*) to next handlers in Netty pipeline
            ctx.fireChannelRead(request);
            return;
        }

        // Retain request for asynchronous virtual thread offloading
        request.retain();
        virtualExecutor.submit(() -> processMcpRequest(ctx, request));
    }

    private void processMcpRequest(ChannelHandlerContext ctx, FullHttpRequest request) {
        boolean keepAlive = HttpUtil.isKeepAlive(request);
        long startedAt = System.nanoTime();
        try {
            if (!HttpMethod.POST.equals(request.method())) {
                audit("unauthenticated", "mcp/rpc", "METHOD_NOT_ALLOWED", startedAt,
                        "method=" + request.method() + " status=405");
                sendError(ctx, JsonRpcId.nullId(),
                        JsonRpcError.invalidRequest("MCP RPC endpoint requires POST"),
                        HttpResponseStatus.METHOD_NOT_ALLOWED, keepAlive);
                return;
            }

            AgentIdentity identity = resolveIdentity(request, ctx);
            SecurityContext securityContext = SecurityContext.of(identity, ctx.channel().remoteAddress());

            if (requireAuth && !securityContext.isAuthenticated()) {
                audit(identity.agentId(), "mcp/authentication", "AUTHENTICATION_FAILED", startedAt,
                        "status=401");
                sendError(ctx, JsonRpcId.nullId(),
                        JsonRpcError.authenticationFailed("Missing or invalid agent credentials"),
                        HttpResponseStatus.UNAUTHORIZED, keepAlive);
                return;
            }

            ByteBuf content = request.content();
            if (!content.isReadable()) {
                audit(identity.agentId(), "mcp/rpc", "INVALID_REQUEST", startedAt, "empty body status=400");
                sendError(ctx, JsonRpcId.nullId(),
                        JsonRpcError.invalidRequest("Empty request body"),
                        HttpResponseStatus.BAD_REQUEST, keepAlive);
                return;
            }

            JsonRpcRequest rpcRequest;
            try {
                rpcRequest = codec.decodeRequest(content);
            } catch (JsonRpcCodecException e) {
                logger.debug("Failed decoding JSON-RPC request: {}", e.getMessage());
                audit(identity.agentId(), "mcp/rpc", "INVALID_REQUEST", startedAt,
                        "status=" + e.getHttpStatus().code());
                sendError(ctx, e.getId(), e.getError(), e.getHttpStatus(), keepAlive);
                return;
            }

            executeInterceptionPipeline(ctx, securityContext, rpcRequest, keepAlive, startedAt);

        } catch (Exception e) {
            logger.error("Unhandled error in MCP proxy pipeline", e);
            audit("unauthenticated", "mcp/rpc", "INTERNAL_ERROR", startedAt, "status=500");
            sendError(ctx, JsonRpcId.nullId(),
                    JsonRpcError.internalError("The gateway could not complete the request"),
                    HttpResponseStatus.INTERNAL_SERVER_ERROR, keepAlive);
        } finally {
            request.release();
        }
    }

    /**
     * Reads the identity the edge bound to the channel. The shipped path never trusts a header the
     * gateway did not verify; the header fallback exists only for the handler's own unit seam, which
     * is never attached without the identity verifier in front of it (FEAT-009, NFR-027).
     */
    private AgentIdentity resolveIdentity(FullHttpRequest request, ChannelHandlerContext ctx) {
        AgentIdentity verified = ctx.channel().attr(AgentIdentity.VERIFIED_ATTRIBUTE).get();
        if (verified != null) {
            return verified;
        }
        return verifiedIdentityOnly ? AgentIdentity.anonymous() : AgentIdentity.extract(request, ctx);
    }

    private void executeInterceptionPipeline(ChannelHandlerContext ctx, SecurityContext securityContext,
                                            JsonRpcRequest rpcRequest, boolean keepAlive, long startedAt) {
        // The digest is sealed with the decision, so the arguments themselves are never stored
        // (C-013, schema.md#AuditBlock). A resources/read is digested through the same projection
        // the chain evaluates, which is where its resource parameters live.
        String argumentsHash = ArgumentDigest.of(
                PolicyBearingMethods.toChainRequest(rpcRequest).toolArguments());
        if (PolicyBearingMethods.isPolicyBearing(rpcRequest)) {
            // C-001 makes exactly tools/call and resources/read policy-bearing, and both take the
            // whole chain: identity at the edge, parameter validation, policy (which may suspend for
            // approval), sequence anomaly, upstream, DLP on the response, and audit. A resource read
            // is evaluated through the tools/call projection so the shared stages see its target and
            // params; the upstream still receives the original resources/read request (FEAT-001,
            // FEAT-002, FEAT-004, FEAT-012, C-001).
            JsonRpcRequest chainRequest = PolicyBearingMethods.toChainRequest(rpcRequest);
            boolean projected = !rpcRequest.isToolCall();
            logger.debug("Intercepting policy-bearing MCP method: {} for agent: {}",
                    PolicyBearingMethods.policyTarget(rpcRequest), securityContext.identity().agentId());

            // Set by the verdict that leaves the interception chain; an approval decision carries
            // the verified reviewer, every automatic outcome leaves it null (FEAT-006).
            java.util.concurrent.atomic.AtomicReference<String> reviewedBy =
                    new java.util.concurrent.atomic.AtomicReference<>();

            interceptor.intercept(securityContext, chainRequest)
                    // An approval deadline is an interception outcome (C-001 408), not an upstream
                    // failure; any later TimeoutException can only come from the upstream exchange
                    // and maps to UPSTREAM_UNAVAILABLE instead.
                    .handle((verdict, failure) -> {
                        if (failure == null) {
                            return verdict;
                        }
                        Throwable cause = unwrapCompletion(failure);
                        if (cause instanceof TimeoutException) {
                            return InterceptionVerdict.block(
                                    JsonRpcError.approvalTimedOut("No reviewer decided within the deadline"));
                        }
                        throw new java.util.concurrent.CompletionException(cause);
                    })
                    .thenCompose(verdict -> {
                        reviewedBy.set(verdict.reviewedBy());
                        if (verdict instanceof InterceptionVerdict.Block block) {
                            JsonRpcResponse errorResponse = JsonRpcResponse.error(rpcRequest.id(), block.error());
                            return CompletableFuture.completedFuture(errorResponse);
                        }

                        if (!(verdict instanceof InterceptionVerdict.Modify modify)) {
                            // The chain allowed the request: the upstream receives the original
                            // envelope, never the tools/call projection used to evaluate it.
                            return upstreamClient.forward(securityContext, rpcRequest);
                        }

                        if (projected) {
                            // A resource read has no tools/call rewrite surface, so a modification
                            // cannot be applied to the request the upstream understands. Refusing
                            // keeps a partially applied decision from executing (NFR-027).
                            return CompletableFuture.completedFuture(JsonRpcResponse.error(
                                    rpcRequest.id(),
                                    JsonRpcError.internalError("The gateway could not complete the request")));
                        }

                        return upstreamClient.forward(securityContext, modify.modifiedRequest());
                    })
                    .whenComplete((response, throwable) -> handlePipelineResult(
                            ctx, securityContext, rpcRequest, response, throwable, keepAlive, startedAt,
                            argumentsHash, reviewedBy.get()));
        } else {
            // A method C-001 does not make policy-bearing (initialize, tools/list, ping) passes
            // directly to the upstream server without a policy decision.
            upstreamClient.forward(securityContext, rpcRequest)
                    .whenComplete((response, throwable) -> handlePipelineResult(
                            ctx, securityContext, rpcRequest, response, throwable, keepAlive, startedAt,
                            argumentsHash, null));
        }
    }

    private void handlePipelineResult(ChannelHandlerContext ctx, SecurityContext securityContext,
                                       JsonRpcRequest rpcRequest, JsonRpcResponse response,
                                       Throwable throwable, boolean keepAlive, long startedAt,
                                       String argumentsHash, String reviewedBy) {
        String agentId = securityContext.identity().agentId();
        String toolName = rpcRequest.toolName() != null ? rpcRequest.toolName() : rpcRequest.method();

        if (throwable != null) {
            logger.error("Upstream forwarding failed for request {}", rpcRequest.id(), throwable);
            Throwable cause = unwrapCompletion(throwable);
            // Every upstream crash, disconnect, refused exchange, malformed answer, or deadline
            // maps to the C-001 502 row with -32603 and machine code UPSTREAM_UNAVAILABLE.
            if (isUpstreamFailure(cause)) {
                audit(agentId, toolName, "UPSTREAM_UNAVAILABLE", startedAt, "status=502",
                        argumentsHash, reviewedBy);
                sendError(ctx, rpcRequest.id(),
                        JsonRpcError.upstreamUnavailable("The upstream MCP server did not answer"),
                        HttpResponseStatus.BAD_GATEWAY, keepAlive);
            } else {
                audit(agentId, toolName, "INTERNAL_ERROR", startedAt, "status=500",
                        argumentsHash, reviewedBy);
                sendError(ctx, rpcRequest.id(),
                        JsonRpcError.internalError("The gateway could not complete the request"),
                        HttpResponseStatus.INTERNAL_SERVER_ERROR, keepAlive);
            }
            return;
        }

        if (response == null) {
            audit(agentId, toolName, "INTERNAL_ERROR", startedAt, "status=500",
                    argumentsHash, reviewedBy);
            sendError(ctx, rpcRequest.id(),
                    JsonRpcError.internalError("The upstream MCP server returned no response"),
                    HttpResponseStatus.INTERNAL_SERVER_ERROR, keepAlive);
            return;
        }

        // Exact preservation of request id per C-001 / FEAT-001
        JsonRpcResponse responseWithMatchingId = response;
        if (!Objects.equals(rpcRequest.id(), response.id())
                && rpcRequest.id() != null && !(rpcRequest.id() instanceof JsonRpcId.NullId)) {
            responseWithMatchingId = response.isError()
                    ? JsonRpcResponse.error(rpcRequest.id(), response.error())
                    : JsonRpcResponse.success(rpcRequest.id(), response.result());
        }

        HttpResponseStatus status = HttpResponseStatus.OK;
        if (responseWithMatchingId.isError()) {
            status = responseWithMatchingId.error().toHttpStatus();
            // A velocity breach pauses the identity (C-001 429): answer this call first, then close
            // the transport stream instead of severing it before the response can be written.
            if (JsonRpcError.MACHINE_INVOCATION_VELOCITY_EXCEEDED
                    .equals(responseWithMatchingId.error().machineCode())) {
                keepAlive = false;
            }
        }

        audit(agentId, toolName, responseWithMatchingId.isError() ? "BLOCKED" : "ALLOWED", startedAt,
                "status=" + status.code(), argumentsHash, reviewedBy);
        sendResponse(ctx, responseWithMatchingId, status, keepAlive);
    }

    /**
     * An upstream exchange that never produced a JSON-RPC answer: a transport failure, a deadline,
     * or a refused connection. These are the C-001 {@code UPSTREAM_UNAVAILABLE} row; an interceptor
     * defect or an unexpected gateway error is the internal-error row instead.
     */
    private static boolean isUpstreamFailure(Throwable cause) {
        return cause instanceof UpstreamException
                || cause instanceof TimeoutException
                || cause instanceof java.net.http.HttpTimeoutException
                || cause instanceof java.net.ConnectException
                || cause instanceof java.io.IOException;
    }

    private static Throwable unwrapCompletion(Throwable failure) {
        Throwable current = failure;
        while (current instanceof java.util.concurrent.CompletionException && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private void audit(String agentId, String toolName, String decision, long startedAt, String summary) {
        audit(agentId, toolName, decision, startedAt, summary, ArgumentDigest.of(null), null);
    }

    private void audit(String agentId, String toolName, String decision, long startedAt, String summary,
                       String argumentsHash, String reviewedBy) {
        double latencyMs = (System.nanoTime() - startedAt) / 1_000_000.0;
        try {
            auditTrail.record(agentId, toolName, decision, latencyMs, summary, argumentsHash, reviewedBy);
        } catch (RuntimeException e) {
            // An audit sink failure must never turn into a client-visible success or an unhandled
            // pipeline error; the ledger append reports its own failures.
            logger.error("Failed to record audit outcome for decision {}", decision, e);
        }
    }

    private void sendError(ChannelHandlerContext ctx, JsonRpcId id, JsonRpcError error,
                          HttpResponseStatus status, boolean keepAlive) {
        JsonRpcResponse errorResponse = JsonRpcResponse.error(id, error);
        sendResponse(ctx, errorResponse, status, keepAlive);
    }

    private void sendResponse(ChannelHandlerContext ctx, JsonRpcResponse response,
                              HttpResponseStatus status, boolean keepAlive) {
        byte[] payload = codec.encode(response);
        ByteBuf content = Unpooled.wrappedBuffer(payload);

        DefaultFullHttpResponse httpResponse = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                status,
                content
        );
        httpResponse.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        httpResponse.headers().set(HttpHeaderNames.CONTENT_LENGTH, payload.length);

        if (keepAlive) {
            httpResponse.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
            ctx.executor().execute(() -> ctx.writeAndFlush(httpResponse));
        } else {
            httpResponse.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
            ctx.executor().execute(() -> ctx.writeAndFlush(httpResponse).addListener(ChannelFutureListener.CLOSE));
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Exception caught in McpProxyHandler", cause);
        sendError(ctx, JsonRpcId.nullId(),
                JsonRpcError.internalError("The gateway could not complete the request"),
                HttpResponseStatus.INTERNAL_SERVER_ERROR, false);
    }
}
