package dev.aegismcp.gateway.proxy;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
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

    public McpProxyHandler() {
        this(DEFAULT_RPC_PATH, ToolCallInterceptor.allowAll(), UpstreamClient.mockEcho(), false);
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
        super(false); // Manual retain/release control for pass-through compatibility
        this.rpcPath = Objects.requireNonNull(rpcPath, "rpcPath must not be null");
        this.codec = Objects.requireNonNull(codec, "codec must not be null");
        this.interceptor = Objects.requireNonNull(interceptor, "interceptor must not be null");
        this.upstreamClient = Objects.requireNonNull(upstreamClient, "upstreamClient must not be null");
        this.virtualExecutor = Objects.requireNonNull(virtualExecutor, "virtualExecutor must not be null");
        this.requireAuth = requireAuth;
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
        try {
            if (!HttpMethod.POST.equals(request.method())) {
                sendError(ctx, JsonRpcId.nullId(),
                        new JsonRpcError(JsonRpcError.INVALID_REQUEST, "Method Not Allowed: MCP RPC endpoint requires POST"),
                        HttpResponseStatus.METHOD_NOT_ALLOWED, keepAlive);
                return;
            }

            AgentIdentity identity = AgentIdentity.extract(request, ctx);
            SecurityContext securityContext = SecurityContext.of(identity, ctx.channel().remoteAddress());

            if (requireAuth && !securityContext.isAuthenticated()) {
                sendError(ctx, JsonRpcId.nullId(),
                        JsonRpcError.authenticationFailed("Missing or invalid agent credentials"),
                        HttpResponseStatus.UNAUTHORIZED, keepAlive);
                return;
            }

            ByteBuf content = request.content();
            if (!content.isReadable()) {
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
                sendError(ctx, e.getId(), e.getError(), e.getHttpStatus(), keepAlive);
                return;
            }

            executeInterceptionPipeline(ctx, securityContext, rpcRequest, keepAlive);

        } catch (Exception e) {
            logger.error("Unhandled error in MCP proxy pipeline", e);
            sendError(ctx, JsonRpcId.nullId(),
                    JsonRpcError.internalError("Proxy pipeline internal error: " + e.getMessage()),
                    HttpResponseStatus.INTERNAL_SERVER_ERROR, keepAlive);
        } finally {
            request.release();
        }
    }

    private void executeInterceptionPipeline(ChannelHandlerContext ctx, SecurityContext securityContext,
                                            JsonRpcRequest rpcRequest, boolean keepAlive) {
        if (rpcRequest.isToolCall()) {
            logger.debug("Intercepting MCP tool call: {} for agent: {}",
                    rpcRequest.toolName(), securityContext.identity().agentId());

            interceptor.intercept(securityContext, rpcRequest)
                    .thenCompose(verdict -> {
                        if (verdict instanceof InterceptionVerdict.Block block) {
                            JsonRpcResponse errorResponse = JsonRpcResponse.error(rpcRequest.id(), block.error());
                            return CompletableFuture.completedFuture(errorResponse);
                        }

                        JsonRpcRequest targetRequest = (verdict instanceof InterceptionVerdict.Modify modify)
                                ? modify.modifiedRequest()
                                : rpcRequest;

                        return upstreamClient.forward(securityContext, targetRequest);
                    })
                    .whenComplete((response, throwable) -> handlePipelineResult(ctx, rpcRequest.id(), response, throwable, keepAlive));
        } else {
            // Non-tool call (e.g. tools/list, initialize, ping) passes directly to upstream
            upstreamClient.forward(securityContext, rpcRequest)
                    .whenComplete((response, throwable) -> handlePipelineResult(ctx, rpcRequest.id(), response, throwable, keepAlive));
        }
    }

    private void handlePipelineResult(ChannelHandlerContext ctx, JsonRpcId requestId,
                                       JsonRpcResponse response, Throwable throwable, boolean keepAlive) {
        if (throwable != null) {
            logger.error("Upstream forwarding failed for request {}", requestId, throwable);
            Throwable cause = throwable.getCause() != null ? throwable.getCause() : throwable;
            if (cause instanceof TimeoutException) {
                sendError(ctx, requestId,
                        JsonRpcError.approvalTimedOut("Upstream request timed out"),
                        HttpResponseStatus.REQUEST_TIMEOUT, keepAlive);
            } else {
                sendError(ctx, requestId,
                        JsonRpcError.upstreamUnavailable("Upstream MCP server unreachable: " + cause.getMessage()),
                        HttpResponseStatus.BAD_GATEWAY, keepAlive);
            }
            return;
        }

        if (response == null) {
            sendError(ctx, requestId,
                    JsonRpcError.internalError("Null response received from upstream"),
                    HttpResponseStatus.INTERNAL_SERVER_ERROR, keepAlive);
            return;
        }

        // Exact preservation of request id per C-001 / FEAT-001
        JsonRpcResponse responseWithMatchingId = response;
        if (!Objects.equals(requestId, response.id()) && requestId != null && !(requestId instanceof JsonRpcId.NullId)) {
            responseWithMatchingId = response.isError()
                    ? JsonRpcResponse.error(requestId, response.error())
                    : JsonRpcResponse.success(requestId, response.result());
        }

        HttpResponseStatus status = HttpResponseStatus.OK;
        if (responseWithMatchingId.isError()) {
            status = responseWithMatchingId.error().toHttpStatus();
        }

        sendResponse(ctx, responseWithMatchingId, status, keepAlive);
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
                JsonRpcError.internalError("Channel pipeline failure: " + cause.getMessage()),
                HttpResponseStatus.INTERNAL_SERVER_ERROR, false);
    }
}
