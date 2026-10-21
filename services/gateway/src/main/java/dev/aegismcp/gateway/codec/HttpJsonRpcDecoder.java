package dev.aegismcp.gateway.codec;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Netty inbound handler that decodes incoming HTTP requests for POST /mcp/v1/rpc into JsonRpcRequest.
 * Enforces contract C-001 framing and returns standardized JSON-RPC error responses on invalid payloads.
 * Anchors: FEAT-001, C-001.
 */
public class HttpJsonRpcDecoder extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(HttpJsonRpcDecoder.class);
    public static final String MCP_RPC_PATH = "/mcp/v1/rpc";

    private final JsonRpcCodec codec;
    private final String rpcPath;

    public HttpJsonRpcDecoder() {
        this(JsonRpcCodec.getInstance(), MCP_RPC_PATH);
    }

    public HttpJsonRpcDecoder(JsonRpcCodec codec, String rpcPath) {
        super(false); // Do not auto-release here so we can pass unmatched requests through
        this.codec = codec;
        this.rpcPath = rpcPath;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        // Ignore query string if present
        int queryIndex = uri.indexOf('?');
        String path = queryIndex >= 0 ? uri.substring(0, queryIndex) : uri;

        if (!rpcPath.equals(path)) {
            // Not a C-001 MCP RPC request; pass through to subsequent handlers
            ctx.fireChannelRead(request);
            return;
        }

        try {
            if (!HttpMethod.POST.equals(request.method())) {
                sendErrorResponse(ctx, JsonRpcId.nullId(),
                        new JsonRpcError(JsonRpcError.INVALID_REQUEST, "Method Not Allowed; MCP RPC requires POST"),
                        HttpResponseStatus.METHOD_NOT_ALLOWED);
                return;
            }

            ByteBuf content = request.content();
            if (!content.isReadable()) {
                sendErrorResponse(ctx, JsonRpcId.nullId(),
                        JsonRpcError.invalidRequest("Empty request body"),
                        HttpResponseStatus.BAD_REQUEST);
                return;
            }

            JsonRpcRequest rpcRequest = codec.decodeRequest(content);
            ctx.fireChannelRead(rpcRequest);
        } catch (JsonRpcCodecException e) {
            logger.debug("JSON-RPC decode failed: {}", e.getMessage());
            sendErrorResponse(ctx, e.getId(), e.getError(), e.getHttpStatus());
        } catch (Exception e) {
            logger.error("Unexpected error decoding JSON-RPC request", e);
            sendErrorResponse(ctx, JsonRpcId.nullId(),
                    JsonRpcError.internalError("Internal decode failure"),
                    HttpResponseStatus.INTERNAL_SERVER_ERROR);
        } finally {
            request.release();
        }
    }

    private void sendErrorResponse(ChannelHandlerContext ctx, JsonRpcId id, JsonRpcError error, HttpResponseStatus status) {
        JsonRpcResponse errorResponse = JsonRpcResponse.error(id, error);
        byte[] payload = codec.encode(errorResponse);

        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                status,
                Unpooled.wrappedBuffer(payload)
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, payload.length);
        ctx.writeAndFlush(response);
    }
}
