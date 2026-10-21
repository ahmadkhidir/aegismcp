package dev.aegismcp.gateway.codec;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageEncoder;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;

import java.util.List;

/**
 * Netty outbound handler that encodes a JsonRpcResponse into a FullHttpResponse.
 * Maps C-001 error codes to their respective HTTP status codes.
 * Anchors: FEAT-001, C-001.
 */
public class HttpJsonRpcEncoder extends MessageToMessageEncoder<JsonRpcResponse> {

    private final JsonRpcCodec codec;

    public HttpJsonRpcEncoder() {
        this(JsonRpcCodec.getInstance());
    }

    public HttpJsonRpcEncoder(JsonRpcCodec codec) {
        this.codec = codec;
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, JsonRpcResponse msg, List<Object> out) {
        byte[] payload = codec.encode(msg);
        ByteBuf content = Unpooled.wrappedBuffer(payload);

        HttpResponseStatus status = HttpResponseStatus.OK;
        if (msg.isError()) {
            status = msg.error().toHttpStatus();
        }

        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                status,
                content
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, payload.length);

        out.add(response);
    }
}
