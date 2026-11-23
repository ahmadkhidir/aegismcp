package dev.aegismcp.gateway.health;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import io.netty.handler.codec.http.QueryStringDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Netty HTTP handler serving the unauthenticated liveness and readiness probes.
 *
 * <p>{@code GET /health} answers {@code 200} with exactly {@code {"status":"UP"}} while the process
 * serves requests (C-022). {@code GET /ready} answers {@code 200} when every dependency check is
 * healthy and {@code 503} with a reason otherwise (C-023). Neither response carries a tenant,
 * credential, host, path, or exception detail.
 *
 * <p>Anchors: C-022, C-023, FEAT-001, NFR-010.
 */
@ChannelHandler.Sharable
public class HealthHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(HealthHandler.class);

    public static final String HEALTH_PATH = "/health";
    public static final String READY_PATH = "/ready";

    private static final byte[] LIVENESS_BODY = "{\"status\":\"UP\"}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] METHOD_NOT_ALLOWED_BODY = "{\"error\":\"Method Not Allowed\"}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INTERNAL_ERROR_BODY = "{\"error\":\"Internal Server Error\"}".getBytes(StandardCharsets.UTF_8);

    private final GatewayReadiness readiness;
    private final ObjectMapper jsonMapper;

    public HealthHandler(GatewayReadiness readiness) {
        this(readiness, new ObjectMapper());
    }

    public HealthHandler(GatewayReadiness readiness, ObjectMapper jsonMapper) {
        super(false); // Manual buffer ownership: the request is released on every handled path
        this.readiness = Objects.requireNonNull(readiness, "readiness must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String path = new QueryStringDecoder(request.uri()).path();
        boolean liveness = HEALTH_PATH.equals(path);
        if (!liveness && !READY_PATH.equals(path)) {
            ctx.fireChannelRead(request);
            return;
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);
        try {
            if (!HttpMethod.GET.equals(request.method())) {
                send(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED, METHOD_NOT_ALLOWED_BODY, keepAlive);
                return;
            }

            if (liveness) {
                send(ctx, HttpResponseStatus.OK, LIVENESS_BODY, keepAlive);
                return;
            }

            ReadinessSnapshot snapshot = readiness.snapshot();
            HttpResponseStatus status = GatewayReadiness.STATUS_UP.equals(snapshot.status())
                    ? HttpResponseStatus.OK
                    : HttpResponseStatus.SERVICE_UNAVAILABLE;
            send(ctx, status, jsonMapper.writeValueAsBytes(snapshot), keepAlive);
        } catch (JsonProcessingException e) {
            logger.error("Failed to serialize the readiness payload", e);
            send(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR, INTERNAL_ERROR_BODY, keepAlive);
        } catch (RuntimeException e) {
            logger.error("Failed to answer the health probe", e);
            send(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR, INTERNAL_ERROR_BODY, keepAlive);
        } finally {
            request.release();
        }
    }

    private void send(ChannelHandlerContext ctx, HttpResponseStatus status, byte[] body, boolean keepAlive) {
        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                status,
                Unpooled.wrappedBuffer(body)
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, body.length);

        if (keepAlive) {
            response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
            ctx.writeAndFlush(response);
        } else {
            response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        }
    }
}
