package dev.aegismcp.gateway.inspector;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.health.GatewayReadiness;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

/**
 * Netty HTTP handler for contract C-002, {@code GET /api/v1/stream/traffic}.
 *
 * <p>The handler authenticates the operator before any byte of the stream is written: a missing,
 * expired, or invalid credential is answered {@code 401} with no stream opened, a verified operator
 * holding no console role is answered {@code 403} and the attempt is logged, and a broadcasting
 * gateway that is unavailable or draining is answered {@code 503} so the console can show its
 * reconnect state. Only then is the {@code text/event-stream} response opened with
 * {@code Cache-Control: no-cache}, the {@code retry: 3000} directive, and no content length, because
 * the body is chunked for the life of the connection.
 *
 * <p>The handler is stateless and shared across connections; subscription state lives in
 * {@link InspectorEventStream} and is released when the channel closes.
 *
 * <p>Anchors: FEAT-008, NFR-005, NFR-029, C-002.
 */
@ChannelHandler.Sharable
public final class TrafficStreamHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(TrafficStreamHandler.class);

    /** Contract path of the live traffic stream (C-002). */
    public static final String STREAM_PATH = "/api/v1/stream/traffic";

    public static final String BEARER_PREFIX = "Bearer ";

    private static final String CONTENT_TYPE_EVENT_STREAM = "text/event-stream";

    private final InspectorEventStream eventStream;
    private final ObjectMapper jsonMapper;
    private final StreamAuthorizer authorizer;
    private final GatewayReadiness readiness;
    private final Executor worker;

    /**
     * Authenticates and authorizes a subscription. It receives both credentials C-002 names because a
     * browser-native {@code EventSource} cannot attach an {@code Authorization} header and presents
     * the console session cookie instead.
     */
    @FunctionalInterface
    public interface StreamAuthorizer {
        AuthResult authorize(String bearerToken, String cookieHeader);

        record AuthResult(boolean authorized, boolean forbidden, String errorReason) {
            public static AuthResult allow() {
                return new AuthResult(true, false, null);
            }

            public static AuthResult unauthenticated(String reason) {
                return new AuthResult(false, false, reason);
            }

            public static AuthResult forbidden(String reason) {
                return new AuthResult(false, true, reason);
            }
        }
    }

    public TrafficStreamHandler(
            InspectorEventStream eventStream,
            ObjectMapper jsonMapper,
            StreamAuthorizer authorizer,
            GatewayReadiness readiness,
            Executor worker
    ) {
        super(false); // An unowned request is forwarded to the handler that owns its path.
        this.eventStream = Objects.requireNonNull(eventStream, "eventStream must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
        this.readiness = Objects.requireNonNull(readiness, "readiness must not be null");
        this.worker = Objects.requireNonNull(worker, "worker must not be null");
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String path = path(request.uri());
        if (!STREAM_PATH.equals(path)) {
            // Forward every other request to the handler that owns its path; it owns the buffer.
            ctx.fireChannelRead(request);
            return;
        }

        // Token validation verifies a signature and, on a cold cache, fetches the identity provider's
        // JWKS over the network. That is not event-loop work, so the subscription is decided on a
        // virtual thread and only the framing stays on this channel's loop (NFR-001, NFR-002).
        request.retain();
        try {
            worker.execute(() -> {
                try {
                    handleStreamRequest(ctx, request);
                } finally {
                    request.release();
                }
            });
        } catch (RejectedExecutionException e) {
            // The worker is shutting down, so the subscription would never be answered.
            logger.warn("Live traffic stream worker rejected the subscription; refusing the request");
            sendError(ctx, HttpResponseStatus.SERVICE_UNAVAILABLE,
                    "The live traffic stream is unavailable while the gateway restarts",
                    HttpUtil.isKeepAlive(request));
            request.release();
        }
    }

    private void handleStreamRequest(ChannelHandlerContext ctx, FullHttpRequest request) {
        boolean keepAlive = HttpUtil.isKeepAlive(request);

        if (!HttpMethod.GET.equals(request.method())) {
            sendError(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                    "Method Not Allowed: the live traffic stream accepts GET only", keepAlive);
            return;
        }

        StreamAuthorizer.AuthResult auth = authenticate(request);
        if (!auth.authorized()) {
            if (auth.forbidden()) {
                // FEAT-008: an authenticated operator without a console role is refused and the
                // attempt is logged. The credential itself is never logged.
                logger.warn("Live traffic stream subscription refused: the operator holds no console role");
                sendError(ctx, HttpResponseStatus.FORBIDDEN, auth.errorReason(), keepAlive);
            } else {
                sendError(ctx, HttpResponseStatus.UNAUTHORIZED, auth.errorReason(), keepAlive);
            }
            return;
        }

        if (!eventStream.isAccepting()
                || readiness.getLifecycle() == GatewayReadiness.Lifecycle.SHUTTING_DOWN) {
            sendError(ctx, HttpResponseStatus.SERVICE_UNAVAILABLE,
                    "The live traffic stream is unavailable while the gateway restarts", keepAlive);
            return;
        }

        openStream(ctx);
    }

    private StreamAuthorizer.AuthResult authenticate(FullHttpRequest request) {
        String bearerToken = bearerToken(request);
        String cookieHeader = request.headers().get(HttpHeaderNames.COOKIE);
        try {
            StreamAuthorizer.AuthResult result = authorizer.authorize(bearerToken, cookieHeader);
            return result != null ? result
                    : StreamAuthorizer.AuthResult.unauthenticated("Invalid or missing credentials");
        } catch (RuntimeException e) {
            // An authorizer failure is an authentication failure, never an open stream.
            logger.warn("Live traffic stream authorization failed closed: {}", e.getMessage());
            return StreamAuthorizer.AuthResult.unauthenticated("Invalid or missing credentials");
        }
    }

    private static String bearerToken(FullHttpRequest request) {
        String authorization = request.headers().get(HttpHeaderNames.AUTHORIZATION);
        if (authorization != null
                && authorization.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return authorization.substring(BEARER_PREFIX.length()).trim();
        }
        return null;
    }

    /**
     * Opens the chunked event stream. The response carries no content length because the body ends
     * with the connection; the retry directive is written by the broadcaster as the first frame, in
     * this same event-loop turn, so it always precedes every event.
     */
    private void openStream(ChannelHandlerContext ctx) {
        DefaultHttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, CONTENT_TYPE_EVENT_STREAM);
        response.headers().set(HttpHeaderNames.CACHE_CONTROL, HttpHeaderValues.NO_CACHE);
        response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
        HttpUtil.setTransferEncodingChunked(response, true);

        ctx.writeAndFlush(response).addListener(future -> {
            if (!future.isSuccess()) {
                logger.debug("Failed to open the live traffic stream; closing the connection",
                        future.cause());
                ctx.close();
            }
        });
        if (!eventStream.subscribe(ctx.channel())) {
            // The broadcaster closed between the acceptance check and the subscription (the node
            // began draining); closing makes the console enter its reconnect state (C-002).
            ctx.close();
        }
    }

    private void sendError(ChannelHandlerContext ctx, HttpResponseStatus status, String message,
                           boolean keepAlive) {
        byte[] body;
        try {
            body = jsonMapper.writeValueAsBytes(new InspectorErrorResponse(message));
        } catch (JsonProcessingException e) {
            logger.error("Failed to serialize a live traffic stream error body", e);
            body = "{\"error\":\"Internal server error\"}".getBytes(StandardCharsets.UTF_8);
        }
        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, status, Unpooled.wrappedBuffer(body));
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

    private static String path(String uri) {
        int queryIndex = uri.indexOf('?');
        return queryIndex >= 0 ? uri.substring(0, queryIndex) : uri;
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.debug("Live traffic stream connection failed", cause);
        ctx.close();
    }
}
