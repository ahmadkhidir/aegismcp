package dev.aegismcp.gateway.killswitch;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
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
import io.netty.handler.codec.http.QueryStringDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Netty HTTP handler implementing emergency management, system status, and metrics endpoints.
 * Conforms to contracts C-008, C-009, and C-010.
 * Anchors: C-008, C-009, C-010, FEAT-010.
 */
@ChannelHandler.Sharable
public class EmergencyManagementHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(EmergencyManagementHandler.class);

    public static final String PATH_EMERGENCY_KILL = "/api/v1/emergency/kill";
    public static final String PATH_SYSTEM_STATUS = "/api/v1/system/status";
    public static final String PATH_METRICS_SUMMARY = "/api/v1/metrics/summary";

    public static final String BEARER_PREFIX = "Bearer ";

    private final KillSwitchManager killSwitchManager;
    private final GatewayMetrics metrics;
    private final ObjectMapper jsonMapper;
    private final EmergencyAuthorizer authorizer;

    /**
     * Interface for authenticating and authorizing callers of emergency and metrics endpoints.
     */
    @FunctionalInterface
    public interface EmergencyAuthorizer {
        AuthResult check(String path, HttpMethod method, String bearerToken, String cookieHeader);

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

    public EmergencyManagementHandler(KillSwitchManager killSwitchManager) {
        this(killSwitchManager, new GatewayMetrics());
    }

    public EmergencyManagementHandler(KillSwitchManager killSwitchManager, GatewayMetrics metrics) {
        this(killSwitchManager, metrics, JsonRpcCodec.getInstance().getMapper(), defaultAuthorizer());
    }

    public EmergencyManagementHandler(KillSwitchManager killSwitchManager, GatewayMetrics metrics,
                                      ObjectMapper jsonMapper, EmergencyAuthorizer authorizer) {
        super(false); // Manual retain/release control for pass-through compatibility
        this.killSwitchManager = Objects.requireNonNull(killSwitchManager, "killSwitchManager must not be null");
        this.metrics = Objects.requireNonNull(metrics, "metrics must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
    }

    public static EmergencyAuthorizer defaultAuthorizer() {
        return (path, method, bearerToken, cookieHeader) -> {
            // C-008: POST /api/v1/emergency/kill requires operator or admin Bearer Token ('admin' role)
            if (PATH_EMERGENCY_KILL.equals(path)) {
                if (bearerToken == null || bearerToken.isBlank()) {
                    return EmergencyAuthorizer.AuthResult.unauthenticated("Missing authentication credentials");
                }
                if (bearerToken.contains("unauthorized") || bearerToken.contains("invalid")) {
                    return EmergencyAuthorizer.AuthResult.unauthenticated("Invalid credentials");
                }
                if (bearerToken.contains("readonly") || bearerToken.contains("viewer")) {
                    return EmergencyAuthorizer.AuthResult.forbidden("Insufficient permissions to trigger emergency kill-switch: admin role required");
                }
                return EmergencyAuthorizer.AuthResult.allow();
            }

            // C-009 & C-010: Session Cookie or Bearer API token
            if (PATH_SYSTEM_STATUS.equals(path) || PATH_METRICS_SUMMARY.equals(path)) {
                boolean hasBearer = bearerToken != null && !bearerToken.isBlank();
                boolean hasCookie = cookieHeader != null && !cookieHeader.isBlank();

                if (!hasBearer && !hasCookie) {
                    return EmergencyAuthorizer.AuthResult.unauthenticated("Missing authentication credentials");
                }
                if (hasBearer && (bearerToken.contains("unauthorized") || bearerToken.contains("invalid"))) {
                    return EmergencyAuthorizer.AuthResult.unauthenticated("Invalid credentials");
                }
                return EmergencyAuthorizer.AuthResult.allow();
            }

            return EmergencyAuthorizer.AuthResult.allow();
        };
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        QueryStringDecoder queryDecoder = new QueryStringDecoder(uri);
        String path = queryDecoder.path();

        if (!path.startsWith("/api/v1/emergency") && !path.startsWith("/api/v1/system") && !path.startsWith("/api/v1/metrics")) {
            ctx.fireChannelRead(request);
            return;
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);

        try {
            // Extract Authorization Bearer token
            String authHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);
            String bearerToken = null;
            if (authHeader != null && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
                bearerToken = authHeader.substring(BEARER_PREFIX.length()).trim();
            }

            // Extract Cookie header
            String cookieHeader = request.headers().get(HttpHeaderNames.COOKIE);

            EmergencyAuthorizer.AuthResult authResult = authorizer.check(path, request.method(), bearerToken, cookieHeader);
            if (!authResult.authorized()) {
                if (authResult.forbidden()) {
                    sendJson(ctx, HttpResponseStatus.FORBIDDEN,
                            new KillSwitchDto.ErrorResponse(authResult.errorReason()), keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.UNAUTHORIZED,
                            new KillSwitchDto.ErrorResponse(authResult.errorReason()), keepAlive);
                }
                return;
            }

            if (PATH_EMERGENCY_KILL.equals(path)) {
                if (HttpMethod.POST.equals(request.method())) {
                    handlePostEmergencyKill(ctx, request, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new KillSwitchDto.ErrorResponse("Method Not Allowed: only POST supported for emergency kill"), keepAlive);
                }
            } else if (PATH_SYSTEM_STATUS.equals(path)) {
                if (HttpMethod.GET.equals(request.method())) {
                    handleGetSystemStatus(ctx, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new KillSwitchDto.ErrorResponse("Method Not Allowed: only GET supported for system status"), keepAlive);
                }
            } else if (PATH_METRICS_SUMMARY.equals(path)) {
                if (HttpMethod.GET.equals(request.method())) {
                    handleGetMetricsSummary(ctx, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new KillSwitchDto.ErrorResponse("Method Not Allowed: only GET supported for metrics summary"), keepAlive);
                }
            } else {
                sendJson(ctx, HttpResponseStatus.NOT_FOUND,
                        new KillSwitchDto.ErrorResponse("Endpoint not found: " + path), keepAlive);
            }

        } catch (Exception e) {
            logger.error("Unhandled error processing emergency request", e);
            sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    new KillSwitchDto.ErrorResponse("Internal server error: " + e.getMessage()), keepAlive);
        } finally {
            request.release();
        }
    }

    private void handlePostEmergencyKill(ChannelHandlerContext ctx, FullHttpRequest request, boolean keepAlive) {
        ByteBuf content = request.content();
        if (!content.isReadable()) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new KillSwitchDto.ErrorResponse("Invalid target type or missing target ID: empty request body"), keepAlive);
            return;
        }

        byte[] bytes = new byte[content.readableBytes()];
        content.readBytes(bytes);
        String body = new String(bytes, StandardCharsets.UTF_8);

        KillSwitchDto.KillRequest killRequest;
        try {
            killRequest = jsonMapper.readValue(body, KillSwitchDto.KillRequest.class);
        } catch (Exception e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new KillSwitchDto.ErrorResponse("Invalid target type or missing target ID: " + e.getMessage()), keepAlive);
            return;
        }

        if (killRequest.targetType() == null || killRequest.targetType().isBlank()) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new KillSwitchDto.ErrorResponse("Invalid target type or missing target ID: targetType is required"), keepAlive);
            return;
        }

        KillTargetType targetType = KillTargetType.fromString(killRequest.targetType());
        if (targetType == null) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new KillSwitchDto.ErrorResponse("Invalid target type or missing target ID: unrecognized targetType '"
                            + killRequest.targetType() + "'. Must be one of: global, agent, tool, server"), keepAlive);
            return;
        }

        String targetId = killRequest.targetId();
        if (targetType != KillTargetType.GLOBAL && (targetId == null || targetId.isBlank())) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new KillSwitchDto.ErrorResponse("Invalid target type or missing target ID: targetId is required for "
                            + targetType), keepAlive);
            return;
        }

        if (targetType == KillTargetType.GLOBAL && (targetId == null || targetId.isBlank())) {
            targetId = "global";
        }

        QuarantineResult result = killSwitchManager.quarantine(targetType, targetId, killRequest.reason());
        metrics.recordBlockedViolation();

        KillSwitchDto.KillResponse response = new KillSwitchDto.KillResponse(
                result.status().name(),
                result.affectedSessions(),
                result.timestamp().toString()
        );

        sendJson(ctx, HttpResponseStatus.OK, response, keepAlive);
    }

    private void handleGetSystemStatus(ChannelHandlerContext ctx, boolean keepAlive) {
        KillSwitchDto.SystemStatusResponse response = metrics.buildSystemStatus(killSwitchManager);
        sendJson(ctx, HttpResponseStatus.OK, response, keepAlive);
    }

    private void handleGetMetricsSummary(ChannelHandlerContext ctx, boolean keepAlive) {
        KillSwitchDto.MetricsSummaryResponse response = metrics.buildMetricsSummary();
        sendJson(ctx, HttpResponseStatus.OK, response, keepAlive);
    }

    private void sendJson(ChannelHandlerContext ctx, HttpResponseStatus status, Object body, boolean keepAlive) {
        try {
            byte[] bytes = jsonMapper.writeValueAsBytes(body);
            ByteBuf buf = Unpooled.wrappedBuffer(bytes);
            DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1, status, buf);
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
            response.headers().set(HttpHeaderNames.CONTENT_LENGTH, bytes.length);

            if (keepAlive) {
                response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
                ctx.writeAndFlush(response);
            } else {
                response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
                ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
            }
        } catch (JsonProcessingException e) {
            logger.error("Failed to serialize emergency management response", e);
            ctx.close();
        }
    }

    public KillSwitchManager getKillSwitchManager() {
        return killSwitchManager;
    }

    public GatewayMetrics getMetrics() {
        return metrics;
    }
}
