package dev.aegismcp.gateway.killswitch;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.audit.AuditRecord;
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
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;

/**
 * Netty HTTP handler implementing the emergency kill-switch (C-008), fleet status (C-009),
 * metrics summary (C-010), and metrics timeseries (C-020) contracts.
 *
 * <p>Every request is authenticated through the injected authorizer built from the verified OIDC
 * token. A missing or invalid token is {@code 401}; a verified operator without the contract role
 * is {@code 403}. A {@code global} target additionally requires a multi-factor re-confirmation
 * within the preceding five minutes, read from the standard OIDC {@code auth_time} and
 * {@code amr}/{@code acr} claims; the initiating operator recorded on the audit entry is the
 * verified token subject.
 *
 * <p>Anchors: FEAT-008, FEAT-010, C-008, C-009, C-010, C-020, NFR-029.
 */
@ChannelHandler.Sharable
public class EmergencyManagementHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(EmergencyManagementHandler.class);

    public static final String PATH_EMERGENCY_KILL = "/api/v1/emergency/kill";
    public static final String PATH_SYSTEM_STATUS = "/api/v1/system/status";
    public static final String PATH_METRICS_SUMMARY = "/api/v1/metrics/summary";
    public static final String PATH_METRICS_TIMESERIES = "/api/v1/metrics/timeseries";

    public static final String BEARER_PREFIX = "Bearer ";

    /** C-008: the operator's multi-factor re-confirmation must be at most five minutes old. */
    public static final Duration MFA_FRESHNESS = Duration.ofMinutes(5);

    /** Clock skew tolerated when reading a step-up authentication instant. */
    private static final long CLOCK_SKEW_SECONDS = 60;

    private final KillSwitchManager killSwitchManager;
    private final GatewayMetrics metrics;
    private final AuditLedger auditLedger;
    private final ObjectMapper jsonMapper;
    private final EmergencyAuthorizer authorizer;
    private final Executor worker;

    /**
     * Authenticates and authorizes a caller of an emergency or metrics endpoint. The verified
     * subject and the token claims are carried through so the kill path can require a fresh
     * multi-factor re-confirmation and attribute the action to the operator.
     */
    @FunctionalInterface
    public interface EmergencyAuthorizer {
        AuthResult check(String path, HttpMethod method, String bearerToken, String cookieHeader);

        record AuthResult(
                boolean authorized,
                boolean forbidden,
                String errorReason,
                String subject,
                Map<String, Object> claims
        ) {
            public AuthResult {
                claims = claims != null ? Map.copyOf(claims) : Map.of();
            }

            public AuthResult(boolean authorized, boolean forbidden, String errorReason) {
                this(authorized, forbidden, errorReason, null, Map.of());
            }

            public static AuthResult allow() {
                return new AuthResult(true, false, null, null, Map.of());
            }

            public static AuthResult verified(String subject, Map<String, Object> claims) {
                return new AuthResult(true, false, null, subject, claims);
            }

            public static AuthResult unauthenticated(String reason) {
                return new AuthResult(false, false, reason, null, Map.of());
            }

            public static AuthResult forbidden(String reason) {
                return new AuthResult(false, true, reason, null, Map.of());
            }
        }
    }

    public EmergencyManagementHandler(KillSwitchManager killSwitchManager, GatewayMetrics metrics,
                                      AuditLedger auditLedger, ObjectMapper jsonMapper,
                                      EmergencyAuthorizer authorizer) {
        this(killSwitchManager, metrics, auditLedger, jsonMapper, authorizer,
                runnable -> Thread.startVirtualThread(runnable));
    }

    public EmergencyManagementHandler(KillSwitchManager killSwitchManager, GatewayMetrics metrics,
                                      AuditLedger auditLedger, ObjectMapper jsonMapper,
                                      EmergencyAuthorizer authorizer, Executor worker) {
        super(false); // Manual retain/release control for pass-through compatibility
        this.killSwitchManager = Objects.requireNonNull(killSwitchManager, "killSwitchManager must not be null");
        this.metrics = Objects.requireNonNull(metrics, "metrics must not be null");
        this.auditLedger = Objects.requireNonNull(auditLedger, "auditLedger must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
        this.worker = Objects.requireNonNull(worker, "worker must not be null");
    }

    /** Convenience constructor for the shipped path: the platform JSON mapper. */
    public EmergencyManagementHandler(KillSwitchManager killSwitchManager, GatewayMetrics metrics,
                                      AuditLedger auditLedger, EmergencyAuthorizer authorizer) {
        this(killSwitchManager, metrics, auditLedger, JsonRpcCodec.getInstance().getMapper(), authorizer);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        QueryStringDecoder queryDecoder = new QueryStringDecoder(uri);
        String path = queryDecoder.path();

        if (!path.startsWith("/api/v1/emergency") && !path.startsWith("/api/v1/system")
                && !path.startsWith("/api/v1/metrics")) {
            ctx.fireChannelRead(request);
            return;
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);

        try {
            String bearerToken = bearerToken(request);
            String cookieHeader = request.headers().get(HttpHeaderNames.COOKIE);

            EmergencyAuthorizer.AuthResult authResult;
            try {
                authResult = authorizer.check(path, request.method(), bearerToken, cookieHeader);
            } catch (RuntimeException e) {
                logger.warn("Emergency authorization failed closed: {}", e.getMessage());
                authResult = EmergencyAuthorizer.AuthResult
                        .unauthenticated("Invalid or missing credentials");
            }
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
                    handlePostEmergencyKill(ctx, request, authResult, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new KillSwitchDto.ErrorResponse(
                                    "Method Not Allowed: only POST supported for emergency kill"), keepAlive);
                }
            } else if (PATH_SYSTEM_STATUS.equals(path)) {
                if (HttpMethod.GET.equals(request.method())) {
                    handleGetSystemStatus(ctx, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new KillSwitchDto.ErrorResponse(
                                    "Method Not Allowed: only GET supported for system status"), keepAlive);
                }
            } else if (PATH_METRICS_SUMMARY.equals(path)) {
                if (HttpMethod.GET.equals(request.method())) {
                    handleGetMetricsSummary(ctx, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new KillSwitchDto.ErrorResponse(
                                    "Method Not Allowed: only GET supported for metrics summary"), keepAlive);
                }
            } else if (PATH_METRICS_TIMESERIES.equals(path)) {
                if (HttpMethod.GET.equals(request.method())) {
                    handleGetMetricsTimeseries(ctx, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new KillSwitchDto.ErrorResponse(
                                    "Method Not Allowed: only GET supported for metrics timeseries"), keepAlive);
                }
            } else {
                sendJson(ctx, HttpResponseStatus.NOT_FOUND,
                        new KillSwitchDto.ErrorResponse("Endpoint not found"), keepAlive);
            }

        } catch (Exception e) {
            // The exception text can carry target or provider detail; it stays in the log.
            logger.error("Unhandled error processing an emergency management request", e);
            sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    new KillSwitchDto.ErrorResponse("Internal server error"), keepAlive);
        } finally {
            request.release();
        }
    }

    private void handlePostEmergencyKill(ChannelHandlerContext ctx, FullHttpRequest request,
                                         EmergencyAuthorizer.AuthResult authResult, boolean keepAlive) {
        byte[] bytes = new byte[request.content().readableBytes()];
        request.content().readBytes(bytes);
        if (bytes.length == 0) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new KillSwitchDto.ErrorResponse(
                            "Invalid emergency kill payload: empty request body"), keepAlive);
            return;
        }

        KillSwitchDto.KillRequest killRequest;
        try {
            killRequest = jsonMapper.readValue(bytes, KillSwitchDto.KillRequest.class);
        } catch (Exception e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new KillSwitchDto.ErrorResponse("Invalid emergency kill payload"), keepAlive);
            return;
        }

        KillTargetType targetType = KillTargetType.fromApiValue(killRequest.targetType());
        if (targetType == null) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new KillSwitchDto.ErrorResponse(
                            "Invalid emergency kill payload: 'targetType' must be one of "
                                    + "session, agent, server, global"), keepAlive);
            return;
        }

        String targetId = killRequest.targetId();
        boolean hasTargetId = targetId != null && !targetId.isBlank();
        if (targetType == KillTargetType.GLOBAL && hasTargetId) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new KillSwitchDto.ErrorResponse(
                            "Invalid emergency kill payload: 'targetId' must be absent for a global target"),
                    keepAlive);
            return;
        }
        if (targetType != KillTargetType.GLOBAL && !hasTargetId) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new KillSwitchDto.ErrorResponse(
                            "Invalid emergency kill payload: 'targetId' is required for a "
                                    + targetType.name().toLowerCase(Locale.ROOT) + " target"),
                    keepAlive);
            return;
        }

        // A second approver is permitted only on an Enterprise production global target. This
        // deployment has no Enterprise production tier configured, so any supplied approver is a
        // misplaced field and the action is refused without applying it (C-008).
        if (killRequest.secondApprover() != null && !killRequest.secondApprover().isBlank()) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new KillSwitchDto.ErrorResponse(
                            "Invalid emergency kill payload: 'secondApprover' is permitted only on an "
                                    + "Enterprise production global target"),
                    keepAlive);
            return;
        }

        if (targetType == KillTargetType.GLOBAL && !hasFreshMultiFactor(authResult.claims())) {
            sendJson(ctx, HttpResponseStatus.FORBIDDEN,
                    new KillSwitchDto.ErrorResponse(
                            "A multi-factor re-confirmation completed within the preceding five minutes "
                                    + "is required for a global lockdown"),
                    keepAlive);
            return;
        }

        if (!targetExists(targetType, targetId)) {
            sendJson(ctx, HttpResponseStatus.NOT_FOUND,
                    new KillSwitchDto.ErrorResponse(
                            "No " + targetType.name().toLowerCase(Locale.ROOT) + " matches the supplied targetId"),
                    keepAlive);
            return;
        }

        String reason = killRequest.reason();
        // The action runs off the event-loop thread; the seal is awaited there so the response is
        // never written before the administrative entry is in the ledger chain.
        worker.execute(() -> {
            QuarantineResult result;
            try {
                result = killSwitchManager.quarantine(targetType, targetId, reason);
                recordAdministrativeEntry(authResult.subject(), targetType, targetId, reason,
                        result.status().name());
            } catch (RuntimeException e) {
                logger.error("Emergency kill action failed", e);
                ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                        new KillSwitchDto.ErrorResponse("Internal server error"), keepAlive));
                return;
            }

            KillSwitchDto.KillResponse response = new KillSwitchDto.KillResponse(
                    result.status().name(),
                    result.affectedSessions(),
                    result.timestamp().toString()
            );
            ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.OK, response, keepAlive));
        });
    }

    private boolean targetExists(KillTargetType targetType, String targetId) {
        return switch (targetType) {
            case GLOBAL -> true;
            case SESSION -> killSwitchManager.hasSession(targetId);
            case AGENT -> killSwitchManager.hasAgentSession(targetId);
            case SERVER -> killSwitchManager.hasServerSession(targetId);
            case TOOL -> false;
        };
    }

    /**
     * True when the verified token records a multi-factor authentication within the freshness
     * window. {@code auth_time} is the OIDC instant of the last authentication and {@code amr} or
     * {@code acr} names the method; an operator who has not completed MFA fails closed.
     */
    public static boolean hasFreshMultiFactor(Map<String, Object> claims) {
        if (claims == null || claims.isEmpty()) {
            return false;
        }
        Long authTime = asEpochSeconds(claims.get("auth_time"));
        if (authTime == null) {
            return false;
        }
        long now = Instant.now().getEpochSecond();
        if (authTime > now + CLOCK_SKEW_SECONDS) {
            return false;
        }
        if (now - authTime > MFA_FRESHNESS.toSeconds()) {
            return false;
        }
        return declaresMultiFactor(claims.get("amr")) || declaresMultiFactor(claims.get("acr"));
    }

    private static boolean declaresMultiFactor(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof Collection<?> methods) {
            for (Object method : methods) {
                if (declaresMultiFactor(method)) {
                    return true;
                }
            }
            return false;
        }
        String text = String.valueOf(value).toLowerCase(Locale.ROOT);
        return text.contains("mfa") || text.contains("otp") || text.contains("hwk")
                || text.contains("swk") || text.contains("fido");
    }

    private static Long asEpochSeconds(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String text) {
            try {
                return Long.parseLong(text.trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Seals the administrative kill action in the shared ledger chain. The entry carries the
     * operator, target, outcome, and reason; no token or credential is recorded.
     */
    private void recordAdministrativeEntry(String operator, KillTargetType targetType, String targetId,
                                           String reason, String outcome) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("action", "kill");
        entry.put("actor", operator != null ? operator : "unknown");
        entry.put("targetType", targetType.name().toLowerCase(Locale.ROOT));
        entry.put("targetId", targetType == KillTargetType.GLOBAL ? "global" : targetId);
        entry.put("outcome", outcome);
        entry.put("reason", reason);
        entry.put("sealedAt", Instant.now().toString());

        String summary;
        try {
            summary = jsonMapper.writeValueAsString(entry);
        } catch (JsonProcessingException e) {
            logger.error("Failed to serialize the administrative kill audit entry", e);
            summary = "action=kill outcome=" + outcome;
        }
        // The administrative entry is distinguished from a tool interaction by its decision
        // vocabulary, so the tool-interaction query never returns it (C-013).
        try {
            auditLedger.append(AuditRecord.create(
                    operator != null ? operator : "unknown",
                    "admin/emergency-kill",
                    "KILL",
                    0,
                    0.0,
                    summary)).join();
        } catch (java.util.concurrent.CompletionException e) {
            logger.error("Failed to seal the administrative kill audit entry", e);
        }
    }

    private void handleGetSystemStatus(ChannelHandlerContext ctx, boolean keepAlive) {
        KillSwitchDto.SystemStatusResponse response = metrics.buildSystemStatus(killSwitchManager);
        sendJson(ctx, HttpResponseStatus.OK, response, keepAlive);
    }

    private void handleGetMetricsSummary(ChannelHandlerContext ctx, boolean keepAlive) {
        KillSwitchDto.MetricsSummaryResponse response = metrics.buildMetricsSummary();
        sendJson(ctx, HttpResponseStatus.OK, response, keepAlive);
    }

    private void handleGetMetricsTimeseries(ChannelHandlerContext ctx, boolean keepAlive) {
        KillSwitchDto.MetricsTimeseriesResponse response = metrics.buildTimeseries();
        sendJson(ctx, HttpResponseStatus.OK, response, keepAlive);
    }

    private static String bearerToken(FullHttpRequest request) {
        String authHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);
        if (authHeader != null
                && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return authHeader.substring(BEARER_PREFIX.length()).trim();
        }
        return null;
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
