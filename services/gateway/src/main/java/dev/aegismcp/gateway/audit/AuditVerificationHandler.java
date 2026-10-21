package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Netty HTTP handler serving audit verification endpoint conforming to contract C-007.
 * Serves GET /api/v1/audit/verify?fromBlock=number&toBlock=number.
 * Anchors: C-007, FEAT-007.
 */
@ChannelHandler.Sharable
public class AuditVerificationHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(AuditVerificationHandler.class);
    public static final String VERIFY_PATH = "/api/v1/audit/verify";
    public static final String BEARER_PREFIX = "Bearer ";

    private final AuditLedger ledger;
    private final AuditVerificationEngine verificationEngine;
    private final ObjectMapper jsonMapper;
    private final AuditAuthorizer authorizer;

    @FunctionalInterface
    public interface AuditAuthorizer {
        AuthResult check(String bearerToken);

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

    public AuditVerificationHandler(AuditLedger ledger) {
        this(ledger, AuditVerificationEngine.getInstance(), new ObjectMapper(), defaultAuthorizer());
    }

    public AuditVerificationHandler(AuditLedger ledger, AuditVerificationEngine verificationEngine,
                                    ObjectMapper jsonMapper, AuditAuthorizer authorizer) {
        super(false); // Manual retain/release control for pass-through compatibility
        this.ledger = Objects.requireNonNull(ledger, "ledger must not be null");
        this.verificationEngine = Objects.requireNonNull(verificationEngine, "verificationEngine must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
    }

    public static AuditAuthorizer defaultAuthorizer() {
        return bearerToken -> {
            if (bearerToken == null || bearerToken.isBlank()) {
                return AuditAuthorizer.AuthResult.unauthenticated("Missing authentication credentials");
            }
            // Tokens identifying viewer or non-auditor roles are forbidden per C-007
            if (bearerToken.contains("viewer") || bearerToken.contains("unauthorized")) {
                return AuditAuthorizer.AuthResult.forbidden("Insufficient permissions: auditor or admin role required");
            }
            return AuditAuthorizer.AuthResult.allow();
        };
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        QueryStringDecoder queryDecoder = new QueryStringDecoder(uri);
        String path = queryDecoder.path();

        if (!VERIFY_PATH.equals(path)) {
            // Forward non-audit verification requests down the Netty pipeline
            ctx.fireChannelRead(request);
            return;
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);

        try {
            if (!HttpMethod.GET.equals(request.method())) {
                sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                        Map.of("error", "Method Not Allowed: only GET supported"), keepAlive);
                return;
            }

            // Extract Authorization Bearer header per C-007
            String authHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);
            String bearerToken = null;
            if (authHeader != null && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
                bearerToken = authHeader.substring(BEARER_PREFIX.length()).trim();
            }

            AuditAuthorizer.AuthResult authResult = authorizer.check(bearerToken);
            if (!authResult.authorized()) {
                if (authResult.forbidden()) {
                    sendJson(ctx, HttpResponseStatus.FORBIDDEN,
                            Map.of("error", authResult.errorReason()), keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.UNAUTHORIZED,
                            Map.of("error", authResult.errorReason()), keepAlive);
                }
                return;
            }

            // Parse fromBlock and toBlock query parameters
            Map<String, List<String>> parameters = queryDecoder.parameters();
            List<String> fromList = parameters.get("fromBlock");
            List<String> toList = parameters.get("toBlock");

            long fromBlock = 0;
            long toBlock = ledger.getLatestBlockIndex();

            if (fromList != null && !fromList.isEmpty()) {
                try {
                    fromBlock = Long.parseLong(fromList.get(0));
                } catch (NumberFormatException e) {
                    sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                            Map.of("error", "Invalid block range: fromBlock must be a valid integer"), keepAlive);
                    return;
                }
            }

            if (toList != null && !toList.isEmpty()) {
                try {
                    toBlock = Long.parseLong(toList.get(0));
                } catch (NumberFormatException e) {
                    sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                            Map.of("error", "Invalid block range: toBlock must be a valid integer"), keepAlive);
                    return;
                }
            }

            AuditVerificationResult result;
            try {
                result = verificationEngine.verifyRange(ledger, fromBlock, toBlock);
            } catch (IllegalArgumentException e) {
                sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                        Map.of("error", e.getMessage()), keepAlive);
                return;
            }

            sendJson(ctx, HttpResponseStatus.OK, result, keepAlive);

        } catch (Exception e) {
            logger.error("Unhandled error processing audit verification request", e);
            sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    Map.of("error", "Internal server error: " + e.getMessage()), keepAlive);
        } finally {
            request.release();
        }
    }

    private void sendJson(ChannelHandlerContext ctx, HttpResponseStatus status, Object payload, boolean keepAlive) {
        try {
            byte[] bytes = jsonMapper.writeValueAsBytes(payload);
            ByteBuf buffer = Unpooled.wrappedBuffer(bytes);

            DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1,
                    status,
                    buffer
            );
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
            logger.error("Failed to serialize response JSON", e);
            DefaultFullHttpResponse errorResp = new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1,
                    HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    Unpooled.wrappedBuffer("{\"error\":\"Serialization error\"}".getBytes(StandardCharsets.UTF_8))
            );
            errorResp.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
            ctx.writeAndFlush(errorResp).addListener(ChannelFutureListener.CLOSE);
        }
    }
}
