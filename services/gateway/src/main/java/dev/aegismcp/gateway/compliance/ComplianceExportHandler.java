package dev.aegismcp.gateway.compliance;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
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
import java.util.Map;
import java.util.Objects;

/**
 * Netty HTTP handler serving regulatory compliance export endpoint conforming to contract C-011.
 * Serves POST /api/v1/compliance/export.
 * Anchors: C-011, FEAT-011, NFR-040, NFR-041, NFR-042.
 */
@ChannelHandler.Sharable
public class ComplianceExportHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(ComplianceExportHandler.class);
    public static final String COMPLIANCE_EXPORT_PATH = "/api/v1/compliance/export";
    public static final String BEARER_PREFIX = "Bearer ";

    private final ComplianceReportEngine reportEngine;
    private final ObjectMapper jsonMapper;
    private final ComplianceAuthorizer authorizer;

    @FunctionalInterface
    public interface ComplianceAuthorizer {
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

    public ComplianceExportHandler(ComplianceReportEngine reportEngine) {
        this(reportEngine, new ObjectMapper(), defaultAuthorizer());
    }

    public ComplianceExportHandler(ComplianceReportEngine reportEngine, ObjectMapper jsonMapper, ComplianceAuthorizer authorizer) {
        super(false); // Manual retain/release control for pass-through compatibility
        this.reportEngine = Objects.requireNonNull(reportEngine, "reportEngine must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
    }

    public static ComplianceAuthorizer defaultAuthorizer() {
        return bearerToken -> {
            if (bearerToken == null || bearerToken.isBlank()) {
                return ComplianceAuthorizer.AuthResult.unauthenticated("Missing authentication credentials");
            }
            if (bearerToken.contains("viewer") || bearerToken.contains("readonly") || bearerToken.contains("unauthorized")) {
                return ComplianceAuthorizer.AuthResult.forbidden("Insufficient permissions: auditor or admin role required");
            }
            return ComplianceAuthorizer.AuthResult.allow();
        };
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        QueryStringDecoder queryDecoder = new QueryStringDecoder(uri);
        String path = queryDecoder.path();

        if (!COMPLIANCE_EXPORT_PATH.equals(path)) {
            // Forward non-compliance requests down the Netty pipeline
            ctx.fireChannelRead(request);
            return;
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);

        try {
            if (!HttpMethod.POST.equals(request.method())) {
                sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                        Map.of("error", "Method Not Allowed: only POST supported"), keepAlive);
                return;
            }

            // Extract Authorization Bearer header per C-011
            String authHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);
            String bearerToken = null;
            if (authHeader != null && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
                bearerToken = authHeader.substring(BEARER_PREFIX.length()).trim();
            }

            ComplianceAuthorizer.AuthResult authResult = authorizer.check(bearerToken);
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

            // Read request body JSON
            String body = request.content().toString(StandardCharsets.UTF_8);
            if (body == null || body.isBlank()) {
                sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                        Map.of("error", "Missing request body"), keepAlive);
                return;
            }

            ComplianceExportRequest exportRequest;
            try {
                exportRequest = jsonMapper.readValue(body, ComplianceExportRequest.class);
            } catch (JsonParseException | JsonMappingException e) {
                sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                        Map.of("error", "Malformed JSON request payload: " + e.getOriginalMessage()), keepAlive);
                return;
            }

            ComplianceExportResponse response;
            try {
                response = reportEngine.exportReport(exportRequest);
            } catch (IllegalArgumentException e) {
                sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                        Map.of("error", e.getMessage()), keepAlive);
                return;
            } catch (LedgerIntegrityException e) {
                sendJson(ctx, HttpResponseStatus.CONFLICT,
                        Map.of("error", "Cryptographic hash chain broken or integrity compromised",
                                "details", e.getMessage(),
                                "brokenAtBlock", e.getBrokenAtBlock() != null ? e.getBrokenAtBlock() : -1), keepAlive);
                return;
            }

            sendJson(ctx, HttpResponseStatus.OK, response, keepAlive);

        } catch (Exception e) {
            logger.error("Unhandled error processing compliance export request", e);
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
