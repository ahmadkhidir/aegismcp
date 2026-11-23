package dev.aegismcp.gateway.compliance;

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
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;

/**
 * Netty HTTP handler serving the regulatory compliance export contract C-011.
 *
 * <p>Every request is authenticated through the injected authorizer built from the verified OIDC
 * token; a missing or invalid token is {@code 401} and a verified principal without the
 * {@code admin} or {@code auditor} role is {@code 403}. Report generation, including the ledger
 * verification scan, runs on a worker rather than the event-loop thread.
 *
 * <p>Anchors: FEAT-008, FEAT-011, C-011, NFR-029, NFR-040, NFR-041, NFR-042.
 */
@ChannelHandler.Sharable
public class ComplianceExportHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(ComplianceExportHandler.class);
    public static final String COMPLIANCE_EXPORT_PATH = "/api/v1/compliance/export";
    public static final String BEARER_PREFIX = "Bearer ";

    private final ComplianceReportEngine reportEngine;
    private final ObjectMapper jsonMapper;
    private final ComplianceAuthorizer authorizer;
    private final Executor worker;

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

    public ComplianceExportHandler(ComplianceReportEngine reportEngine, ObjectMapper jsonMapper,
                                   ComplianceAuthorizer authorizer) {
        this(reportEngine, jsonMapper, authorizer, runnable -> Thread.startVirtualThread(runnable));
    }

    public ComplianceExportHandler(ComplianceReportEngine reportEngine, ObjectMapper jsonMapper,
                                   ComplianceAuthorizer authorizer, Executor worker) {
        super(false); // Manual retain/release control for pass-through compatibility
        this.reportEngine = Objects.requireNonNull(reportEngine, "reportEngine must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
        this.worker = Objects.requireNonNull(worker, "worker must not be null");
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        QueryStringDecoder queryDecoder = new QueryStringDecoder(uri);
        String path = queryDecoder.path();

        if (!COMPLIANCE_EXPORT_PATH.equals(path)) {
            ctx.fireChannelRead(request);
            return;
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);

        try {
            String bearerToken = bearerToken(request);
            ComplianceAuthorizer.AuthResult authResult;
            try {
                authResult = authorizer.check(bearerToken);
            } catch (RuntimeException e) {
                logger.warn("Compliance authorization failed closed: {}", e.getMessage());
                authResult = ComplianceAuthorizer.AuthResult.unauthenticated("Invalid or missing credentials");
            }
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

            if (!HttpMethod.POST.equals(request.method())) {
                sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                        Map.of("error", "Method Not Allowed: only POST supported"), keepAlive);
                return;
            }

            byte[] bytes = new byte[request.content().readableBytes()];
            request.content().readBytes(bytes);
            if (bytes.length == 0) {
                sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                        Map.of("error", "Missing request body"), keepAlive);
                return;
            }

            ComplianceExportRequest exportRequest;
            try {
                exportRequest = jsonMapper.readValue(bytes, ComplianceExportRequest.class);
            } catch (Exception e) {
                sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                        Map.of("error", "Malformed JSON request payload"), keepAlive);
                return;
            }

            worker.execute(() -> generate(ctx, exportRequest, keepAlive));

        } catch (Exception e) {
            logger.error("Unhandled error processing a compliance export request", e);
            sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    Map.of("error", "Internal server error"), keepAlive);
        } finally {
            request.release();
        }
    }

    private void generate(ChannelHandlerContext ctx, ComplianceExportRequest exportRequest, boolean keepAlive) {
        ComplianceExportResponse response;
        try {
            response = reportEngine.exportReport(exportRequest);
        } catch (IllegalArgumentException e) {
            ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    Map.of("error", e.getMessage()), keepAlive));
            return;
        } catch (LedgerIntegrityException e) {
            long brokenBlockIndex = e.getBrokenAtBlock() != null ? e.getBrokenAtBlock() : -1;
            ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.CONFLICT,
                    Map.of("error", "Cryptographic hash chain broken or integrity compromised",
                            "brokenBlockIndex", brokenBlockIndex), keepAlive));
            return;
        } catch (RuntimeException e) {
            logger.error("Compliance report generation failed", e);
            ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    Map.of("error", "Internal server error"), keepAlive));
            return;
        }

        ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.OK, response, keepAlive));
    }

    private static String bearerToken(FullHttpRequest request) {
        String authHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);
        if (authHeader != null
                && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return authHeader.substring(BEARER_PREFIX.length()).trim();
        }
        return null;
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
