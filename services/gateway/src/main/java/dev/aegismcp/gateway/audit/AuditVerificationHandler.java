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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;

/**
 * Netty HTTP handler serving the ledger-integrity read model (C-015) and the retired range
 * verification path it replaced.
 *
 * <p>The handler authenticates every request through the injected authorizer, which is built from
 * the verified OIDC token; the ledger scan runs on a worker, never on the event-loop thread, and
 * the response is written back on the channel's own executor.
 *
 * <p>Anchors: FEAT-007, FEAT-008, C-015, NFR-029.
 */
@ChannelHandler.Sharable
public class AuditVerificationHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(AuditVerificationHandler.class);
    public static final String VERIFY_PATH = "/api/v1/audit/verify";
    public static final String INTEGRITY_PATH = "/api/v1/audit/integrity";
    public static final String BEARER_PREFIX = "Bearer ";

    private final AuditLedger ledger;
    private final AuditVerificationEngine verificationEngine;
    private final ObjectMapper jsonMapper;
    private final AuditAuthorizer authorizer;
    private final Executor worker;

    /** The most recent completed chain verification, as C-015 reports it. */
    public record IntegritySnapshot(boolean valid, long totalVerifiedBlocks, String lastVerifiedAt) {
    }

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

    public AuditVerificationHandler(AuditLedger ledger, AuditVerificationEngine verificationEngine,
                                    ObjectMapper jsonMapper, AuditAuthorizer authorizer) {
        this(ledger, verificationEngine, jsonMapper, authorizer,
                runnable -> Thread.startVirtualThread(runnable));
    }

    public AuditVerificationHandler(AuditLedger ledger, AuditVerificationEngine verificationEngine,
                                    ObjectMapper jsonMapper, AuditAuthorizer authorizer, Executor worker) {
        super(false); // Manual retain/release control for pass-through compatibility
        this.ledger = Objects.requireNonNull(ledger, "ledger must not be null");
        this.verificationEngine = Objects.requireNonNull(verificationEngine, "verificationEngine must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
        this.worker = Objects.requireNonNull(worker, "worker must not be null");
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        QueryStringDecoder queryDecoder = new QueryStringDecoder(uri);
        String path = queryDecoder.path();

        if (!VERIFY_PATH.equals(path) && !INTEGRITY_PATH.equals(path)) {
            // Forward non-audit requests down the Netty pipeline
            ctx.fireChannelRead(request);
            return;
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);

        try {
            String bearerToken = bearerToken(request);
            AuditAuthorizer.AuthResult authResult;
            try {
                authResult = authorizer.check(bearerToken);
            } catch (RuntimeException e) {
                logger.warn("Audit authorization failed closed: {}", e.getMessage());
                authResult = AuditAuthorizer.AuthResult.unauthenticated("Invalid or missing credentials");
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

            if (!HttpMethod.GET.equals(request.method())) {
                sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                        Map.of("error", "Method Not Allowed: only GET supported"), keepAlive);
                return;
            }

            if (INTEGRITY_PATH.equals(path)) {
                worker.execute(() -> serveIntegrity(ctx, keepAlive));
                return;
            }

            Map<String, List<String>> parameters = queryDecoder.parameters();
            long fromBlock;
            long toBlock;
            try {
                fromBlock = parseBlock(parameters.get("fromBlock"), 0L);
                toBlock = parseBlock(parameters.get("toBlock"), ledger.getLatestBlockIndex());
            } catch (IllegalArgumentException e) {
                sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                        Map.of("error", e.getMessage()), keepAlive);
                return;
            }

            worker.execute(() -> serveRangeVerification(ctx, fromBlock, toBlock, keepAlive));

        } catch (Exception e) {
            logger.error("Unhandled error processing an audit verification request", e);
            sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    Map.of("error", "Internal server error"), keepAlive);
        } finally {
            request.release();
        }
    }

    private void serveIntegrity(ChannelHandlerContext ctx, boolean keepAlive) {
        IntegritySnapshot snapshot;
        try {
            snapshot = verifyWholeChain();
        } catch (RuntimeException e) {
            logger.error("Ledger integrity verification failed", e);
            ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.SERVICE_UNAVAILABLE,
                    Map.of("error", "Ledger integrity could not be read"), keepAlive));
            return;
        }
        IntegritySnapshot result = snapshot;
        ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.OK, result, keepAlive));
    }

    private IntegritySnapshot verifyWholeChain() {
        long latest = ledger.getLatestBlockIndex();
        AuditVerificationResult result = verificationEngine.verifyRange(ledger, 0, latest);
        return new IntegritySnapshot(
                result.valid(),
                result.checkedBlocks(),
                Instant.now().toString());
    }

    private void serveRangeVerification(ChannelHandlerContext ctx, long fromBlock, long toBlock,
                                        boolean keepAlive) {
        AuditVerificationResult result;
        try {
            result = verificationEngine.verifyRange(ledger, fromBlock, toBlock);
        } catch (IllegalArgumentException e) {
            ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    Map.of("error", e.getMessage()), keepAlive));
            return;
        } catch (RuntimeException e) {
            logger.error("Ledger range verification failed", e);
            ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.SERVICE_UNAVAILABLE,
                    Map.of("error", "Ledger integrity could not be read"), keepAlive));
            return;
        }
        ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.OK, result, keepAlive));
    }

    private static String bearerToken(FullHttpRequest request) {
        String authHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);
        if (authHeader != null
                && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return authHeader.substring(BEARER_PREFIX.length()).trim();
        }
        return null;
    }

    private static long parseBlock(List<String> values, long defaultValue) {
        if (values == null || values.isEmpty()) {
            return defaultValue;
        }
        String raw = values.get(0);
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        try {
            long value = Long.parseLong(raw.trim());
            if (value < 0) {
                throw new IllegalArgumentException("Invalid block range: block indices must not be negative");
            }
            return value;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid block range: block boundaries must be a valid integer");
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
