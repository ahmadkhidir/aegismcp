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
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executor;

/**
 * Netty HTTP handler serving the audit record query contract C-013.
 *
 * <p>Every request is authenticated through the injected authorizer built from the verified OIDC
 * token; a missing or invalid token is {@code 401} and a verified principal without the
 * {@code admin} or {@code auditor} role is {@code 403}. Query validation precedes the ledger scan,
 * the scan runs on a worker rather than the event-loop thread, and the arguments themselves are
 * never returned: each record carries only their digest.
 *
 * <p>Anchors: FEAT-007, FEAT-008, FEAT-011, C-013, NFR-029.
 */
@ChannelHandler.Sharable
public class AuditRecordsHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(AuditRecordsHandler.class);
    public static final String RECORDS_PATH = "/api/v1/audit/records";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final int DEFAULT_LIMIT = 50;
    public static final int MAX_LIMIT = 500;

    private static final Set<String> DECISIONS = Set.of("allow", "block", "require_approval");

    private final AuditLedger ledger;
    private final ObjectMapper jsonMapper;
    private final AuditAuthorizer authorizer;
    private final Executor worker;

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

    public AuditRecordsHandler(AuditLedger ledger, ObjectMapper jsonMapper, AuditAuthorizer authorizer) {
        this(ledger, jsonMapper, authorizer, runnable -> Thread.startVirtualThread(runnable));
    }

    public AuditRecordsHandler(AuditLedger ledger, ObjectMapper jsonMapper, AuditAuthorizer authorizer,
                               Executor worker) {
        super(false); // Manual retain/release control for pipeline pass-through
        this.ledger = Objects.requireNonNull(ledger, "ledger must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
        this.worker = Objects.requireNonNull(worker, "worker must not be null");
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        QueryStringDecoder queryDecoder = new QueryStringDecoder(uri);
        String path = queryDecoder.path();

        if (!RECORDS_PATH.equals(path)) {
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
                logger.warn("Audit records authorization failed closed: {}", e.getMessage());
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

            RecordQuery query;
            try {
                query = RecordQuery.parse(queryDecoder.parameters());
            } catch (IllegalArgumentException e) {
                sendJson(ctx, HttpResponseStatus.BAD_REQUEST, Map.of("error", e.getMessage()), keepAlive);
                return;
            }

            worker.execute(() -> serveRecords(ctx, query, keepAlive));

        } catch (Exception e) {
            logger.error("Error processing an audit records query", e);
            sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    Map.of("error", "Internal server error"), keepAlive);
        } finally {
            request.release();
        }
    }

    private void serveRecords(ChannelHandlerContext ctx, RecordQuery query, boolean keepAlive) {
        List<AuditRecordDto> matching;
        try {
            matching = queryRecords(query);
        } catch (RuntimeException e) {
            logger.error("Ledger records could not be read", e);
            ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.SERVICE_UNAVAILABLE,
                    Map.of("error", "The ledger store is unreachable"), keepAlive));
            return;
        }

        int total = matching.size();
        int fromIndex = Math.min(query.offset(), total);
        int toIndex = Math.min(fromIndex + query.limit(), total);
        AuditRecordsResponse response = new AuditRecordsResponse(
                List.copyOf(matching.subList(fromIndex, toIndex)), total);
        ctx.executor().execute(() -> sendJson(ctx, HttpResponseStatus.OK, response, keepAlive));
    }

    /**
     * Collects matching tool-interaction records in block-index descending order. Administrative
     * entries are skipped: they occupy an index in the same chain but are not tool interactions.
     */
    private List<AuditRecordDto> queryRecords(RecordQuery query) {
        List<AuditRecordDto> result = new ArrayList<>();
        long latestIndex = ledger.getLatestBlockIndex();

        for (long i = latestIndex; i >= 0; i--) {
            AuditBlock block = ledger.getBlock(i);
            if (block == null || block.getBlockIndex() == 0) {
                continue;
            }

            List<AuditRecord> records = block.getRecords();
            if (records.isEmpty()) {
                continue;
            }

            for (AuditRecord record : records) {
                String decision = normalizeDecision(record.getDecision());
                if (decision == null) {
                    continue;
                }
                if (matches(query, block, record, decision)) {
                    result.add(new AuditRecordDto(
                            block.getBlockIndex(),
                            block.getBlockHash(),
                            block.getParentHash(),
                            record.getAgentId(),
                            record.getToolName(),
                            sha256Hex(record.getPayloadSummary()),
                            decision,
                            record.getRedactionCount(),
                            record.getLatencyMs(),
                            record.getTimestamp(),
                            null
                    ));
                }
            }
        }

        return result;
    }

    private boolean matches(RecordQuery query, AuditBlock block, AuditRecord record, String decision) {
        if (query.agentId() != null && !query.agentId().equals(record.getAgentId())) {
            return false;
        }
        if (query.toolName() != null && !query.toolName().equals(record.getToolName())) {
            return false;
        }
        if (query.decision() != null && !query.decision().equals(decision)) {
            return false;
        }
        if (query.blockHash() != null
                && !query.blockHash().equalsIgnoreCase(block.getBlockHash())) {
            return false;
        }

        Instant timestamp;
        try {
            timestamp = Instant.parse(record.getTimestamp());
        } catch (DateTimeParseException e) {
            return false;
        }
        if (query.from() != null && timestamp.isBefore(query.from())) {
            return false;
        }
        return query.to() == null || !timestamp.isAfter(query.to());
    }

    /** Maps the ledger's stored decision names onto the contract vocabulary. */
    private static String normalizeDecision(String decision) {
        if (decision == null) {
            return null;
        }
        String normalized = decision.trim().toLowerCase(Locale.ROOT);
        if (normalized.startsWith("block") || normalized.equals("deny") || normalized.startsWith("denied")) {
            return "block";
        }
        if (normalized.startsWith("require") || normalized.equals("pending")) {
            return "require_approval";
        }
        if (normalized.startsWith("allow") || normalized.equals("permitted")) {
            return "allow";
        }
        // Administrative action entries are sealed in the same chain but are not tool
        // interactions; the query excludes them (C-013).
        return null;
    }

    private static String sha256Hex(String value) {
        return HashUtils.sha256Hex(value != null ? value : "");
    }

    private static String bearerToken(FullHttpRequest request) {
        String authHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);
        if (authHeader != null
                && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return authHeader.substring(BEARER_PREFIX.length()).trim();
        }
        return null;
    }

    /** A validated C-013 query; every rejected parameter is a 400 rather than a silent default. */
    private record RecordQuery(
            String agentId,
            String toolName,
            String decision,
            String blockHash,
            Instant from,
            Instant to,
            int limit,
            int offset
    ) {
        static RecordQuery parse(Map<String, List<String>> parameters) {
            String decision = first(parameters, "decision");
            if (decision != null) {
                decision = decision.trim().toLowerCase(Locale.ROOT);
                if (!DECISIONS.contains(decision)) {
                    throw new IllegalArgumentException(
                            "Invalid query parameter 'decision': expected one of allow, block, require_approval");
                }
            }

            int limit = parseLimit(parameters.get("limit"));
            int offset = parseOffset(parameters.get("offset"));

            return new RecordQuery(
                    blankToNull(first(parameters, "agentId")),
                    blankToNull(first(parameters, "toolName")),
                    decision,
                    blankToNull(first(parameters, "blockHash")),
                    parseInstant(parameters, "from"),
                    parseInstant(parameters, "to"),
                    limit,
                    offset
            );
        }

        private static String first(Map<String, List<String>> parameters, String name) {
            List<String> values = parameters.get(name);
            return values != null && !values.isEmpty() ? values.get(0) : null;
        }

        private static String blankToNull(String value) {
            return value != null && !value.isBlank() ? value.trim() : null;
        }

        private static int parseLimit(List<String> values) {
            if (values == null || values.isEmpty() || values.get(0) == null || values.get(0).isBlank()) {
                return DEFAULT_LIMIT;
            }
            try {
                int value = Integer.parseInt(values.get(0).trim());
                if (value < 1 || value > MAX_LIMIT) {
                    throw new IllegalArgumentException(
                            "Invalid query parameter 'limit': expected an integer from 1 to " + MAX_LIMIT);
                }
                return value;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(
                        "Invalid query parameter 'limit': expected an integer from 1 to " + MAX_LIMIT);
            }
        }

        private static int parseOffset(List<String> values) {
            if (values == null || values.isEmpty() || values.get(0) == null || values.get(0).isBlank()) {
                return 0;
            }
            try {
                int value = Integer.parseInt(values.get(0).trim());
                if (value < 0) {
                    throw new IllegalArgumentException(
                            "Invalid query parameter 'offset': expected an integer of zero or greater");
                }
                return value;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(
                        "Invalid query parameter 'offset': expected an integer of zero or greater");
            }
        }

        private static Instant parseInstant(Map<String, List<String>> parameters, String name) {
            String value = first(parameters, name);
            if (value == null || value.isBlank()) {
                return null;
            }
            try {
                return Instant.parse(value.trim());
            } catch (DateTimeParseException e) {
                throw new IllegalArgumentException(
                        "Invalid query parameter '" + name + "': expected an ISO-8601 date-time");
            }
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
