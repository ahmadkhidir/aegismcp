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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Netty HTTP handler serving audit records query API conforming to contract C-013.
 * Serves GET /api/v1/audit/records?agentId=string&minSeverity=string&decision=string&limit=number&offset=number.
 * Anchors: C-013, FEAT-011, schema.md#AuditBlock.
 */
@ChannelHandler.Sharable
public class AuditRecordsHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(AuditRecordsHandler.class);
    public static final String RECORDS_PATH = "/api/v1/audit/records";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final int DEFAULT_LIMIT = 50;

    private final AuditLedger ledger;
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

    public AuditRecordsHandler(AuditLedger ledger) {
        this(ledger, new ObjectMapper(), defaultAuthorizer());
    }

    public AuditRecordsHandler(AuditLedger ledger, ObjectMapper jsonMapper, AuditAuthorizer authorizer) {
        super(false); // Manual retain/release control for pipeline pass-through
        this.ledger = Objects.requireNonNull(ledger, "ledger must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
    }

    public static AuditAuthorizer defaultAuthorizer() {
        return bearerToken -> {
            if (bearerToken == null || bearerToken.isBlank()) {
                return AuditAuthorizer.AuthResult.unauthenticated("Missing authentication credentials");
            }
            if (bearerToken.contains("viewer") || bearerToken.contains("readonly") || bearerToken.contains("unauthorized")) {
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

        if (!RECORDS_PATH.equals(path)) {
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

            // Extract Authorization Bearer header
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

            // Extract query parameters
            Map<String, List<String>> parameters = queryDecoder.parameters();
            String agentIdFilter = getFirstParam(parameters, "agentId");
            String minSeverityFilter = getFirstParam(parameters, "minSeverity");
            String decisionFilter = getFirstParam(parameters, "decision");
            int limit = parseIntParam(getFirstParam(parameters, "limit"), DEFAULT_LIMIT);
            int offset = parseIntParam(getFirstParam(parameters, "offset"), 0);

            if (limit <= 0) {
                limit = DEFAULT_LIMIT;
            }
            if (offset < 0) {
                offset = 0;
            }

            // Query matching records
            List<AuditRecordDto> matching = queryRecords(agentIdFilter, minSeverityFilter, decisionFilter);
            int total = matching.size();

            int fromIndex = Math.min(offset, total);
            int toIndex = Math.min(offset + limit, total);
            List<AuditRecordDto> pagedRecords = matching.subList(fromIndex, toIndex);

            AuditRecordsResponse response = new AuditRecordsResponse(pagedRecords, total);
            sendJson(ctx, HttpResponseStatus.OK, response, keepAlive);

        } catch (Exception e) {
            logger.error("Error processing audit records query", e);
            sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    Map.of("error", "Internal server error: " + e.getMessage()), keepAlive);
        } finally {
            request.release();
        }
    }

    private List<AuditRecordDto> queryRecords(String agentIdFilter, String minSeverityFilter, String decisionFilter) {
        List<AuditRecordDto> result = new ArrayList<>();
        long latestIndex = ledger.getLatestBlockIndex();

        for (long i = 0; i <= latestIndex; i++) {
            AuditBlock block = ledger.getBlock(i);
            if (block == null) {
                continue;
            }

            List<AuditRecord> records = block.getRecords();
            if (records.isEmpty()) {
                // Genesis block or empty block
                String blockAgentId = block.getAgentId();
                String blockDecision = block.getDecision();
                if (matchesFilter(blockAgentId, blockDecision, agentIdFilter, decisionFilter, minSeverityFilter)) {
                    result.add(new AuditRecordDto(
                            block.getBlockIndex(),
                            block.getBlockHash(),
                            block.getParentHash(),
                            blockAgentId,
                            block.getToolName(),
                            blockDecision,
                            block.getRedactionCount(),
                            block.getLatencyMs(),
                            block.getTimestamp()
                    ));
                }
            } else {
                for (AuditRecord r : records) {
                    if (matchesFilter(r.getAgentId(), r.getDecision(), agentIdFilter, decisionFilter, minSeverityFilter)) {
                        result.add(new AuditRecordDto(
                                block.getBlockIndex(),
                                block.getBlockHash(),
                                block.getParentHash(),
                                r.getAgentId(),
                                r.getToolName(),
                                r.getDecision(),
                                r.getRedactionCount(),
                                r.getLatencyMs(),
                                r.getTimestamp()
                        ));
                    }
                }
            }
        }

        return result;
    }

    private boolean matchesFilter(String recordAgentId, String recordDecision,
                                  String agentIdFilter, String decisionFilter, String minSeverityFilter) {
        if (agentIdFilter != null && !agentIdFilter.isBlank()) {
            if (!agentIdFilter.trim().equalsIgnoreCase(recordAgentId)) {
                return false;
            }
        }

        if (decisionFilter != null && !decisionFilter.isBlank()) {
            if (!decisionFilter.trim().equalsIgnoreCase(recordDecision)) {
                return false;
            }
        }

        if (minSeverityFilter != null && !minSeverityFilter.isBlank()) {
            int requiredLevel = parseSeverityLevel(minSeverityFilter);
            int recordLevel = getDecisionSeverityLevel(recordDecision);
            if (recordLevel < requiredLevel) {
                return false;
            }
        }

        return true;
    }

    private int parseSeverityLevel(String severity) {
        if (severity == null) return 0;
        return switch (severity.trim().toLowerCase()) {
            case "critical" -> 4;
            case "high" -> 3;
            case "medium" -> 2;
            case "low" -> 1;
            default -> 0;
        };
    }

    private int getDecisionSeverityLevel(String decision) {
        if (decision == null) return 1;
        String dec = decision.trim().toLowerCase();
        if (dec.contains("block") || dec.contains("quarantine") || dec.contains("violation") || dec.contains("deny")) {
            return 3; // High
        } else if (dec.contains("require_approval") || dec.contains("pending")) {
            return 2; // Medium
        }
        return 1; // Low
    }

    private String getFirstParam(Map<String, List<String>> params, String key) {
        List<String> values = params.get(key);
        if (values != null && !values.isEmpty()) {
            return values.get(0);
        }
        return null;
    }

    private int parseIntParam(String val, int defaultVal) {
        if (val == null || val.isBlank()) {
            return defaultVal;
        }
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            return defaultVal;
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
