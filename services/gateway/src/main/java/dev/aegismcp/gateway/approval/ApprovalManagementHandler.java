package dev.aegismcp.gateway.approval;

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
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Netty HTTP handler for the Human-in-the-Loop approval contracts C-003, C-004, C-014, and C-019.
 * Serves the pending queue, the approve and reject decisions, and the resolution history.
 *
 * <p>Every request is authenticated through the injected authorizer, which must be built from the
 * verified OIDC token: an absent or invalid token is answered {@code 401}, a verified operator
 * without the contract role {@code 403}. The reviewer recorded on a decision is the verified
 * token subject, never a request-body field.
 *
 * <p>Anchors: FEAT-006, FEAT-008, C-003, C-004, C-014, C-019, NFR-029.
 */
@ChannelHandler.Sharable
public class ApprovalManagementHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalManagementHandler.class);

    public static final String APPROVALS_BASE_PATH = "/api/v1/approvals";
    public static final String PENDING_PATH = APPROVALS_BASE_PATH + "/pending";
    private static final Pattern DECISION_PATH_PATTERN =
            Pattern.compile("^/api/v1/approvals/([^/]+)/(approve|reject)/?$");
    public static final String BEARER_PREFIX = "Bearer ";

    private static final Set<String> HISTORY_STATUSES = Set.of("approved", "rejected", "expired");
    private static final int DEFAULT_LIMIT = 50;
    private static final int MAX_LIMIT = 100;

    private final ApprovalManager approvalManager;
    private final ObjectMapper jsonMapper;
    private final ApprovalAuthorizer authorizer;

    /**
     * Authenticates and authorizes a caller of an approval endpoint. The authorizer receives the
     * request path because the pending queue (C-003) and the resolution history (C-019) address
     * different role sets even though both are {@code GET}s.
     */
    @FunctionalInterface
    public interface ApprovalAuthorizer {
        AuthResult check(String path, HttpMethod method, String bearerToken);

        record AuthResult(boolean authorized, boolean forbidden, String errorReason, String subject) {
            public AuthResult(boolean authorized, boolean forbidden, String errorReason) {
                this(authorized, forbidden, errorReason, null);
            }

            public static AuthResult allow() {
                return new AuthResult(true, false, null, null);
            }

            public static AuthResult verified(String subject) {
                return new AuthResult(true, false, null, subject);
            }

            public static AuthResult unauthenticated(String reason) {
                return new AuthResult(false, false, reason, null);
            }

            public static AuthResult forbidden(String reason) {
                return new AuthResult(false, true, reason, null);
            }
        }
    }

    public ApprovalManagementHandler(ApprovalManager approvalManager, ObjectMapper jsonMapper,
                                     ApprovalAuthorizer authorizer) {
        super(false); // Manual retain/release control for pass-through compatibility
        this.approvalManager = Objects.requireNonNull(approvalManager, "approvalManager must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
    }

    /** Convenience constructor for the shipped path: the platform JSON mapper. */
    public ApprovalManagementHandler(ApprovalManager approvalManager, ApprovalAuthorizer authorizer) {
        this(approvalManager, JsonRpcCodec.getInstance().getMapper(), authorizer);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        QueryStringDecoder queryDecoder = new QueryStringDecoder(uri);
        String path = queryDecoder.path();

        if (!path.equals(APPROVALS_BASE_PATH) && !path.startsWith(APPROVALS_BASE_PATH + "/")) {
            // Forward non-approval requests down the pipeline
            ctx.fireChannelRead(request);
            return;
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);

        try {
            String bearerToken = bearerToken(request);
            ApprovalAuthorizer.AuthResult authResult;
            try {
                authResult = authorizer.check(path, request.method(), bearerToken);
            } catch (RuntimeException e) {
                logger.warn("Approval authorization failed closed: {}", e.getMessage());
                authResult = ApprovalAuthorizer.AuthResult
                        .unauthenticated("Invalid or missing credentials");
            }
            if (!authResult.authorized()) {
                sendAuthFailure(ctx, authResult, keepAlive);
                return;
            }

            if (PENDING_PATH.equals(path)) {
                if (HttpMethod.GET.equals(request.method())) {
                    handlePending(ctx, queryDecoder, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new ApprovalDto.ErrorResponse("Method Not Allowed: only GET supported for the pending queue"),
                            keepAlive);
                }
                return;
            }

            Matcher decisionMatcher = DECISION_PATH_PATTERN.matcher(path);
            if (decisionMatcher.matches()) {
                if (!HttpMethod.POST.equals(request.method())) {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new ApprovalDto.ErrorResponse("Method Not Allowed: only POST supported for decisions"),
                            keepAlive);
                    return;
                }
                String ticketId = decisionMatcher.group(1);
                boolean approve = "approve".equals(decisionMatcher.group(2));
                if (approve) {
                    handleApprove(ctx, ticketId, authResult.subject(), keepAlive);
                } else {
                    handleReject(ctx, request, ticketId, authResult.subject(), keepAlive);
                }
                return;
            }

            if (APPROVALS_BASE_PATH.equals(path) || (APPROVALS_BASE_PATH + "/").equals(path)) {
                if (HttpMethod.GET.equals(request.method())) {
                    handleHistory(ctx, queryDecoder, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new ApprovalDto.ErrorResponse("Method Not Allowed: only GET supported for ticket history"),
                            keepAlive);
                }
                return;
            }

            sendJson(ctx, HttpResponseStatus.NOT_FOUND,
                    new ApprovalDto.ErrorResponse("Endpoint not found"), keepAlive);

        } catch (Exception e) {
            // The exception text can carry request or provider detail; it stays out of the body.
            logger.error("Unhandled error processing an approval management request", e);
            sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    new ApprovalDto.ErrorResponse("Internal server error"), keepAlive);
        } finally {
            request.release();
        }
    }

    private static String bearerToken(FullHttpRequest request) {
        String authHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);
        if (authHeader != null
                && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return authHeader.substring(BEARER_PREFIX.length()).trim();
        }
        return null;
    }

    private void sendAuthFailure(
            ChannelHandlerContext ctx,
            ApprovalAuthorizer.AuthResult authResult,
            boolean keepAlive
    ) {
        if (authResult.forbidden()) {
            sendJson(ctx, HttpResponseStatus.FORBIDDEN,
                    new ApprovalDto.ErrorResponse(authResult.errorReason()), keepAlive);
        } else {
            sendJson(ctx, HttpResponseStatus.UNAUTHORIZED,
                    new ApprovalDto.ErrorResponse(authResult.errorReason()), keepAlive);
        }
    }

    private void handlePending(ChannelHandlerContext ctx, QueryStringDecoder queryDecoder, boolean keepAlive) {
        List<String> limitParams = queryDecoder.parameters().get("limit");
        Integer limit = parseBoundedInt(limitParams, DEFAULT_LIMIT, MAX_LIMIT);
        if (limit == null) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new ApprovalDto.ErrorResponse(
                            "Invalid query parameter 'limit': expected an integer from 1 to " + MAX_LIMIT),
                    keepAlive);
            return;
        }

        List<ApprovalDto.PendingTicket> tickets = approvalManager.getPendingTickets(limit).stream()
                .map(ticket -> new ApprovalDto.PendingTicket(
                        ticket.id(),
                        ticket.agentId(),
                        ticket.toolName(),
                        ApprovalManager.maskedArguments(ticket),
                        ticket.triggerPolicyId(),
                        ticket.agentIntent(),
                        ApprovalStatus.PENDING.getValue(),
                        ticket.createdAt(),
                        ticket.expiresAt()))
                .toList();

        sendJson(ctx, HttpResponseStatus.OK, new ApprovalDto.PendingTicketsResponse(tickets), keepAlive);
    }

    private void handleHistory(ChannelHandlerContext ctx, QueryStringDecoder queryDecoder, boolean keepAlive) {
        String status = firstParam(queryDecoder, "status");
        if (status == null || status.isBlank() || !HISTORY_STATUSES.contains(status.trim().toLowerCase())) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new ApprovalDto.ErrorResponse(
                            "Invalid or missing query parameter 'status': expected one of approved, rejected, expired"),
                    keepAlive);
            return;
        }

        Integer limit = parseBoundedInt(queryDecoder.parameters().get("limit"), DEFAULT_LIMIT, MAX_LIMIT);
        if (limit == null) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new ApprovalDto.ErrorResponse(
                            "Invalid query parameter 'limit': expected an integer from 1 to " + MAX_LIMIT),
                    keepAlive);
            return;
        }

        Integer offset = parseNonNegativeInt(queryDecoder.parameters().get("offset"));
        if (offset == null) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new ApprovalDto.ErrorResponse(
                            "Invalid query parameter 'offset': expected an integer of zero or greater"),
                    keepAlive);
            return;
        }

        ApprovalManager.HistoryPage page = approvalManager.getHistory(status, limit, offset);
        List<ApprovalDto.HistoryTicket> tickets = page.tickets().stream()
                .map(ticket -> new ApprovalDto.HistoryTicket(
                        ticket.id(),
                        ticket.agentId(),
                        ticket.toolName(),
                        ApprovalManager.maskedArguments(ticket),
                        historyStatus(ticket),
                        ticket.triggerPolicyId(),
                        ticket.createdAt(),
                        ticket.expiresAt(),
                        ticket.reviewedBy(),
                        ticket.rejectionReason(),
                        ticket.processedAt()))
                .toList();

        sendJson(ctx, HttpResponseStatus.OK, new ApprovalDto.HistoryResponse(tickets, page.total()), keepAlive);
    }

    /** C-019 names a TTL failure {@code expired}; the ticket's internal state is {@code timed_out}. */
    private static String historyStatus(ApprovalTicket ticket) {
        return ApprovalStatus.TIMED_OUT.getValue().equalsIgnoreCase(ticket.status())
                ? "expired"
                : ticket.status();
    }

    private void handleApprove(
            ChannelHandlerContext ctx,
            String ticketId,
            String reviewer,
            boolean keepAlive
    ) {
        try {
            ApprovalTicket ticket = approvalManager.approve(ticketId, reviewer);
            sendJson(ctx, HttpResponseStatus.OK,
                    new ApprovalDto.ApproveResponse(
                            ticket.id(), ticket.status(), ticket.reviewedBy(), ticket.processedAt()),
                    keepAlive);
        } catch (ApprovalException e) {
            sendApprovalFailure(ctx, e, keepAlive);
        }
    }

    private void handleReject(
            ChannelHandlerContext ctx,
            FullHttpRequest request,
            String ticketId,
            String reviewer,
            boolean keepAlive
    ) {
        String body = request.content().toString(StandardCharsets.UTF_8);
        if (body.isBlank()) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new ApprovalDto.ErrorResponse(
                            "Invalid rejection payload: 'reason' is required and must not be blank"),
                    keepAlive);
            return;
        }

        ApprovalDto.RejectRequest rejectRequest;
        try {
            rejectRequest = jsonMapper.readValue(body, ApprovalDto.RejectRequest.class);
        } catch (JsonProcessingException e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new ApprovalDto.ErrorResponse("Invalid JSON payload"), keepAlive);
            return;
        }

        if (rejectRequest == null || rejectRequest.reason() == null || rejectRequest.reason().isBlank()) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new ApprovalDto.ErrorResponse(
                            "Invalid rejection payload: 'reason' is required and must not be blank"),
                    keepAlive);
            return;
        }

        try {
            ApprovalTicket ticket = approvalManager.reject(ticketId, reviewer, rejectRequest.reason());
            sendJson(ctx, HttpResponseStatus.OK,
                    new ApprovalDto.RejectResponse(
                            ticket.id(),
                            ticket.status(),
                            ticket.reviewedBy(),
                            ticket.rejectionReason(),
                            ticket.processedAt()),
                    keepAlive);
        } catch (ApprovalException e) {
            sendApprovalFailure(ctx, e, keepAlive);
        }
    }

    private void sendApprovalFailure(ChannelHandlerContext ctx, ApprovalException e, boolean keepAlive) {
        String message = e.getMessage();
        if (e instanceof ApprovalException.TicketNotFoundException) {
            sendJson(ctx, HttpResponseStatus.NOT_FOUND, new ApprovalDto.ErrorResponse(message), keepAlive);
        } else if (e instanceof ApprovalException.TicketExpiredException) {
            sendJson(ctx, HttpResponseStatus.GONE, new ApprovalDto.ErrorResponse(message), keepAlive);
        } else if (e instanceof ApprovalException.TicketAlreadyResolvedException resolved) {
            String resolver = resolved.resolvingReviewer();
            String detail = resolver != null
                    ? message + " (resolved by " + resolver + ")"
                    : message;
            sendJson(ctx, HttpResponseStatus.CONFLICT, new ApprovalDto.ErrorResponse(detail), keepAlive);
        } else {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST, new ApprovalDto.ErrorResponse(message), keepAlive);
        }
    }

    private static String firstParam(QueryStringDecoder decoder, String name) {
        List<String> values = decoder.parameters().get(name);
        return (values != null && !values.isEmpty()) ? values.get(0) : null;
    }

    /** Parses an integer from 1 to {@code max}; returns null when absent-invalid or out of range. */
    private static Integer parseBoundedInt(List<String> values, int defaultValue, int max) {
        if (values == null || values.isEmpty()) {
            return defaultValue;
        }
        String raw = values.get(0);
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        try {
            int value = Integer.parseInt(raw.trim());
            return (value < 1 || value > max) ? null : value;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Integer parseNonNegativeInt(List<String> values) {
        if (values == null || values.isEmpty()) {
            return 0;
        }
        String raw = values.get(0);
        if (raw == null || raw.isBlank()) {
            return 0;
        }
        try {
            int value = Integer.parseInt(raw.trim());
            return value < 0 ? null : value;
        } catch (NumberFormatException e) {
            return null;
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
            logger.error("Failed to serialize approval response JSON", e);
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
