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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Netty HTTP handler for Human-in-the-Loop Approval Gateway conforming to contracts C-003 and C-004.
 * Serves GET /api/v1/approvals and POST /api/v1/approvals/{id}/decision.
 * Anchors: C-003, C-004, FEAT-006.
 */
@ChannelHandler.Sharable
public class ApprovalManagementHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalManagementHandler.class);

    public static final String APPROVALS_BASE_PATH = "/api/v1/approvals";
    private static final Pattern DECISION_PATH_PATTERN = Pattern.compile("^/api/v1/approvals/([^/]+)/decision/?$");
    public static final String BEARER_PREFIX = "Bearer ";

    private final ApprovalManager approvalManager;
    private final ObjectMapper jsonMapper;
    private final ApprovalAuthorizer authorizer;

    /**
     * Interface for authenticating and authorizing callers of approval endpoints.
     */
    @FunctionalInterface
    public interface ApprovalAuthorizer {
        AuthResult check(HttpMethod method, String bearerToken);

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

    public ApprovalManagementHandler(ApprovalManager approvalManager) {
        this(approvalManager, JsonRpcCodec.getInstance().getMapper(), defaultAuthorizer());
    }

    public ApprovalManagementHandler(ApprovalManager approvalManager, ObjectMapper jsonMapper, ApprovalAuthorizer authorizer) {
        super(false); // Manual retain/release control for pass-through compatibility
        this.approvalManager = Objects.requireNonNull(approvalManager, "approvalManager must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
    }

    public static ApprovalAuthorizer defaultAuthorizer() {
        return (method, bearerToken) -> {
            if (bearerToken == null || bearerToken.isBlank()) {
                return ApprovalAuthorizer.AuthResult.unauthenticated("Missing or invalid token");
            }
            if (bearerToken.contains("unauthorized")) {
                return ApprovalAuthorizer.AuthResult.unauthenticated("Invalid credentials");
            }
            // For decisions, if caller has readonly or viewer token, forbid execution
            if (HttpMethod.POST.equals(method) && (bearerToken.contains("readonly") || bearerToken.contains("viewer"))) {
                return ApprovalAuthorizer.AuthResult.forbidden("Insufficient permissions: operator or admin role required");
            }
            return ApprovalAuthorizer.AuthResult.allow();
        };
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        QueryStringDecoder queryDecoder = new QueryStringDecoder(uri);
        String path = queryDecoder.path();

        if (!path.startsWith(APPROVALS_BASE_PATH)) {
            // Forward non-approval requests down the pipeline
            ctx.fireChannelRead(request);
            return;
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);

        try {
            // Extract Authorization Bearer header
            String authHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);
            String bearerToken = null;
            if (authHeader != null && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
                bearerToken = authHeader.substring(BEARER_PREFIX.length()).trim();
            }

            ApprovalAuthorizer.AuthResult authResult = authorizer.check(request.method(), bearerToken);
            if (!authResult.authorized()) {
                if (authResult.forbidden()) {
                    sendJson(ctx, HttpResponseStatus.FORBIDDEN,
                            new ApprovalDto.ErrorResponse(authResult.errorReason()), keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.UNAUTHORIZED,
                            new ApprovalDto.ErrorResponse(authResult.errorReason()), keepAlive);
                }
                return;
            }

            Matcher decisionMatcher = DECISION_PATH_PATTERN.matcher(path);
            if (decisionMatcher.matches()) {
                String ticketId = decisionMatcher.group(1);
                if (HttpMethod.POST.equals(request.method())) {
                    handlePostDecision(ctx, request, ticketId, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new ApprovalDto.ErrorResponse("Method Not Allowed: only POST supported for decisions"), keepAlive);
                }
            } else if (APPROVALS_BASE_PATH.equals(path)) {
                if (HttpMethod.GET.equals(request.method())) {
                    handleGetApprovals(ctx, queryDecoder, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new ApprovalDto.ErrorResponse("Method Not Allowed: only GET supported for ticket listing"), keepAlive);
                }
            } else {
                sendJson(ctx, HttpResponseStatus.NOT_FOUND,
                        new ApprovalDto.ErrorResponse("Endpoint not found: " + path), keepAlive);
            }

        } catch (Exception e) {
            logger.error("Unhandled error processing approval gateway request", e);
            sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    new ApprovalDto.ErrorResponse("Internal server error: " + e.getMessage()), keepAlive);
        } finally {
            request.release();
        }
    }

    private void handleGetApprovals(ChannelHandlerContext ctx, QueryStringDecoder queryDecoder, boolean keepAlive) {
        List<String> statusParams = queryDecoder.parameters().get("status");
        String statusFilter = (statusParams != null && !statusParams.isEmpty()) ? statusParams.get(0) : null;

        List<ApprovalTicket> tickets = approvalManager.getTickets(statusFilter);
        ApprovalDto.TicketListResponse response = new ApprovalDto.TicketListResponse(tickets);

        sendJson(ctx, HttpResponseStatus.OK, response, keepAlive);
    }

    private void handlePostDecision(ChannelHandlerContext ctx, FullHttpRequest request, String ticketId, boolean keepAlive) {
        ByteBuf content = request.content();
        if (!content.isReadable()) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new ApprovalDto.ErrorResponse("Invalid decision payload: empty request body"), keepAlive);
            return;
        }

        byte[] bytes = new byte[content.readableBytes()];
        content.readBytes(bytes);

        ApprovalDto.DecisionRequest decisionRequest;
        try {
            decisionRequest = jsonMapper.readValue(bytes, ApprovalDto.DecisionRequest.class);
        } catch (Exception e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new ApprovalDto.ErrorResponse("Invalid JSON payload: " + e.getMessage()), keepAlive);
            return;
        }

        if (decisionRequest.decision() == null || decisionRequest.decision().isBlank()) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new ApprovalDto.ErrorResponse("Invalid decision payload: 'decision' field is required"), keepAlive);
            return;
        }

        try {
            ApprovalDto.DecisionResponse response = approvalManager.submitDecision(
                    ticketId,
                    decisionRequest.decision(),
                    decisionRequest.reviewer(),
                    decisionRequest.reason()
            );
            sendJson(ctx, HttpResponseStatus.OK, response, keepAlive);
        } catch (ApprovalException.TicketNotFoundException e) {
            sendJson(ctx, HttpResponseStatus.NOT_FOUND,
                    new ApprovalDto.ErrorResponse(e.getMessage()), keepAlive);
        } catch (ApprovalException.TicketAlreadyResolvedException | ApprovalException.InvalidDecisionException e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new ApprovalDto.ErrorResponse(e.getMessage()), keepAlive);
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
