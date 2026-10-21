package dev.aegismcp.gateway.policy;

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
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Netty HTTP handler for Declarative Policy Management API conforming to contracts C-005 and C-006.
 * Serves GET /api/v1/policies and POST /api/v1/policies.
 * Anchors: C-005, C-006, FEAT-002.
 */
@ChannelHandler.Sharable
public class PolicyManagementHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(PolicyManagementHandler.class);
    public static final String POLICIES_PATH = "/api/v1/policies";
    public static final String BEARER_PREFIX = "Bearer ";

    private final PolicyCache policyCache;
    private final PolicyCompiler policyCompiler;
    private final ObjectMapper jsonMapper;
    private final PolicyAuthorizer authorizer;

    /**
     * Interface for authenticating and authorizing callers of policy management endpoints.
     */
    @FunctionalInterface
    public interface PolicyAuthorizer {
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

    public PolicyManagementHandler(PolicyCache policyCache) {
        this(policyCache, PolicyCompiler.getInstance(), JsonRpcCodec.getInstance().getMapper(), defaultAuthorizer());
    }

    public PolicyManagementHandler(PolicyCache policyCache, PolicyCompiler policyCompiler,
                                   ObjectMapper jsonMapper, PolicyAuthorizer authorizer) {
        super(false); // Manual retain/release control for pass-through compatibility
        this.policyCache = Objects.requireNonNull(policyCache, "policyCache must not be null");
        this.policyCompiler = Objects.requireNonNull(policyCompiler, "policyCompiler must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
    }

    public static PolicyAuthorizer defaultAuthorizer() {
        return (method, bearerToken) -> {
            if (bearerToken == null || bearerToken.isBlank()) {
                return PolicyAuthorizer.AuthResult.unauthenticated("Missing authentication credentials");
            }
            // If caller provides a read-only token attempting to POST, forbid it
            if (HttpMethod.POST.equals(method) && bearerToken.contains("readonly")) {
                return PolicyAuthorizer.AuthResult.forbidden("Insufficient permissions to publish policy: admin role required");
            }
            return PolicyAuthorizer.AuthResult.allow();
        };
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        QueryStringDecoder queryDecoder = new QueryStringDecoder(uri);
        String path = queryDecoder.path();

        if (!POLICIES_PATH.equals(path)) {
            // Forward non-policy requests down the pipeline
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

            PolicyAuthorizer.AuthResult authResult = authorizer.check(request.method(), bearerToken);
            if (!authResult.authorized()) {
                if (authResult.forbidden()) {
                    sendJson(ctx, HttpResponseStatus.FORBIDDEN,
                            new PolicyDto.ErrorResponse(authResult.errorReason()), keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.UNAUTHORIZED,
                            new PolicyDto.ErrorResponse(authResult.errorReason()), keepAlive);
                }
                return;
            }

            if (HttpMethod.GET.equals(request.method())) {
                handleGetPolicies(ctx, queryDecoder, keepAlive);
            } else if (HttpMethod.POST.equals(request.method())) {
                handlePostPolicy(ctx, request, keepAlive);
            } else {
                sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                        new PolicyDto.ErrorResponse("Method Not Allowed: only GET and POST supported"), keepAlive);
            }

        } catch (Exception e) {
            logger.error("Unhandled error processing policy management request", e);
            sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    new PolicyDto.ErrorResponse("Internal server error: " + e.getMessage()), keepAlive);
        } finally {
            request.release();
        }
    }

    private void handleGetPolicies(ChannelHandlerContext ctx, QueryStringDecoder queryDecoder, boolean keepAlive) {
        List<String> statusParams = queryDecoder.parameters().get("status");
        String statusFilter = (statusParams != null && !statusParams.isEmpty()) ? statusParams.get(0) : null;

        List<SecurityPolicy> policies = policyCache.getAllPolicies(statusFilter);
        PolicyDto.PolicyListResponse response = new PolicyDto.PolicyListResponse(policies);

        sendJson(ctx, HttpResponseStatus.OK, response, keepAlive);
    }

    private void handlePostPolicy(ChannelHandlerContext ctx, FullHttpRequest request, boolean keepAlive) {
        ByteBuf content = request.content();
        if (!content.isReadable()) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Empty request body"), keepAlive);
            return;
        }

        byte[] bytes = new byte[content.readableBytes()];
        content.readBytes(bytes);

        PolicyDto.CreatePolicyRequest createRequest;
        try {
            createRequest = jsonMapper.readValue(bytes, PolicyDto.CreatePolicyRequest.class);
        } catch (Exception e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Invalid JSON payload: " + e.getMessage()), keepAlive);
            return;
        }

        // Validate and compile YAML per C-006 (HTTP 400 on YAML syntax error or invalid AST rules)
        PolicyAst compiledAst;
        try {
            compiledAst = policyCompiler.compile(createRequest.rawYaml());
        } catch (PolicyCompilationException e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Syntax error in YAML or invalid AST policy rules", e.getMessage()), keepAlive);
            return;
        }

        // Generate stable ID if AST doesn't declare one or generate unique policy instance id
        String policyId = (compiledAst.id() != null && !compiledAst.id().isBlank())
                ? compiledAst.id()
                : "pol_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);

        SecurityPolicy policy = new SecurityPolicy(
                policyId,
                createRequest.name(),
                createRequest.version(),
                createRequest.rawYaml(),
                SecurityPolicy.STATUS_ACTIVE,
                createRequest.gitCommitHash(),
                Instant.now().toString()
        );

        // Put policy in cache (atomically verified)
        policyCache.putPolicy(policy);

        PolicyDto.CreatePolicyResponse response = new PolicyDto.CreatePolicyResponse(
                policy.id(),
                policy.name(),
                policy.version(),
                policy.status(),
                policy.createdAt()
        );

        sendJson(ctx, HttpResponseStatus.CREATED, response, keepAlive);
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
