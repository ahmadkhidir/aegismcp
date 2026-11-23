package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
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
import java.util.Set;
import java.util.UUID;

/**
 * Netty HTTP handler for the declarative policy management contracts C-005, C-006, C-017, and
 * C-018. Serves the policy catalogue, the publish path, and the active-document read and
 * activation paths.
 *
 * <p>Every request is authenticated through the injected authorizer built from the verified OIDC
 * token; a missing or invalid token is {@code 401}, a verified principal without the contract
 * role is {@code 403}. No decision is taken from a caller-supplied header.
 *
 * <p>Anchors: FEAT-002, FEAT-008, C-005, C-006, C-017, C-018, NFR-029.
 */
@ChannelHandler.Sharable
public class PolicyManagementHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(PolicyManagementHandler.class);
    public static final String POLICIES_PATH = "/api/v1/policies";
    public static final String ACTIVE_POLICY_PATH = "/api/v1/policies/active";
    public static final String POLICIES_SIMULATE_PATH = "/api/v1/policies/simulate";
    public static final String BEARER_PREFIX = "Bearer ";

    private static final Set<String> POLICY_STATUSES = Set.of(
            SecurityPolicy.STATUS_ACTIVE, SecurityPolicy.STATUS_DRAFT, SecurityPolicy.STATUS_ARCHIVED);

    private final PolicyCache policyCache;
    private final PolicyCompiler policyCompiler;
    private final ObjectMapper jsonMapper;
    private final PolicyAuthorizer authorizer;
    private final dev.aegismcp.gateway.validation.DynamicParameterValidator parameterValidator;
    private final PolicyEvaluator policyEvaluator;

    /**
     * Authenticates and authorizes a caller of a policy management endpoint. The HTTP method
     * selects the contract role set: readable paths accept {@code admin}, {@code operator}, or
     * {@code auditor}, while publishing and activation require {@code admin}.
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

    public PolicyManagementHandler(PolicyCache policyCache, PolicyCompiler policyCompiler,
                                   ObjectMapper jsonMapper, PolicyAuthorizer authorizer) {
        this(policyCache, policyCompiler, jsonMapper, authorizer,
                new dev.aegismcp.gateway.validation.DynamicParameterValidator());
    }

    public PolicyManagementHandler(PolicyCache policyCache, PolicyCompiler policyCompiler,
                                   ObjectMapper jsonMapper, PolicyAuthorizer authorizer,
                                   dev.aegismcp.gateway.validation.DynamicParameterValidator parameterValidator) {
        super(false); // Manual retain/release control for pass-through compatibility
        this.policyCache = Objects.requireNonNull(policyCache, "policyCache must not be null");
        this.policyCompiler = Objects.requireNonNull(policyCompiler, "policyCompiler must not be null");
        this.jsonMapper = Objects.requireNonNull(jsonMapper, "jsonMapper must not be null");
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer must not be null");
        this.parameterValidator = parameterValidator;
        this.policyEvaluator = new PolicyEvaluator(policyCache, parameterValidator);
    }

    /** Convenience constructor for the shipped path: the platform JSON mapper and validator. */
    public PolicyManagementHandler(PolicyCache policyCache, PolicyAuthorizer authorizer) {
        this(policyCache, PolicyCompiler.getInstance(), JsonRpcCodec.getInstance().getMapper(), authorizer);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String uri = request.uri();
        QueryStringDecoder queryDecoder = new QueryStringDecoder(uri);
        String path = queryDecoder.path();

        if (!POLICIES_PATH.equals(path) && !ACTIVE_POLICY_PATH.equals(path)
                && !POLICIES_SIMULATE_PATH.equals(path)) {
            // Forward non-policy requests down the pipeline
            ctx.fireChannelRead(request);
            return;
        }

        boolean keepAlive = HttpUtil.isKeepAlive(request);

        try {
            String bearerToken = bearerToken(request);
            PolicyAuthorizer.AuthResult authResult;
            try {
                authResult = authorizer.check(request.method(), bearerToken);
            } catch (RuntimeException e) {
                logger.warn("Policy authorization failed closed: {}", e.getMessage());
                authResult = PolicyAuthorizer.AuthResult.unauthenticated("Invalid or missing credentials");
            }
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

            if (ACTIVE_POLICY_PATH.equals(path)) {
                if (HttpMethod.GET.equals(request.method())) {
                    handleGetActivePolicy(ctx, keepAlive);
                } else if (HttpMethod.PUT.equals(request.method())) {
                    handleActivatePolicy(ctx, request, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new PolicyDto.ErrorResponse("Method Not Allowed: only GET and PUT supported for the active policy"),
                            keepAlive);
                }
            } else if (POLICIES_SIMULATE_PATH.equals(path)) {
                if (HttpMethod.POST.equals(request.method())) {
                    handleSimulatePolicy(ctx, request, keepAlive);
                } else {
                    sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                            new PolicyDto.ErrorResponse("Method Not Allowed: only POST supported for policy simulation"),
                            keepAlive);
                }
            } else if (HttpMethod.GET.equals(request.method())) {
                handleGetPolicies(ctx, queryDecoder, keepAlive);
            } else if (HttpMethod.POST.equals(request.method())) {
                handlePostPolicy(ctx, request, keepAlive);
            } else {
                sendJson(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED,
                        new PolicyDto.ErrorResponse("Method Not Allowed: only GET and POST supported"),
                        keepAlive);
            }

        } catch (Exception e) {
            // Exception text can carry policy or provider detail; it stays in the log.
            logger.error("Unhandled error processing a policy management request", e);
            sendJson(ctx, HttpResponseStatus.INTERNAL_SERVER_ERROR,
                    new PolicyDto.ErrorResponse("Internal server error"), keepAlive);
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

    private void handleGetPolicies(ChannelHandlerContext ctx, QueryStringDecoder queryDecoder, boolean keepAlive) {
        List<String> statusParams = queryDecoder.parameters().get("status");
        String statusFilter = (statusParams != null && !statusParams.isEmpty()) ? statusParams.get(0) : null;
        if (statusFilter != null && !statusFilter.isBlank()
                && !POLICY_STATUSES.contains(statusFilter.trim().toLowerCase())) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse(
                            "Invalid query parameter 'status': expected one of active, draft, archived"),
                    keepAlive);
            return;
        }

        List<SecurityPolicy> policies = policyCache.getAllPolicies(statusFilter);
        sendJson(ctx, HttpResponseStatus.OK, new PolicyDto.PolicyListResponse(policies), keepAlive);
    }

    private void handleGetActivePolicy(ChannelHandlerContext ctx, boolean keepAlive) {
        SecurityPolicy active = policyCache.getActivePolicy();
        if (active == null) {
            sendJson(ctx, HttpResponseStatus.NOT_FOUND,
                    new PolicyDto.ErrorResponse("No policy version is active"), keepAlive);
            return;
        }
        sendJson(ctx, HttpResponseStatus.OK, active, keepAlive);
    }

    /**
     * Publishes a policy version as a draft (C-006). A document identical to an already published
     * draft returns that record rather than creating a duplicate; a draft never governs traffic.
     */
    private void handlePostPolicy(ChannelHandlerContext ctx, FullHttpRequest request, boolean keepAlive) {
        byte[] bytes = readBody(request);
        if (bytes.length == 0) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Empty request body"), keepAlive);
            return;
        }

        PolicyDto.CreatePolicyRequest createRequest;
        try {
            createRequest = jsonMapper.readValue(bytes, PolicyDto.CreatePolicyRequest.class);
        } catch (Exception e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Invalid JSON payload"), keepAlive);
            return;
        }
        if (createRequest == null || isBlank(createRequest.rawYaml())) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Invalid policy payload: 'rawYaml' is required"),
                    keepAlive);
            return;
        }

        PolicyAst compiledAst;
        try {
            compiledAst = policyCompiler.compile(createRequest.rawYaml());
        } catch (PolicyCompilationException e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Syntax error in YAML or invalid AST policy rules"),
                    keepAlive);
            return;
        }

        SecurityPolicy existing = policyCache.findByRawYaml(createRequest.rawYaml());
        if (existing != null && SecurityPolicy.STATUS_DRAFT.equals(existing.status())) {
            sendJson(ctx, HttpResponseStatus.CREATED, toCreateResponse(existing), keepAlive);
            return;
        }

        String policyId = versionRecordId(compiledAst, createRequest.version());
        SecurityPolicy policy = new SecurityPolicy(
                policyId,
                createRequest.name(),
                createRequest.version(),
                createRequest.rawYaml(),
                SecurityPolicy.STATUS_DRAFT,
                createRequest.gitCommitHash(),
                Instant.now().toString()
        );

        try {
            policyCache.putPolicy(policy);
        } catch (PolicyCompilationException e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Syntax error in YAML or invalid AST policy rules"),
                    keepAlive);
            return;
        }

        sendJson(ctx, HttpResponseStatus.CREATED, toCreateResponse(policy), keepAlive);
    }

    private static PolicyDto.CreatePolicyResponse toCreateResponse(SecurityPolicy policy) {
        return new PolicyDto.CreatePolicyResponse(
                policy.id(), policy.name(), policy.version(), policy.status(), policy.createdAt());
    }

    /**
     * Selects the catalogue record identifier for a policy version. The declared policy identifier
     * is reused while it names no other version; a second version of the same policy gets a
     * version-qualified record so every published version stays readable through C-005.
     */
    private String versionRecordId(PolicyAst ast, String declaredVersion) {
        String baseId = ast.id() != null && !ast.id().isBlank()
                ? ast.id()
                : "pol_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String version = declaredVersion != null && !declaredVersion.isBlank()
                ? declaredVersion
                : ast.version();

        SecurityPolicy existing = policyCache.getPolicy(baseId);
        if (existing == null || existing.version() == null || existing.version().equals(version)) {
            return baseId;
        }
        String qualified = baseId + "@" + version;
        SecurityPolicy qualifiedRecord = policyCache.getPolicy(qualified);
        if (qualifiedRecord == null || version.equals(qualifiedRecord.version())) {
            return qualified;
        }
        return "pol_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    /**
     * Activates a policy version (C-018). The named base version must still be the active one, the
     * document must compile, and the compiled policy replaces the in-memory cache before the
     * response is returned; a rejected document leaves the previously active version in force.
     */
    private void handleActivatePolicy(ChannelHandlerContext ctx, FullHttpRequest request, boolean keepAlive) {
        byte[] bytes = readBody(request);
        if (bytes.length == 0) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Empty request body"), keepAlive);
            return;
        }

        JsonNode document;
        try {
            document = jsonMapper.readTree(bytes);
        } catch (Exception e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Invalid JSON payload"), keepAlive);
            return;
        }
        if (document == null || !document.isObject() || !document.has("baseVersionId")) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Invalid policy payload: 'baseVersionId' is required"),
                    keepAlive);
            return;
        }

        PolicyDto.ActivatePolicyRequest activateRequest;
        try {
            activateRequest = jsonMapper.treeToValue(document, PolicyDto.ActivatePolicyRequest.class);
        } catch (Exception e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Invalid JSON payload"), keepAlive);
            return;
        }
        if (activateRequest == null || isBlank(activateRequest.rawYaml())) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Invalid policy payload: 'rawYaml' is required"),
                    keepAlive);
            return;
        }

        PolicyAst compiledAst;
        try {
            compiledAst = policyCompiler.compile(activateRequest.rawYaml());
        } catch (PolicyCompilationException e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Syntax error in YAML or invalid AST policy rules"),
                    keepAlive);
            return;
        }

        String baseVersionId = activateRequest.baseVersionId();
        SecurityPolicy currentActive = policyCache.getActivePolicy();
        String currentActiveId = currentActive != null ? currentActive.id() : "";
        String declaredBase = baseVersionId != null ? baseVersionId : "";
        if (!declaredBase.equals(currentActiveId)) {
            sendJson(ctx, HttpResponseStatus.CONFLICT,
                    new PolicyDto.ErrorResponse(
                            "The policy version named by 'baseVersionId' is no longer active"),
                    keepAlive);
            return;
        }

        SecurityPolicy draft = policyCache.findByRawYaml(activateRequest.rawYaml());
        String policyId;
        String name;
        String version;
        String gitCommitHash;
        String createdAt;
        if (draft != null && SecurityPolicy.STATUS_DRAFT.equals(draft.status())) {
            policyId = draft.id();
            name = draft.name();
            version = draft.version();
            gitCommitHash = draft.gitCommitHash();
            createdAt = draft.createdAt();
        } else {
            policyId = versionRecordId(compiledAst, activateRequest.version());
            name = compiledAst.name() != null && !compiledAst.name().isBlank()
                    ? compiledAst.name()
                    : policyId;
            version = activateRequest.version() != null && !activateRequest.version().isBlank()
                    ? activateRequest.version()
                    : compiledAst.version();
            gitCommitHash = null;
            createdAt = Instant.now().toString();
        }

        SecurityPolicy activated;
        try {
            activated = policyCache.activate(new SecurityPolicy(
                    policyId,
                    name,
                    version,
                    activateRequest.rawYaml(),
                    SecurityPolicy.STATUS_ACTIVE,
                    gitCommitHash,
                    createdAt));
        } catch (PolicyCompilationException e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Syntax error in YAML or invalid AST policy rules"),
                    keepAlive);
            return;
        }

        sendJson(ctx, HttpResponseStatus.OK, activated, keepAlive);
    }

    private void handleSimulatePolicy(ChannelHandlerContext ctx, FullHttpRequest request, boolean keepAlive) {
        byte[] bytes = readBody(request);
        if (bytes.length == 0) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Empty request body"), keepAlive);
            return;
        }

        PolicyDto.SimulatePolicyRequest simRequest;
        try {
            simRequest = jsonMapper.readValue(bytes, PolicyDto.SimulatePolicyRequest.class);
        } catch (Exception e) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("Invalid JSON payload"), keepAlive);
            return;
        }

        if (simRequest.agentId() == null || simRequest.agentId().isBlank()
                || simRequest.toolName() == null || simRequest.toolName().isBlank()) {
            sendJson(ctx, HttpResponseStatus.BAD_REQUEST,
                    new PolicyDto.ErrorResponse("agentId and toolName are required"), keepAlive);
            return;
        }

        List<String> violations = new java.util.ArrayList<>();

        // 1. Run dynamic parameter validation (JSON schema, path traversal, SQL injection, command injection)
        if (parameterValidator != null) {
            var valResult = parameterValidator.validate(simRequest.agentId(), simRequest.toolName(), simRequest.arguments());
            if (!valResult.isValid()) {
                for (var v : valResult.violations()) {
                    violations.add(v.message());
                }
                PolicyDto.SimulatePolicyResponse simResponse = new PolicyDto.SimulatePolicyResponse(
                        "BLOCKED",
                        "parameter_validation",
                        violations
                );
                sendJson(ctx, HttpResponseStatus.OK, simResponse, keepAlive);
                return;
            }
        }

        // 2. Evaluate against the active security policy
        dev.aegismcp.gateway.proxy.AgentIdentity identity = new dev.aegismcp.gateway.proxy.AgentIdentity(
                simRequest.agentId(), null, null, true
        );
        PolicyEvaluationResult polResult = policyEvaluator.evaluate(identity, simRequest.toolName(), simRequest.arguments());

        String verdict;
        String ruleMatched = polResult.ruleId();
        if (polResult.isDenied()) {
            verdict = "BLOCKED";
            violations.add(polResult.reason());
        } else if (polResult.isRequireApproval()) {
            verdict = "REQUIRE_APPROVAL";
        } else {
            verdict = "ALLOWED";
        }

        PolicyDto.SimulatePolicyResponse simResponse = new PolicyDto.SimulatePolicyResponse(
                verdict,
                ruleMatched,
                violations
        );
        sendJson(ctx, HttpResponseStatus.OK, simResponse, keepAlive);
    }

    private static byte[] readBody(FullHttpRequest request) {
        ByteBuf content = request.content();
        if (!content.isReadable()) {
            return new byte[0];
        }
        byte[] bytes = new byte[content.readableBytes()];
        content.readBytes(bytes);
        return bytes;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
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

    public dev.aegismcp.gateway.validation.DynamicParameterValidator getParameterValidator() {
        return parameterValidator;
    }

    public PolicyEvaluator getPolicyEvaluator() {
        return policyEvaluator;
    }
}
