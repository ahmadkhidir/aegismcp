package dev.aegismcp.e2e;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.AegisGatewayServer;
import dev.aegismcp.gateway.anomaly.AnomalyCircuitBreaker;
import dev.aegismcp.gateway.anomaly.AnomalyRule;
import dev.aegismcp.gateway.anomaly.SessionSequenceTracker;
import dev.aegismcp.gateway.anomaly.ToolBurstRule;
import dev.aegismcp.gateway.anomaly.ToolChainingAnomalyInterceptor;
import dev.aegismcp.gateway.approval.ApprovalManagementHandler;
import dev.aegismcp.gateway.approval.ApprovalManager;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.audit.AuditRecord;
import dev.aegismcp.gateway.audit.AuditVerificationEngine;
import dev.aegismcp.gateway.audit.AuditVerificationHandler;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.dlp.DlpOutboundHandler;
import dev.aegismcp.gateway.dlp.DlpPipelineConfigurator;
import dev.aegismcp.gateway.dlp.DlpScrubber;
import dev.aegismcp.gateway.identity.AgentIdentityResolver;
import dev.aegismcp.gateway.killswitch.EmergencyManagementHandler;
import dev.aegismcp.gateway.killswitch.GatewayMetrics;
import dev.aegismcp.gateway.killswitch.InvocationVelocityCircuitBreaker;
import dev.aegismcp.gateway.killswitch.KillSwitchManager;
import dev.aegismcp.gateway.policy.DeclarativePolicyInterceptor;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyCompiler;
import dev.aegismcp.gateway.policy.PolicyEvaluator;
import dev.aegismcp.gateway.policy.PolicyManagementHandler;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.McpProxyHandler;
import dev.aegismcp.gateway.proxy.McpProxyPipelineConfigurator;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;
import dev.aegismcp.gateway.proxy.UpstreamClient;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslContext;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Fixture encapsulating a live AegisGatewayServer configured with the Zero-Trust pipeline,
 * including Phase 1 controls and Phase 2 visibility, kill-switch, and identity verification.
 */
public class E2EGatewayFixture implements AutoCloseable {

    private final AegisGatewayServer server;
    private final PolicyCache policyCache;
    private final ApprovalManager approvalManager;
    private final AuditLedger auditLedger;
    private final AuditVerificationEngine auditEngine;
    private final SessionSequenceTracker sessionTracker;
    private final AnomalyCircuitBreaker circuitBreaker;
    private final DlpScrubber dlpScrubber;
    private final AtomicReference<UpstreamClient> upstreamClientRef;

    private final KillSwitchManager killSwitchManager;
    private final GatewayMetrics gatewayMetrics;
    private final EmergencyManagementHandler emergencyHandler;
    private final InvocationVelocityCircuitBreaker velocityCircuitBreaker;
    private volatile AgentIdentityResolver identityResolver;
    private final SslContext sslContext;

    public static final int DEFAULT_BURST_THRESHOLD = 100_000;

    public E2EGatewayFixture() throws InterruptedException {
        this(UpstreamClient.mockEcho(), true, DEFAULT_BURST_THRESHOLD);
    }

    public E2EGatewayFixture(boolean loadDefaultPolicy) throws InterruptedException {
        this(UpstreamClient.mockEcho(), loadDefaultPolicy, DEFAULT_BURST_THRESHOLD);
    }

    public E2EGatewayFixture(int burstThreshold) throws InterruptedException {
        this(UpstreamClient.mockEcho(), true, burstThreshold);
    }

    public E2EGatewayFixture(UpstreamClient initialUpstream) throws InterruptedException {
        this(initialUpstream, true, DEFAULT_BURST_THRESHOLD);
    }

    public E2EGatewayFixture(UpstreamClient initialUpstream, boolean loadDefaultPolicy) throws InterruptedException {
        this(initialUpstream, loadDefaultPolicy, DEFAULT_BURST_THRESHOLD);
    }

    public E2EGatewayFixture(UpstreamClient initialUpstream, boolean loadDefaultPolicy, int burstThreshold) throws InterruptedException {
        this(initialUpstream, loadDefaultPolicy, burstThreshold, 100_000, null, null);
    }

    public E2EGatewayFixture(
            UpstreamClient initialUpstream,
            boolean loadDefaultPolicy,
            int burstThreshold,
            int velocityThreshold,
            AgentIdentityResolver identityResolver,
            SslContext sslContext
    ) throws InterruptedException {
        this.policyCache = new PolicyCache();
        this.approvalManager = new ApprovalManager(Duration.ofMinutes(5));
        this.auditLedger = new AuditLedger(1);
        this.auditEngine = new AuditVerificationEngine();
        this.sessionTracker = new SessionSequenceTracker();
        this.circuitBreaker = new AnomalyCircuitBreaker();
        this.dlpScrubber = DlpScrubber.getInstance();
        this.upstreamClientRef = new AtomicReference<>(initialUpstream);

        this.killSwitchManager = new KillSwitchManager();
        this.gatewayMetrics = new GatewayMetrics();
        this.velocityCircuitBreaker = new InvocationVelocityCircuitBreaker(
                killSwitchManager,
                velocityThreshold > 0 ? velocityThreshold : 100_000,
                Duration.ofSeconds(10),
                gatewayMetrics
        );
        this.emergencyHandler = new EmergencyManagementHandler(
                killSwitchManager,
                gatewayMetrics,
                JsonRpcCodec.getInstance().getMapper(),
                EmergencyManagementHandler.defaultAuthorizer()
        );
        this.identityResolver = identityResolver;
        this.sslContext = sslContext;

        if (loadDefaultPolicy) {
            String defaultYaml = """
                    id: pol_default_e2e
                    name: Default E2E Base Policy
                    version: 1.0.0
                    targetAgents:
                      - "*"
                    rules:
                      - id: rule_echo
                        tool: echo
                        action: allow
                      - id: rule_ping
                        tool: ping
                        action: allow
                      - id: rule_cluster_info
                        tool: cluster_info
                        action: allow
                      - id: rule_read_file
                        tool: read_file
                        action: allow
                      - id: rule_curl
                        tool: curl:exec
                        action: allow
                      - id: rule_sensitive
                        tool: get_sensitive_config
                        action: allow
                    """;
            this.policyCache.putPolicy(SecurityPolicy.of("pol_default_e2e", "Default E2E Base Policy", "1.0.0", defaultYaml, "git-base"));
        }

        // Anomaly interceptor: data exfiltration, untrusted execution, rapid bursts
        ToolChainingAnomalyInterceptor anomalyInterceptor = new ToolChainingAnomalyInterceptor(
                sessionTracker,
                List.of(
                        AnomalyRule.defaultRules().get(0), // dataExfiltrationRule (read_file -> curl:exec)
                        AnomalyRule.defaultRules().get(1), // untrustedExecutionRule
                        new ToolBurstRule("E2EBurstRule", burstThreshold, Duration.ofSeconds(1), "HIGH")
                ),
                circuitBreaker
        );

        PolicyEvaluator policyEvaluator = new PolicyEvaluator(policyCache);
        DeclarativePolicyInterceptor policyInterceptor = new DeclarativePolicyInterceptor(
                policyEvaluator,
                approvalManager
        );

        ToolCallInterceptor auditInterceptor = (context, request) -> {
            if (request.isToolCall()) {
                gatewayMetrics.recordToolCall();
                auditLedger.append(AuditRecord.create(
                        context.identity().agentId(),
                        request.toolName(),
                        "ALLOWED",
                        0,
                        0.5,
                        request.toolArguments() != null ? request.toolArguments().toString() : ""
                ));
            }
            return CompletableFuture.completedFuture(InterceptionVerdict.allow());
        };

        ToolCallInterceptor killSwitchInterceptor = (context, request) -> {
            if (!killSwitchManager.hasActiveQuarantines()) {
                return CompletableFuture.completedFuture(InterceptionVerdict.allow());
            }
            return killSwitchManager.asInterceptor().intercept(context, request);
        };

        java.util.List<ToolCallInterceptor> interceptorsList = new java.util.ArrayList<>();
        interceptorsList.add(killSwitchInterceptor);
        if (velocityThreshold > 0 && velocityThreshold < 100_000) {
            interceptorsList.add(velocityCircuitBreaker);
        }
        interceptorsList.add(anomalyInterceptor);
        interceptorsList.add(policyInterceptor);
        interceptorsList.add(auditInterceptor);

        ToolCallInterceptor baseInterceptor = ToolCallInterceptor.chain(interceptorsList.toArray(new ToolCallInterceptor[0]));

        ToolCallInterceptor combinedInterceptor = (context, request) -> {
            long start = System.nanoTime();
            return baseInterceptor.intercept(context, request)
                    .thenApply(verdict -> {
                        double latency = (System.nanoTime() - start) / 1_000_000.0;
                        if (request.isToolCall() && verdict instanceof InterceptionVerdict.Block) {
                            gatewayMetrics.recordBlockedViolation();
                            auditLedger.append(AuditRecord.create(
                                    context.identity().agentId(),
                                    request.toolName(),
                                    "BLOCKED",
                                    0,
                                    latency,
                                    request.toolArguments() != null ? request.toolArguments().toString() : ""
                            ));
                        }
                        return verdict;
                    });
        };

        this.server = new AegisGatewayServer(
                "127.0.0.1",
                0,
                java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor(),
                true,
                this.auditLedger,
                this.policyCache,
                this.approvalManager,
                this.killSwitchManager,
                this.gatewayMetrics,
                null
        );
        this.server.start();

        UpstreamClient delegatingUpstream = (context, request) -> upstreamClientRef.get().forward(context, request);

        McpProxyHandler mcpProxyHandler = new McpProxyHandler(
                McpProxyHandler.DEFAULT_RPC_PATH,
                JsonRpcCodec.getInstance(),
                combinedInterceptor,
                delegatingUpstream,
                server.getVirtualThreadExecutor(),
                true // requireAuth
        );

        DlpOutboundHandler dlpHandler = new DlpOutboundHandler(dlpScrubber);
        AuditVerificationHandler auditHandler = new AuditVerificationHandler(
                auditLedger,
                auditEngine,
                new ObjectMapper(),
                AuditVerificationHandler.defaultAuthorizer()
        );
        PolicyManagementHandler policyHandler = new PolicyManagementHandler(
                policyCache,
                PolicyCompiler.getInstance(),
                JsonRpcCodec.getInstance().getMapper(),
                PolicyManagementHandler.defaultAuthorizer()
        );
        ApprovalManagementHandler approvalHandler = new ApprovalManagementHandler(
                approvalManager,
                JsonRpcCodec.getInstance().getMapper(),
                ApprovalManagementHandler.defaultAuthorizer()
        );

        // Inject Zero-Trust pipeline dynamically on newly accepted connections
        this.server.getServerChannel().pipeline().addFirst("e2e-pipeline-injector", new ChannelInboundHandlerAdapter() {
            @Override
            public void channelRead(ChannelHandlerContext ctx, Object msg) {
                if (msg instanceof SocketChannel ch) {
                    if (sslContext != null) {
                        ch.pipeline().addFirst("ssl-handler", sslContext.newHandler(ch.alloc()));
                    }
                    ch.pipeline().addLast("e2e-channel-activator", new ChannelInboundHandlerAdapter() {
                        @Override
                        public void channelActive(ChannelHandlerContext childCtx) throws Exception {
                            if (childCtx.pipeline().get("http-codec") != null) {
                                childCtx.pipeline().addAfter("http-codec", "dlp-outbound-filter", dlpHandler);
                            } else {
                                DlpPipelineConfigurator.configure(childCtx.pipeline(), dlpHandler);
                            }
                            if (childCtx.pipeline().get("audit-verify-handler") == null) {
                                childCtx.pipeline().addBefore("gateway-dispatcher", "audit-verify-handler", auditHandler);
                            }
                            if (childCtx.pipeline().get("policy-management-handler") == null) {
                                childCtx.pipeline().addBefore("gateway-dispatcher", "policy-management-handler", policyHandler);
                            }
                            if (childCtx.pipeline().get("approval-management-handler") == null) {
                                childCtx.pipeline().addBefore("gateway-dispatcher", "approval-management-handler", approvalHandler);
                            }
                            if (childCtx.pipeline().get("emergency-management-handler") == null) {
                                childCtx.pipeline().addBefore("gateway-dispatcher", "emergency-management-handler", emergencyHandler);
                            }
                            if (identityResolver != null) {
                                childCtx.pipeline().addBefore("gateway-dispatcher", "identity-auth-handler", createIdentityAuthHandler());
                            }
                            McpProxyPipelineConfigurator.configure(childCtx.pipeline(), mcpProxyHandler);
                            childCtx.pipeline().remove(this);
                            super.channelActive(childCtx);
                        }
                    });
                }
                ctx.fireChannelRead(msg);
            }
        });
    }

    private ChannelInboundHandlerAdapter createIdentityAuthHandler() {
        return new ChannelInboundHandlerAdapter() {
            @Override
            public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                if (msg instanceof FullHttpRequest req) {
                    gatewayMetrics.recordRequest();
                    String path = req.uri();
                    int q = path.indexOf('?');
                    if (q >= 0) path = path.substring(0, q);

                    if ("/mcp/v1/rpc".equals(path) && identityResolver != null) {
                        dev.aegismcp.gateway.identity.AgentIdentity id = identityResolver.resolve(req, ctx);
                        if (!id.authenticated()) {
                            String errorMsg = id.claims().getOrDefault("error", "Missing or invalid agent credentials").toString();
                            String jsonErr = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,\"message\":\"Authentication Failed: " +
                                    escapeJson(errorMsg) + "\"}}";
                            DefaultFullHttpResponse resp = new DefaultFullHttpResponse(
                                    HttpVersion.HTTP_1_1,
                                    HttpResponseStatus.UNAUTHORIZED,
                                    Unpooled.copiedBuffer(jsonErr, StandardCharsets.UTF_8)
                            );
                            resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
                            resp.headers().set(HttpHeaderNames.CONTENT_LENGTH, resp.content().readableBytes());
                            ctx.writeAndFlush(resp);
                            req.release();
                            return;
                        }
                        // Register session with killSwitchManager
                        killSwitchManager.registerSession(id.id(), null, ctx.channel());
                        if (id.spiffeId() != null) {
                            killSwitchManager.registerSession(id.spiffeId(), null, ctx.channel());
                        }
                    }
                }
                super.channelRead(ctx, msg);
            }
        };
    }

    public static E2EGatewayFixture forPhase2(AgentIdentityResolver resolver) throws InterruptedException {
        return new E2EGatewayFixture(UpstreamClient.mockEcho(), true, DEFAULT_BURST_THRESHOLD, 100_000, resolver, null);
    }

    public static E2EGatewayFixture forPhase2(AgentIdentityResolver resolver, int velocityThreshold) throws InterruptedException {
        return new E2EGatewayFixture(UpstreamClient.mockEcho(), true, DEFAULT_BURST_THRESHOLD, velocityThreshold, resolver, null);
    }

    public static E2EGatewayFixture forMtlsPhase2(AgentIdentityResolver resolver, SslContext sslContext) throws InterruptedException {
        return new E2EGatewayFixture(UpstreamClient.mockEcho(), true, DEFAULT_BURST_THRESHOLD, 100_000, resolver, sslContext);
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    public int getPort() {
        return server.getPort();
    }

    public String getBaseUrl() {
        return (sslContext != null ? "https" : "http") + "://127.0.0.1:" + getPort();
    }

    public PolicyCache getPolicyCache() {
        return policyCache;
    }

    public ApprovalManager getApprovalManager() {
        return approvalManager;
    }

    public AuditLedger getAuditLedger() {
        return auditLedger;
    }

    public SessionSequenceTracker getSessionTracker() {
        return sessionTracker;
    }

    public AnomalyCircuitBreaker getCircuitBreaker() {
        return circuitBreaker;
    }

    public KillSwitchManager getKillSwitchManager() {
        return killSwitchManager;
    }

    public GatewayMetrics getGatewayMetrics() {
        return gatewayMetrics;
    }

    public InvocationVelocityCircuitBreaker getVelocityCircuitBreaker() {
        return velocityCircuitBreaker;
    }

    public AgentIdentityResolver getIdentityResolver() {
        return identityResolver;
    }

    public void setIdentityResolver(AgentIdentityResolver identityResolver) {
        this.identityResolver = identityResolver;
    }

    public void setUpstreamClient(UpstreamClient client) {
        this.upstreamClientRef.set(client);
    }

    @Override
    public void close() {
        if (server != null && server.isRunning()) {
            server.stop();
        }
        if (approvalManager != null) {
            approvalManager.close();
        }
        if (auditLedger != null) {
            auditLedger.close();
        }
    }
}
