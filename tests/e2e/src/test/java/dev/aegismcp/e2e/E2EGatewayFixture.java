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
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.socket.SocketChannel;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Fixture encapsulating a live AegisGatewayServer configured with the full Phase 1 Zero-Trust pipeline.
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
        this.policyCache = new PolicyCache();
        this.approvalManager = new ApprovalManager(Duration.ofMinutes(5));
        this.auditLedger = new AuditLedger(1);
        this.auditEngine = new AuditVerificationEngine();
        this.sessionTracker = new SessionSequenceTracker();
        this.circuitBreaker = new AnomalyCircuitBreaker();
        this.dlpScrubber = DlpScrubber.getInstance();
        this.upstreamClientRef = new AtomicReference<>(initialUpstream);

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

        ToolCallInterceptor baseInterceptor = ToolCallInterceptor.chain(
                anomalyInterceptor,
                policyInterceptor,
                auditInterceptor
        );

        ToolCallInterceptor combinedInterceptor = (context, request) -> {
            long start = System.nanoTime();
            return baseInterceptor.intercept(context, request)
                    .thenApply(verdict -> {
                        double latency = (System.nanoTime() - start) / 1_000_000.0;
                        if (request.isToolCall() && verdict instanceof InterceptionVerdict.Block) {
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

        this.server = new AegisGatewayServer("127.0.0.1", 0);
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

        // Inject Phase 1 Zero-Trust pipeline dynamically on newly accepted connections
        this.server.getServerChannel().pipeline().addFirst("e2e-pipeline-injector", new ChannelInboundHandlerAdapter() {
            @Override
            public void channelRead(ChannelHandlerContext ctx, Object msg) {
                if (msg instanceof SocketChannel ch) {
                    ch.pipeline().addLast("e2e-channel-activator", new ChannelInboundHandlerAdapter() {
                        @Override
                        public void channelActive(ChannelHandlerContext childCtx) throws Exception {
                            if (childCtx.pipeline().get("http-codec") != null) {
                                childCtx.pipeline().addAfter("http-codec", "dlp-outbound-filter", dlpHandler);
                            } else {
                                DlpPipelineConfigurator.configure(childCtx.pipeline(), dlpHandler);
                            }
                            childCtx.pipeline().addBefore("gateway-dispatcher", "audit-verify-handler", auditHandler);
                            childCtx.pipeline().addBefore("gateway-dispatcher", "policy-management-handler", policyHandler);
                            childCtx.pipeline().addBefore("gateway-dispatcher", "approval-management-handler", approvalHandler);
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

    public int getPort() {
        return server.getPort();
    }

    public String getBaseUrl() {
        return "http://127.0.0.1:" + getPort();
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
