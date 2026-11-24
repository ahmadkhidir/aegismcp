package dev.aegismcp.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.anomaly.SessionSequenceTracker;
import dev.aegismcp.gateway.anomaly.AnomalyCircuitBreaker;
import dev.aegismcp.gateway.anomaly.AnomalyRule;
import dev.aegismcp.gateway.anomaly.ToolChainingAnomalyInterceptor;
import dev.aegismcp.gateway.approval.ApprovalManagementHandler;
import dev.aegismcp.gateway.approval.ApprovalManager;
import dev.aegismcp.gateway.approval.ApprovalNotificationConfig;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.audit.AuditRecord;
import dev.aegismcp.gateway.audit.AuditRecordsHandler;
import dev.aegismcp.gateway.audit.AuditVerificationEngine;
import dev.aegismcp.gateway.audit.AuditVerificationHandler;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.compliance.ComplianceExportHandler;
import dev.aegismcp.gateway.compliance.ComplianceReportEngine;
import dev.aegismcp.gateway.config.ConfigurationException;
import dev.aegismcp.gateway.config.GatewayConfiguration;
import dev.aegismcp.gateway.config.VerifiedManagementAuthorizers;
import dev.aegismcp.gateway.dlp.DlpOutboundHandler;
import dev.aegismcp.gateway.dlp.DlpScrubber;
import dev.aegismcp.gateway.health.GatewayReadiness;
import dev.aegismcp.gateway.health.HealthHandler;
import dev.aegismcp.gateway.identity.AgentIdentityResolver;
import dev.aegismcp.gateway.identity.HttpJwksSupplier;
import dev.aegismcp.gateway.identity.IdentityVerificationHandler;
import dev.aegismcp.gateway.identity.JwksKeyResolver;
import dev.aegismcp.gateway.identity.OidcTokenValidator;
import dev.aegismcp.gateway.identity.SpiffeSvidValidator;
import dev.aegismcp.gateway.inspector.InspectorApprovalHandler;
import dev.aegismcp.gateway.inspector.InspectorEventStream;
import dev.aegismcp.gateway.inspector.InspectorPolicyEvaluator;
import dev.aegismcp.gateway.inspector.InspectorSubscriptionAuthorizer;
import dev.aegismcp.gateway.inspector.InspectorTelemetryObserver;
import dev.aegismcp.gateway.inspector.InspectorTrafficInterceptor;
import dev.aegismcp.gateway.inspector.TrafficEventFactory;
import dev.aegismcp.gateway.inspector.TrafficObservations;
import dev.aegismcp.gateway.inspector.TrafficStreamHandler;
import dev.aegismcp.gateway.killswitch.EmergencyManagementHandler;
import dev.aegismcp.gateway.killswitch.GatewayMetrics;
import dev.aegismcp.gateway.killswitch.GatewayMetricsInterceptor;
import dev.aegismcp.gateway.killswitch.InvocationVelocityCircuitBreaker;
import dev.aegismcp.gateway.killswitch.KillSwitchManager;
import dev.aegismcp.gateway.policy.DeclarativePolicyInterceptor;
import dev.aegismcp.gateway.policy.PolicyAst;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyCompiler;
import dev.aegismcp.gateway.policy.PolicyEvaluator;
import dev.aegismcp.gateway.policy.PolicyManagementHandler;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import dev.aegismcp.gateway.proxy.McpProxyHandler;
import dev.aegismcp.gateway.proxy.McpProxyPipelineConfigurator;
import dev.aegismcp.gateway.proxy.ToolCallInterceptor;
import dev.aegismcp.gateway.proxy.UpstreamClient;
import dev.aegismcp.gateway.proxy.UpstreamClientFactory;
import dev.aegismcp.gateway.validation.DynamicParameterValidator;
import dev.aegismcp.gateway.validation.DynamicValidationInterceptor;
import dev.aegismcp.gateway.validation.ToolSchemaRegistry;
import dev.aegismcp.gateway.validation.UpstreamToolSchemaSource;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Composition root for the AegisMCP gateway.
 *
 * <p>One assembly builds the shipped request path: TLS at the listener, verified identity at the
 * edge, the untrusted-body boundary, then the interceptor chain — kill switch, invocation velocity,
 * parameter validation, policy (which may suspend on an approval), and sequence anomaly — followed
 * by the configured upstream, outbound DLP on the response, and an audit record for every terminal
 * outcome. The same assembly splits the telemetry surface off that path: the chain is observed from
 * the outside so every intercepted tool call reaches the live inspector on
 * {@code GET /api/v1/stream/traffic}, the same observation feeds the fleet counters C-009 and C-010
 * report, and a dedicated observer turns approval-queue and threat-level changes into stream events.
 * Management and probe endpoints are attached in the same channel initializer, and a request that
 * matches no owned path is answered {@code 404} rather than a fallback success body.
 *
 * <p>Anchors: FEAT-001, FEAT-002, FEAT-004, FEAT-005, FEAT-006, FEAT-007, FEAT-008, FEAT-009,
 * FEAT-012, NFR-001, NFR-005, NFR-010, NFR-021, NFR-027, C-001, C-002, C-009, C-010.
 */
public class AegisGatewayServer {

    private static final Logger logger = LoggerFactory.getLogger(AegisGatewayServer.class);

    public static final String DEFAULT_HOST = GatewayConfiguration.DEFAULT_HOST;
    public static final int DEFAULT_PORT = GatewayConfiguration.DEFAULT_PORT;
    public static final int MAX_CONTENT_LENGTH = GatewayConfiguration.DEFAULT_MAX_CONTENT_LENGTH;

    private static final byte[] NOT_FOUND_BODY =
            "{\"error\":\"Not Found\"}".getBytes(StandardCharsets.UTF_8);

    private final GatewayConfiguration configuration;
    private final String host;
    private final int port;
    private final int maxContentLength;
    private final ExecutorService virtualThreadExecutor;
    private final boolean ownsExecutor;
    private final SslContext sslContext;

    private final AuditLedger auditLedger;
    private final PolicyCache policyCache;
    private final ApprovalManager approvalManager;
    private final KillSwitchManager killSwitchManager;
    private final GatewayMetrics gatewayMetrics;
    private final ComplianceReportEngine complianceReportEngine;

    private final AuditVerificationHandler auditVerificationHandler;
    private final AuditRecordsHandler auditRecordsHandler;
    private final ComplianceExportHandler complianceExportHandler;
    private final PolicyManagementHandler policyManagementHandler;
    private final ApprovalManagementHandler approvalManagementHandler;
    private final EmergencyManagementHandler emergencyManagementHandler;

    private final GatewayReadiness readiness;
    private final HealthHandler healthHandler;

    private final InspectorEventStream inspectorEventStream;
    private final InspectorTelemetryObserver inspectorTelemetryObserver;
    private final TrafficStreamHandler trafficStreamHandler;
    private final TrafficObservations trafficObservations;

    private final IdentityVerificationHandler identityVerificationHandler;
    private final DlpOutboundHandler dlpOutboundHandler;
    private final UpstreamClient upstreamClient;
    private final McpProxyHandler mcpProxyHandler;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel serverChannel;
    private volatile boolean running = false;
    private int boundPort = -1;

    /**
     * Builds the shipped gateway from validated operator configuration. Every request-path class is
     * constructed here; nothing else binds a port or assembles a handler chain. A configuration
     * that is not explicitly probe-only must be complete; an incomplete one fails startup naming
     * every missing key instead of booting a partially served node (NFR-010, NFR-027).
     */
    public AegisGatewayServer(GatewayConfiguration configuration) {
        this(configuration,
                Executors.newVirtualThreadPerTaskExecutor(),
                true,
                new AuditLedger(),
                new PolicyCache(),
                new ApprovalManager(configuration.approvalTtl(), configuration.approvals()),
                new KillSwitchManager(),
                new GatewayMetrics(),
                null,
                !configuration.probeOnly());
    }

    /**
     * In-process seam for the probe suites. It attaches the management and probe handlers, which
     * authorize through the verified OIDC token like the shipped path; because this seam supplies
     * no identity provider, every management request fails closed with {@code 401}. It does not
     * attach an agent request path. The shipped path is
     * {@link #AegisGatewayServer(GatewayConfiguration)}, which {@code main} builds from validated
     * operator configuration.
     */
    public AegisGatewayServer(String host, int port) {
        this(GatewayConfiguration.local(host, port),
                Executors.newVirtualThreadPerTaskExecutor(),
                true,
                new AuditLedger(),
                new PolicyCache(),
                new ApprovalManager(GatewayConfiguration.DEFAULT_APPROVAL_TTL,
                        ApprovalNotificationConfig.none()),
                new KillSwitchManager(),
                new GatewayMetrics(),
                null,
                false);
    }

    /**
     * Collaborator-injection seam used by the artifact harness. It deliberately does not attach a
     * request path: the harness supplies its own. Never reachable from {@code main}.
     */
    public AegisGatewayServer(
            String host,
            int port,
            ExecutorService virtualThreadExecutor,
            boolean ownsExecutor,
            AuditLedger auditLedger,
            PolicyCache policyCache,
            ApprovalManager approvalManager,
            KillSwitchManager killSwitchManager,
            GatewayMetrics gatewayMetrics,
            ComplianceReportEngine complianceReportEngine
    ) {
        this(GatewayConfiguration.local(host, port),
                virtualThreadExecutor,
                ownsExecutor,
                auditLedger,
                policyCache,
                approvalManager,
                killSwitchManager,
                gatewayMetrics,
                complianceReportEngine,
                false);
    }

    private AegisGatewayServer(
            GatewayConfiguration configuration,
            ExecutorService virtualThreadExecutor,
            boolean ownsExecutor,
            AuditLedger auditLedger,
            PolicyCache policyCache,
            ApprovalManager approvalManager,
            KillSwitchManager killSwitchManager,
            GatewayMetrics gatewayMetrics,
            ComplianceReportEngine complianceReportEngine,
            boolean assembleRequestPath
    ) {
        this.configuration = Objects.requireNonNull(configuration, "configuration must not be null");
        this.host = configuration.host();
        this.port = configuration.port();
        this.maxContentLength = configuration.maxContentLength();
        this.virtualThreadExecutor = Objects.requireNonNull(virtualThreadExecutor, "virtualThreadExecutor must not be null");
        this.ownsExecutor = ownsExecutor;

        this.auditLedger = Objects.requireNonNull(auditLedger, "auditLedger must not be null");
        this.policyCache = Objects.requireNonNull(policyCache, "policyCache must not be null");
        this.approvalManager = Objects.requireNonNull(approvalManager, "approvalManager must not be null");
        this.killSwitchManager = Objects.requireNonNull(killSwitchManager, "killSwitchManager must not be null");
        this.gatewayMetrics = Objects.requireNonNull(gatewayMetrics, "gatewayMetrics must not be null");
        // The session registry is the owner of open agent transport streams, so it feeds the live
        // active-connection and active-agent counters C-009 and C-010 report (FEAT-010, C-009).
        this.killSwitchManager.attachMetrics(this.gatewayMetrics);

        this.complianceReportEngine = complianceReportEngine != null
                ? complianceReportEngine
                : new ComplianceReportEngine(this.auditLedger, this.policyCache, this.approvalManager);

        this.readiness = new GatewayReadiness();
        this.sslContext = configuration.tls().enabled() ? buildSslContext(configuration.tls()) : null;

        ObjectMapper jsonMapper = JsonRpcCodec.getInstance().getMapper();
        OidcTokenValidator oidcValidator = buildOidcValidator(configuration.identity());
        // Management endpoints always authorize through the verified OIDC token and the role set
        // its contract names. When the identity provider is unconfigured the validator is absent
        // and every management request fails closed with 401 rather than falling back to a
        // permissive or token-substring check (FEAT-008, NFR-029).
        VerifiedManagementAuthorizers managementAuthorizers = new VerifiedManagementAuthorizers(oidcValidator);

        this.auditVerificationHandler = new AuditVerificationHandler(
                this.auditLedger, AuditVerificationEngine.getInstance(), jsonMapper,
                managementAuthorizers.auditVerification());
        this.auditRecordsHandler = new AuditRecordsHandler(
                this.auditLedger, jsonMapper, managementAuthorizers.auditRecords());
        this.complianceExportHandler = new ComplianceExportHandler(
                this.complianceReportEngine, jsonMapper, managementAuthorizers.compliance());
        this.policyManagementHandler = new PolicyManagementHandler(
                this.policyCache, PolicyCompiler.getInstance(), jsonMapper, managementAuthorizers.policy());
        this.approvalManagementHandler = new ApprovalManagementHandler(
                this.approvalManager, jsonMapper, managementAuthorizers.approvals());
        this.emergencyManagementHandler = new EmergencyManagementHandler(
                this.killSwitchManager, this.gatewayMetrics, this.auditLedger, jsonMapper,
                managementAuthorizers.emergency());

        this.healthHandler = new HealthHandler(this.readiness);

        // The live inspector is a management surface, so it is attached whether or not the agent
        // request path is assembled; an unconfigured identity provider leaves every subscription
        // refused with 401 (FEAT-008, C-002).
        this.inspectorEventStream = new InspectorEventStream(jsonMapper);
        this.trafficObservations = new TrafficObservations();
        this.trafficStreamHandler = new TrafficStreamHandler(
                this.inspectorEventStream,
                jsonMapper,
                new InspectorSubscriptionAuthorizer(oidcValidator).asStreamAuthorizer(),
                this.readiness,
                this.virtualThreadExecutor);
        this.inspectorTelemetryObserver = new InspectorTelemetryObserver(
                this.approvalManager, this.gatewayMetrics, this.killSwitchManager,
                this.inspectorEventStream);

        if (assembleRequestPath) {
            this.identityVerificationHandler = new IdentityVerificationHandler(
                    buildIdentityResolver(configuration.identity()), this.auditLedger,
                    this.killSwitchManager, this.virtualThreadExecutor);
            this.dlpOutboundHandler = new DlpOutboundHandler(DlpScrubber.getInstance());
            this.upstreamClient = buildUpstreamClient(configuration);
            this.mcpProxyHandler = new McpProxyHandler(
                    McpProxyHandler.DEFAULT_RPC_PATH,
                    JsonRpcCodec.getInstance(),
                    buildInterceptorChain(configuration),
                    this.upstreamClient,
                    this.virtualThreadExecutor,
                    true,
                    buildAuditTrail(),
                    true);
            loadPolicyDocument(configuration);
        } else {
            this.identityVerificationHandler = null;
            this.dlpOutboundHandler = null;
            this.upstreamClient = null;
            this.mcpProxyHandler = null;
        }

        if (configuration.probeOnly()) {
            // Probe-only is the one deployment allowed to omit the serving configuration. The
            // readiness contract reports it as an unhealthy configuration dependency, and no
            // agent request path is attached, so every agent call fails closed (C-023, NFR-027).
            readiness.markDependencyUnhealthy(GatewayReadiness.Dependency.CONFIGURATION);
            logger.info("Gateway is probe-only ({}); serving /health and /ready only, "
                    + "every agent request is refused", GatewayConfiguration.PROBE_ONLY_ENV);
        }
    }

    /**
     * Starts the Netty listener on the configured host and port. TLS is installed when the
     * configuration supplies a keystore. A probe-only configuration serves the health and readiness
     * probes only; a serving configuration was validated before any listener is bound.
     */
    public synchronized void start() throws InterruptedException {
        if (running) {
            logger.warn("AegisGatewayServer is already running on {}:{}", host, boundPort);
            return;
        }

        readiness.markStarting();
        inspectorEventStream.start();

        bossGroup = new NioEventLoopGroup(1, Thread.ofPlatform().name("netty-boss-", 0).factory());
        workerGroup = new NioEventLoopGroup(0, Thread.ofPlatform().name("netty-worker-", 0).factory());

        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, 1024)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .childOption(ChannelOption.TCP_NODELAY, true)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        if (sslContext != null) {
                            ch.pipeline().addLast("ssl-handler", sslContext.newHandler(ch.alloc()));
                        }
                        ch.pipeline().addLast("http-codec", new HttpServerCodec());
                        ch.pipeline().addLast("http-aggregator", new HttpObjectAggregator(maxContentLength));

                        if (identityVerificationHandler != null) {
                            ch.pipeline().addLast(IdentityVerificationHandler.HANDLER_NAME, identityVerificationHandler);
                        }

                        ch.pipeline().addLast("health-handler", healthHandler);
                        ch.pipeline().addLast("audit-verification-handler", auditVerificationHandler);
                        ch.pipeline().addLast("audit-records-handler", auditRecordsHandler);
                        ch.pipeline().addLast("compliance-export-handler", complianceExportHandler);
                        ch.pipeline().addLast("policy-management-handler", policyManagementHandler);
                        ch.pipeline().addLast("approval-management-handler", approvalManagementHandler);
                        ch.pipeline().addLast("emergency-management-handler", emergencyManagementHandler);
                        ch.pipeline().addLast("traffic-stream-handler", trafficStreamHandler);

                        // Outbound DLP is a tool-response stage, not a global response filter. It is
                        // added after every probe, management, and inspector-stream handler, so a
                        // response those handlers write travels toward the pipeline head without
                        // ever crossing it; only the proxied upstream response written below it is
                        // scrubbed (FEAT-005, C-001, C-003, C-004, C-014, C-019, C-024).
                        if (dlpOutboundHandler != null) {
                            ch.pipeline().addLast("dlp-outbound-filter", dlpOutboundHandler);
                        }
                        if (mcpProxyHandler != null) {
                            McpProxyPipelineConfigurator.configure(ch.pipeline(), mcpProxyHandler);
                        }
                        ch.pipeline().addLast("gateway-dispatcher", new GatewayDispatcherHandler());
                    }
                });

        ChannelFuture future = bootstrap.bind(host, port).sync();
        serverChannel = future.channel();
        InetSocketAddress localAddress = (InetSocketAddress) serverChannel.localAddress();
        boundPort = localAddress.getPort();
        running = true;
        readiness.markReady();
        inspectorTelemetryObserver.start();

        logger.info("AegisGatewayServer started successfully on {}:{} (tls={})", host, boundPort, sslContext != null);
    }

    /** Gracefully stops the listener and releases every owned resource. */
    public synchronized void stop() {
        if (!running) {
            return;
        }

        readiness.markShuttingDown();
        logger.info("Stopping AegisGatewayServer on {}:{}...", host, boundPort);

        // Draining ends the live stream first: a refused or closed subscription is what tells the
        // console to enter its reconnect state instead of waiting on an idle connection (C-002).
        inspectorTelemetryObserver.close();
        inspectorEventStream.close();

        try {
            if (serverChannel != null && serverChannel.isOpen()) {
                serverChannel.close().syncUninterruptibly();
            }
        } catch (Exception e) {
            logger.warn("Error closing server channel", e);
        }

        if (bossGroup != null) {
            bossGroup.shutdownGracefully(100, 1000, TimeUnit.MILLISECONDS).syncUninterruptibly();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully(100, 1000, TimeUnit.MILLISECONDS).syncUninterruptibly();
        }

        if (upstreamClient != null) {
            try {
                upstreamClient.close();
            } catch (RuntimeException e) {
                logger.warn("Error closing the upstream transport during shutdown", e);
            }
        }

        if (ownsExecutor) {
            virtualThreadExecutor.shutdown();
            try {
                if (!virtualThreadExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                    virtualThreadExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                virtualThreadExecutor.shutdownNow();
            }
        }

        try {
            auditLedger.close();
        } catch (Exception e) {
            logger.warn("Error closing audit ledger during server shutdown", e);
        }

        try {
            approvalManager.close();
        } catch (Exception e) {
            logger.warn("Error closing approval manager during server shutdown", e);
        }

        running = false;
        logger.info("AegisGatewayServer stopped cleanly.");
    }

    private ToolCallInterceptor buildInterceptorChain(GatewayConfiguration configuration) {
        // Parameter validation reads each tool's published JSON schema from the upstream MCP server's
        // own manifest (FEAT-012), so a tool the gateway has not seen is still validated against the
        // definition its server publishes rather than against a gateway-side copy.
        DynamicParameterValidator parameterValidator = new DynamicParameterValidator(
                new ToolSchemaRegistry(),
                new UpstreamToolSchemaSource(upstreamClient));
        PolicyEvaluator policyEvaluator =
                new InspectorPolicyEvaluator(policyCache, parameterValidator, trafficObservations);
        TrafficEventFactory trafficEvents = new TrafficEventFactory(DlpScrubber.getInstance());

        ToolCallInterceptor killSwitch = (context, request) -> killSwitchManager.asInterceptor().intercept(context, request);
        InvocationVelocityCircuitBreaker velocity = new InvocationVelocityCircuitBreaker(
                killSwitchManager,
                configuration.velocityThreshold(),
                configuration.velocityWindow());
        DynamicValidationInterceptor validation =
                new DynamicValidationInterceptor(parameterValidator, auditLedger);
        DeclarativePolicyInterceptor policy = new DeclarativePolicyInterceptor(
                policyEvaluator,
                new InspectorApprovalHandler(approvalManager, trafficObservations, inspectorEventStream,
                        trafficEvents));
        ToolChainingAnomalyInterceptor anomaly = new ToolChainingAnomalyInterceptor(
                new SessionSequenceTracker(),
                AnomalyRule.defaultRules(),
                new AnomalyCircuitBreaker());

        // Identity is verified by the edge handler. Within the tool-call chain the cheapest
        // fail-closed checks run first, then the untrusted-body checks, then policy, then the
        // sequence anomaly that can quarantine the session (FEAT-001, FEAT-002, FEAT-004).
        ToolCallInterceptor chain = ToolCallInterceptor.chain(killSwitch, velocity, validation, policy, anomaly);

        // The live inspector observes the whole chain from outside it, so a call refused by any
        // stage is still reported and the verdict reaching the proxy is unchanged (FEAT-008, C-002).
        ToolCallInterceptor observed =
                new InspectorTrafficInterceptor(chain, trafficObservations, inspectorEventStream, trafficEvents);

        // The fleet counters wrap the observed chain, so every intercepted tool call is counted once
        // and every terminal refusal is recorded as one blocked violation (C-009, C-010).
        return new GatewayMetricsInterceptor(observed, gatewayMetrics);
    }

    private UpstreamClient buildUpstreamClient(GatewayConfiguration configuration) {
        GatewayConfiguration.Upstream upstream = configuration.upstream();
        if (!upstream.configured()) {
            logger.warn("No upstream MCP server is configured; every forwarded call fails closed");
            return UpstreamClient.unconfigured();
        }
        return UpstreamClientFactory.create(
                upstream.url(), upstream.transport(), upstream.connectTimeout(), upstream.requestTimeout());
    }

    private McpProxyHandler.AuditTrail buildAuditTrail() {
        return (agentId, toolName, decision, latencyMs, summary) -> auditLedger.append(
                AuditRecord.create(
                        agentId != null ? agentId : "unauthenticated",
                        toolName != null ? toolName : "mcp/rpc",
                        decision,
                        0,
                        latencyMs,
                        summary != null ? summary : ""));
    }

    private void loadPolicyDocument(GatewayConfiguration configuration) {
        if (configuration.policyDocument() == null) {
            return;
        }
        try {
            String yaml = Files.readString(configuration.policyDocument());
            PolicyAst ast = PolicyCompiler.getInstance().compile(yaml);
            policyCache.putPolicy(SecurityPolicy.of(ast.id(), ast.name(), ast.version(), yaml, "startup"));
            logger.info("Loaded the configured policy document '{}'", configuration.policyDocument());
        } catch (Exception e) {
            logger.error("The configured policy document could not be compiled; the node is not ready", e);
            readiness.markDependencyUnhealthy(GatewayReadiness.Dependency.POLICY);
        }
    }

    private static OidcTokenValidator buildOidcValidator(GatewayConfiguration.Identity identity) {
        if (!identity.oidcConfigured()) {
            return null;
        }
        JwksKeyResolver resolver = new JwksKeyResolver(
                new HttpJwksSupplier(identity.jwksUrl(), identity.jwksConnectTimeout(), identity.jwksRequestTimeout()),
                identity.jwksCacheTtl(),
                identity.jwksGracePeriod(),
                java.time.Clock.systemUTC());
        return new OidcTokenValidator(resolver, identity.oidcIssuer(), identity.oidcAudience());
    }

    private static AgentIdentityResolver buildIdentityResolver(GatewayConfiguration.Identity identity) {
        OidcTokenValidator oidcValidator = buildOidcValidator(identity);
        if (oidcValidator == null) {
            // No OIDC provider: every bearer token is rejected by the validator-less path.
            oidcValidator = new OidcTokenValidator(new JwksKeyResolver());
        }
        SpiffeSvidValidator spiffeValidator = new SpiffeSvidValidator(
                identity.spiffeTrustDomains(), loadTrustBundle(identity.spiffeTrustBundle()));
        // A caller-supplied SPIFFE header is only trustworthy when an ingress verified it; the
        // shipped gateway requires the SVID or the JWT itself (FEAT-009, NFR-027).
        return new AgentIdentityResolver(spiffeValidator, oidcValidator, false);
    }

    private static Set<X509Certificate> loadTrustBundle(java.nio.file.Path bundlePath) {
        if (bundlePath == null) {
            return Set.of();
        }
        try (InputStream input = Files.newInputStream(bundlePath)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certificates = factory.generateCertificates(input);
            Set<X509Certificate> roots = new LinkedHashSet<>();
            for (Certificate certificate : certificates) {
                if (certificate instanceof X509Certificate x509) {
                    roots.add(x509);
                }
            }
            return Set.copyOf(roots);
        } catch (Exception e) {
            throw new ConfigurationException(
                    "AEGIS_SPIFFE_TRUST_BUNDLE_PATH could not be read as X.509 certificates: " + bundlePath, e);
        }
    }

    private static SslContext buildSslContext(GatewayConfiguration.Tls tls) {
        char[] storePassword = tls.keystorePassword() != null ? tls.keystorePassword().toCharArray() : new char[0];
        try {
            KeyStore keyStore = KeyStore.getInstance(tls.keystoreType());
            try (InputStream input = Files.newInputStream(tls.keystorePath())) {
                keyStore.load(input, storePassword);
            }
            KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            char[] keyPassword = tls.keyPassword() != null ? tls.keyPassword().toCharArray() : storePassword;
            keyManagers.init(keyStore, keyPassword);

            SslContextBuilder builder = SslContextBuilder.forServer(keyManagers);

            if (tls.truststorePath() != null) {
                char[] trustPassword = tls.truststorePassword() != null
                        ? tls.truststorePassword().toCharArray() : new char[0];
                KeyStore trustStore = KeyStore.getInstance(tls.keystoreType());
                try (InputStream input = Files.newInputStream(tls.truststorePath())) {
                    trustStore.load(input, trustPassword);
                }
                TrustManagerFactory trustManagers =
                        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagers.init(trustStore);
                builder.trustManager(trustManagers);
            }

            switch (tls.clientAuth()) {
                case REQUIRE -> builder.clientAuth(io.netty.handler.ssl.ClientAuth.REQUIRE);
                case OPTIONAL -> builder.clientAuth(io.netty.handler.ssl.ClientAuth.OPTIONAL);
                case NONE -> builder.clientAuth(io.netty.handler.ssl.ClientAuth.NONE);
            }
            return builder.build();
        } catch (ConfigurationException e) {
            throw e;
        } catch (Exception e) {
            throw new ConfigurationException(
                    "AEGIS_TLS_KEYSTORE_PATH could not be used to build the TLS listener: " + e.getMessage(), e);
        }
    }

    public boolean isRunning() {
        return running;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return running ? boundPort : port;
    }

    public Channel getServerChannel() {
        return serverChannel;
    }

    public ExecutorService getVirtualThreadExecutor() {
        return virtualThreadExecutor;
    }

    public GatewayConfiguration getConfiguration() {
        return configuration;
    }

    public AuditLedger getAuditLedger() {
        return auditLedger;
    }

    public PolicyCache getPolicyCache() {
        return policyCache;
    }

    public ApprovalManager getApprovalManager() {
        return approvalManager;
    }

    public KillSwitchManager getKillSwitchManager() {
        return killSwitchManager;
    }

    public GatewayMetrics getGatewayMetrics() {
        return gatewayMetrics;
    }

    public ComplianceReportEngine getComplianceReportEngine() {
        return complianceReportEngine;
    }

    public AuditVerificationHandler getAuditVerificationHandler() {
        return auditVerificationHandler;
    }

    public AuditRecordsHandler getAuditRecordsHandler() {
        return auditRecordsHandler;
    }

    public ComplianceExportHandler getComplianceExportHandler() {
        return complianceExportHandler;
    }

    public PolicyManagementHandler getPolicyManagementHandler() {
        return policyManagementHandler;
    }

    public ApprovalManagementHandler getApprovalManagementHandler() {
        return approvalManagementHandler;
    }

    public EmergencyManagementHandler getEmergencyManagementHandler() {
        return emergencyManagementHandler;
    }

    public GatewayReadiness getReadiness() {
        return readiness;
    }

    public HealthHandler getHealthHandler() {
        return healthHandler;
    }

    public McpProxyHandler getMcpProxyHandler() {
        return mcpProxyHandler;
    }

    public IdentityVerificationHandler getIdentityVerificationHandler() {
        return identityVerificationHandler;
    }

    public DlpOutboundHandler getDlpOutboundHandler() {
        return dlpOutboundHandler;
    }

    /**
     * Terminal handler: a request that reached it matched no owned path, so it is answered
     * {@code 404} with no internal detail (FEAT-001).
     */
    public static class GatewayDispatcherHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
            boolean keepAlive = io.netty.handler.codec.http.HttpUtil.isKeepAlive(request);
            DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                    HttpVersion.HTTP_1_1,
                    HttpResponseStatus.NOT_FOUND,
                    Unpooled.wrappedBuffer(NOT_FOUND_BODY)
            );
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
            response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, NOT_FOUND_BODY.length);
            if (keepAlive) {
                response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
                ctx.writeAndFlush(response);
            } else {
                response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
                ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            logger.error("Channel error caught in pipeline", cause);
            ctx.close();
        }
    }

    public static void main(String[] args) {
        GatewayConfiguration configuration;
        try {
            configuration = GatewayConfiguration.load();
        } catch (ConfigurationException e) {
            logger.error("Gateway configuration is invalid; refusing to start: {}", e.getMessage());
            System.exit(1);
            return;
        }

        AegisGatewayServer server;
        try {
            server = new AegisGatewayServer(configuration);
        } catch (ConfigurationException e) {
            logger.error("Gateway startup configuration is invalid; refusing to start: {}", e.getMessage());
            System.exit(1);
            return;
        }

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown hook triggered, stopping gateway...");
            server.stop();
        }, "gateway-shutdown-hook"));

        try {
            server.start();
            if (server.getServerChannel() != null) {
                server.getServerChannel().closeFuture().sync();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.info("Server interrupted, exiting.");
        } finally {
            server.stop();
        }
    }
}
