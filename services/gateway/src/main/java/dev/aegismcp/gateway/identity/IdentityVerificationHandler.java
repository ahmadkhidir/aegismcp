package dev.aegismcp.gateway.identity;

import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.audit.AuditRecord;
import dev.aegismcp.gateway.killswitch.KillSwitchManager;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

/**
 * Authenticates every agent-transport request at the edge before any handler or interceptor sees
 * it, binds the verified identity to the channel, and fails closed on a missing or untrusted
 * credential.
 *
 * <p>Probe endpoints and the operator management API are exempt here: probes are unauthenticated by
 * contract (C-022, C-023) and management endpoints verify the operator token through their own
 * contract authorizer. Agent transports live under {@code /mcp/}, so a request reaching the proxy
 * without a verified identity can only be a defect and is refused.
 *
 * <p>Anchors: FEAT-001, FEAT-009, NFR-020, NFR-027, C-001.
 */
@ChannelHandler.Sharable
public class IdentityVerificationHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private static final Logger logger = LoggerFactory.getLogger(IdentityVerificationHandler.class);

    public static final String HANDLER_NAME = "identity-verifier";
    public static final String AGENT_PATH_PREFIX = "/mcp/";

    private static final byte[] UNAUTHORIZED_BODY = (
            "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,"
                    + "\"message\":\"Authentication Failed\",\"data\":{\"code\":\"AUTHENTICATION_FAILED\"}}}"
    ).getBytes(StandardCharsets.UTF_8);

    private final AgentIdentityResolver resolver;
    private final AuditLedger auditLedger;
    private final KillSwitchManager killSwitchManager;
    private final Executor worker;

    public IdentityVerificationHandler(
            AgentIdentityResolver resolver,
            AuditLedger auditLedger,
            KillSwitchManager killSwitchManager,
            Executor worker
    ) {
        super(false); // The request is released on every handled path
        this.resolver = Objects.requireNonNull(resolver, "resolver must not be null");
        this.auditLedger = auditLedger;
        this.killSwitchManager = killSwitchManager;
        this.worker = Objects.requireNonNull(worker, "worker must not be null");
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        String path = request.uri();
        int query = path.indexOf('?');
        if (query >= 0) {
            path = path.substring(0, query);
        }

        if (!path.startsWith(AGENT_PATH_PREFIX)) {
            ctx.fireChannelRead(request);
            return;
        }

        // JWT signature verification may fetch the identity provider's keys. That is network work,
        // so it runs on a virtual thread and the channel only carries the framing (NFR-002).
        request.retain();
        try {
            worker.execute(() -> verify(ctx, request));
        } catch (RejectedExecutionException e) {
            logger.error("Identity worker rejected the verification; refusing the request", e);
            ctx.executor().execute(() -> sendUnauthorized(ctx, request));
        }
    }

    private void verify(ChannelHandlerContext ctx, FullHttpRequest request) {
        try {
            dev.aegismcp.gateway.identity.AgentIdentity verified = resolver.resolve(request, ctx);
            if (!verified.authenticated()) {
                recordRejection(verified);
                ctx.executor().execute(() -> sendUnauthorized(ctx, request));
                return;
            }

            AgentIdentity bound = verified.toProxyIdentity();
            ctx.executor().execute(() -> {
                ctx.channel().attr(AgentIdentity.VERIFIED_ATTRIBUTE).set(bound);
                if (killSwitchManager != null) {
                    killSwitchManager.registerSession(bound.agentId(), ctx.channel());
                    if (bound.spiffeId() != null) {
                        killSwitchManager.registerSession(bound.spiffeId(), ctx.channel());
                    }
                }
                ctx.fireChannelRead(request);
            });
        } catch (RuntimeException e) {
            logger.warn("Agent identity verification failed; refusing the request", e);
            recordRejection(null);
            ctx.executor().execute(() -> sendUnauthorized(ctx, request));
        }
    }

    private void recordRejection(dev.aegismcp.gateway.identity.AgentIdentity rejected) {
        if (auditLedger == null) {
            return;
        }
        String agentId = rejected != null && rejected.id() != null ? rejected.id() : "unauthenticated";
        // The rejection reason stays in the resolver's log; the audit record carries no credential.
        auditLedger.append(AuditRecord.create(agentId, "mcp/authentication", "AUTHENTICATION_FAILED", 0, 0, ""));
    }

    private void sendUnauthorized(ChannelHandlerContext ctx, FullHttpRequest request) {
        boolean keepAlive = HttpUtil.isKeepAlive(request);
        DefaultFullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                HttpResponseStatus.UNAUTHORIZED,
                Unpooled.wrappedBuffer(UNAUTHORIZED_BODY)
        );
        response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, UNAUTHORIZED_BODY.length);
        if (keepAlive) {
            response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
            ctx.writeAndFlush(response);
        } else {
            response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        }
        request.release();
    }
}
