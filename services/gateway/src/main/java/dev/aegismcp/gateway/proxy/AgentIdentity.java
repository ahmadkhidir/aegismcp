package dev.aegismcp.gateway.proxy;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

/**
 * Representation of an Agent Workload identity validated via SPIFFE mTLS (X.509 SVID) or Bearer JWT.
 * Anchors: FEAT-001, C-001.
 */
public record AgentIdentity(
        String agentId,
        String spiffeId,
        String bearerToken,
        boolean authenticated
) {
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String HEADER_SPIFFE_ID = "X-Spiffe-Id";

    public static AgentIdentity anonymous() {
        return new AgentIdentity("anonymous", null, null, false);
    }

    public static AgentIdentity fromBearer(String token) {
        String agentId = "agent-" + (token.length() > 8 ? token.substring(0, 8) : token);
        return new AgentIdentity(agentId, null, token, true);
    }

    public static AgentIdentity fromSpiffe(String spiffeId) {
        String agentId = spiffeId.replaceFirst("^spiffe://[^/]+/", "");
        return new AgentIdentity(agentId, spiffeId, null, true);
    }

    public static AgentIdentity fromCredentials(String spiffeId, String bearerToken) {
        String agentId = spiffeId != null ? spiffeId.replaceFirst("^spiffe://[^/]+/", "") : "agent-bearer";
        return new AgentIdentity(agentId, spiffeId, bearerToken, true);
    }

    /**
     * Extracts agent identity from HTTP headers and Netty SSL session peer certificates.
     */
    public static AgentIdentity extract(FullHttpRequest request, ChannelHandlerContext ctx) {
        String spiffeId = null;

        // 1. Check for SPIFFE SVID from SSL session if TLS is present
        SslHandler sslHandler = ctx != null ? ctx.pipeline().get(SslHandler.class) : null;
        if (sslHandler != null) {
            try {
                SSLSession session = sslHandler.engine().getSession();
                Certificate[] peerCerts = session.getPeerCertificates();
                if (peerCerts.length > 0 && peerCerts[0] instanceof X509Certificate x509) {
                    Collection<List<?>> sans = x509.getSubjectAlternativeNames();
                    if (sans != null) {
                        for (List<?> san : sans) {
                            // SAN type 6 is URI (RFC 5280)
                            if (san.size() >= 2 && Integer.valueOf(6).equals(san.get(0))) {
                                String uriVal = String.valueOf(san.get(1));
                                if (uriVal.startsWith("spiffe://")) {
                                    spiffeId = uriVal;
                                    break;
                                }
                            }
                        }
                    }
                }
            } catch (SSLPeerUnverifiedException ignored) {
                // Mutual TLS not established or peer not verified
            } catch (Exception ignored) {
                // Best effort extraction
            }
        }

        // 2. Check X-Spiffe-Id header if mTLS terminated at upstream load balancer/sidecar
        if (spiffeId == null && request.headers().contains(HEADER_SPIFFE_ID)) {
            String headerSpiffe = request.headers().get(HEADER_SPIFFE_ID).trim();
            if (headerSpiffe.startsWith("spiffe://")) {
                spiffeId = headerSpiffe;
            }
        }

        // 3. Check Authorization Bearer header
        String authHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);
        String bearerToken = null;
        if (authHeader != null && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            bearerToken = authHeader.substring(BEARER_PREFIX.length()).trim();
        }

        if (spiffeId != null || (bearerToken != null && !bearerToken.isEmpty())) {
            return fromCredentials(spiffeId, bearerToken);
        }

        return anonymous();
    }
}
