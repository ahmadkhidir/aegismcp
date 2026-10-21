package dev.aegismcp.gateway.identity;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.ssl.SslHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Resolves incoming network and transport credentials into a cryptographically verified {@link AgentIdentity}.
 * Enforces fail-closed authentication for invalid, expired, untrusted, or malformed credentials.
 * Anchors: FEAT-009, NFR-020, C-001.
 */
public class AgentIdentityResolver {

    private static final Logger logger = LoggerFactory.getLogger(AgentIdentityResolver.class);

    public static final String HEADER_SPIFFE_ID = "X-Spiffe-Id";
    public static final String BEARER_PREFIX = "Bearer ";

    private final SpiffeSvidValidator spiffeValidator;
    private final OidcTokenValidator oidcValidator;
    private final boolean allowSpiffeHeader;

    public AgentIdentityResolver(SpiffeSvidValidator spiffeValidator, OidcTokenValidator oidcValidator) {
        this(spiffeValidator, oidcValidator, true);
    }

    public AgentIdentityResolver(
            SpiffeSvidValidator spiffeValidator,
            OidcTokenValidator oidcValidator,
            boolean allowSpiffeHeader
    ) {
        this.spiffeValidator = spiffeValidator != null ? spiffeValidator : new SpiffeSvidValidator();
        this.oidcValidator = oidcValidator != null ? oidcValidator : new OidcTokenValidator(new JwksKeyResolver());
        this.allowSpiffeHeader = allowSpiffeHeader;
    }

    /**
     * Resolves agent identity from Netty HTTP request and channel context (extracting mTLS certs and headers).
     */
    public AgentIdentity resolve(FullHttpRequest request, ChannelHandlerContext ctx) {
        X509Certificate[] peerCertificates = extractPeerCertificates(ctx);
        String authHeader = request != null ? request.headers().get(HttpHeaderNames.AUTHORIZATION) : null;
        String spiffeHeader = request != null ? request.headers().get(HEADER_SPIFFE_ID) : null;

        return resolve(peerCertificates, authHeader, spiffeHeader);
    }

    /**
     * Resolves agent identity from explicit peer certificates or header credentials.
     */
    public AgentIdentity resolve(
            X509Certificate[] peerCertificates,
            String authorizationHeader,
            String spiffeHeader
    ) {
        // 1. High priority: Mutual TLS peer certificate chain (SPIFFE X.509 SVID)
        if (peerCertificates != null && peerCertificates.length > 0 && peerCertificates[0] != null) {
            return resolveCertificate(peerCertificates);
        }

        // 2. Next priority: OpenID Connect / OAuth 2.0 Bearer JWT
        if (authorizationHeader != null && authorizationHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            String token = authorizationHeader.substring(BEARER_PREFIX.length()).trim();
            return resolveBearer(token);
        }

        // 3. Fallback: Upstream ingress terminated SPIFFE header (if permitted)
        if (allowSpiffeHeader && spiffeHeader != null && !spiffeHeader.isBlank()) {
            return resolveSpiffeHeader(spiffeHeader.trim());
        }

        // 4. Default stance: Anonymous / unauthenticated
        return AgentIdentity.anonymous();
    }

    /**
     * Resolves and verifies an X.509 SVID certificate chain.
     */
    public AgentIdentity resolveCertificate(X509Certificate[] chain) {
        SpiffeValidationResult result = spiffeValidator.validate(chain);
        if (!result.valid()) {
            logger.warn("SPIFFE mTLS authentication rejected: {}", result.errorMessage());
            return AgentIdentity.unauthenticated("untrusted-spiffe-peer", result.errorMessage());
        }

        SpiffeId spiffeId = result.spiffeId();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("spiffe_id", spiffeId.toString());
        claims.put("trust_domain", spiffeId.trustDomain());
        claims.put("workload_id", spiffeId.workloadId());

        Set<String> roles = new LinkedHashSet<>();
        if (spiffeId.kubernetesNamespace() != null) {
            claims.put("namespace", spiffeId.kubernetesNamespace());
            roles.add("ns:" + spiffeId.kubernetesNamespace());
        }
        if (spiffeId.kubernetesServiceAccount() != null) {
            claims.put("service_account", spiffeId.kubernetesServiceAccount());
            roles.add("sa:" + spiffeId.kubernetesServiceAccount());
        }

        return AgentIdentity.spiffe(spiffeId.toString(), spiffeId.workloadId(), claims, roles);
    }

    /**
     * Resolves and verifies an OIDC Bearer token.
     */
    public AgentIdentity resolveBearer(String bearerToken) {
        OidcValidationResult result = oidcValidator.validate(bearerToken);
        if (!result.valid()) {
            logger.warn("OIDC Bearer token rejected: {}", result.errorMessage());
            return AgentIdentity.unauthenticated("invalid-bearer-token", result.errorMessage());
        }

        Map<String, Object> claims = new LinkedHashMap<>(result.claims());
        // Store redacted or reference token claim if needed without logging
        claims.put("raw_token", bearerToken);

        return AgentIdentity.oidc(result.subject(), claims, result.roles());
    }

    /**
     * Resolves a SPIFFE ID string presented via header (e.g. from trusted Envoy / ingress sidecar).
     */
    public AgentIdentity resolveSpiffeHeader(String spiffeHeader) {
        SpiffeValidationResult result = spiffeValidator.validateSpiffeIdString(spiffeHeader);
        if (!result.valid()) {
            logger.warn("SPIFFE header rejected: {}", result.errorMessage());
            return AgentIdentity.unauthenticated("invalid-spiffe-header", result.errorMessage());
        }

        SpiffeId spiffeId = result.spiffeId();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("spiffe_id", spiffeId.toString());
        claims.put("trust_domain", spiffeId.trustDomain());
        claims.put("workload_id", spiffeId.workloadId());
        claims.put("via_header", true);

        Set<String> roles = new LinkedHashSet<>();
        if (spiffeId.kubernetesNamespace() != null) {
            claims.put("namespace", spiffeId.kubernetesNamespace());
            roles.add("ns:" + spiffeId.kubernetesNamespace());
        }
        if (spiffeId.kubernetesServiceAccount() != null) {
            claims.put("service_account", spiffeId.kubernetesServiceAccount());
            roles.add("sa:" + spiffeId.kubernetesServiceAccount());
        }

        return AgentIdentity.spiffe(spiffeId.toString(), spiffeId.workloadId(), claims, roles);
    }

    /**
     * Resolves identity, throwing {@link AuthenticationException} if authentication fails or is unauthenticated.
     */
    public AgentIdentity resolveOrThrow(
            X509Certificate[] peerCertificates,
            String authorizationHeader,
            String spiffeHeader
    ) {
        AgentIdentity identity = resolve(peerCertificates, authorizationHeader, spiffeHeader);
        if (!identity.authenticated()) {
            String reason = String.valueOf(identity.claims().getOrDefault("error", "Missing or invalid agent credentials"));
            throw new AuthenticationException("Agent authentication failed: " + reason);
        }
        return identity;
    }

    private static X509Certificate[] extractPeerCertificates(ChannelHandlerContext ctx) {
        if (ctx == null) {
            return null;
        }
        SslHandler sslHandler = ctx.pipeline().get(SslHandler.class);
        if (sslHandler == null) {
            return null;
        }
        try {
            SSLSession session = sslHandler.engine().getSession();
            Certificate[] peerCerts = session.getPeerCertificates();
            List<X509Certificate> x509List = new ArrayList<>();
            for (Certificate cert : peerCerts) {
                if (cert instanceof X509Certificate x509) {
                    x509List.add(x509);
                }
            }
            return x509List.isEmpty() ? null : x509List.toArray(new X509Certificate[0]);
        } catch (SSLPeerUnverifiedException ignored) {
            return null;
        } catch (Exception e) {
            logger.debug("Could not extract peer certificates from SSL session: {}", e.getMessage());
            return null;
        }
    }
}
