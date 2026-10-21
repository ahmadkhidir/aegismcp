package dev.aegismcp.gateway.identity;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslHandler;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link AgentIdentityResolver}.
 * Anchors: FEAT-009, NFR-020, C-001.
 */
class AgentIdentityResolverTest {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private static KeyPair caKeyPair;
    private static X509Certificate caCert;
    private static KeyPair agentKeyPair;

    private static KeyPair oidcRsaKeyPair;
    private static SpiffeSvidValidator spiffeValidator;
    private static OidcTokenValidator oidcValidator;
    private static AgentIdentityResolver resolver;

    private static final String ISSUER = "https://idp.enterprise.internal/auth";
    private static final String AUDIENCE = "aegismcp-gateway";

    @BeforeAll
    static void setup() throws Exception {
        caKeyPair = TestCertificateGenerator.generateRsaKeyPair();
        Date caNotBefore = Date.from(NOW.minusSeconds(86400));
        Date caNotAfter = Date.from(NOW.plusSeconds(86400 * 365));
        caCert = TestCertificateGenerator.createSelfSignedCa(caKeyPair, "Cluster CA", caNotBefore, caNotAfter);
        agentKeyPair = TestCertificateGenerator.generateRsaKeyPair();

        spiffeValidator = new SpiffeSvidValidator(
                Set.of("cluster.local"),
                Set.of(caCert),
                FIXED_CLOCK
        );

        oidcRsaKeyPair = TestJwtGenerator.generateRsaKeyPair();
        String jwks = TestJwtGenerator.createJwksJson("oidc-key", oidcRsaKeyPair, "RS256");
        JwksKeyResolver keyResolver = new JwksKeyResolver();
        keyResolver.registerJwksJson(jwks);

        oidcValidator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);
        resolver = new AgentIdentityResolver(spiffeValidator, oidcValidator, true);
    }

    @Test
    @DisplayName("FEAT-009 / C-001: Resolves agent identity from valid mTLS X.509 SVID peer certificates")
    void testResolveFromMtlsPeerCertificates() throws Exception {
        Date notBefore = Date.from(NOW.minusSeconds(60));
        Date notAfter = Date.from(NOW.plusSeconds(3600));
        String spiffeUri = "spiffe://cluster.local/ns/agents/sa/support-bot";

        X509Certificate svid = TestCertificateGenerator.createSpiffeSvid(
                agentKeyPair.getPublic(), "support-bot",
                caKeyPair.getPrivate(), "Cluster CA",
                spiffeUri, notBefore, notAfter
        );

        AgentIdentity identity = resolver.resolve(new X509Certificate[]{svid, caCert}, null, null);

        assertTrue(identity.authenticated());
        assertEquals(IdentityType.SPIFFE, identity.type());
        assertEquals("ns/agents/sa/support-bot", identity.id());
        assertEquals(spiffeUri, identity.spiffeId());
        assertTrue(identity.roles().contains("sa:support-bot"));
        assertTrue(identity.roles().contains("ns:agents"));

        // Verify compatibility with proxy AgentIdentity
        dev.aegismcp.gateway.proxy.AgentIdentity proxyId = identity.toProxyIdentity();
        assertEquals("ns/agents/sa/support-bot", proxyId.agentId());
        assertEquals(spiffeUri, proxyId.spiffeId());
        assertTrue(proxyId.authenticated());
    }

    @Test
    @DisplayName("FEAT-009 / C-001: Resolves agent identity from valid Bearer JWT")
    void testResolveFromBearerJwt() throws Exception {
        String token = TestJwtGenerator.buildJwt(
                "oidc-key", "RS256", oidcRsaKeyPair.getPrivate(),
                ISSUER, AUDIENCE, "agent-oidc-worker",
                NOW.minusSeconds(30), NOW.minusSeconds(30), NOW.plusSeconds(3600),
                List.of("agent", "tools:read")
        );

        AgentIdentity identity = resolver.resolve(null, "Bearer " + token, null);

        assertTrue(identity.authenticated());
        assertEquals(IdentityType.OIDC, identity.type());
        assertEquals("agent-oidc-worker", identity.id());
        assertNull(identity.spiffeId());
        assertTrue(identity.roles().containsAll(Set.of("agent", "tools:read")));

        dev.aegismcp.gateway.proxy.AgentIdentity proxyId = identity.toProxyIdentity();
        assertEquals("agent-oidc-worker", proxyId.agentId());
        assertEquals(token, proxyId.bearerToken());
        assertTrue(proxyId.authenticated());
    }

    @Test
    @DisplayName("FEAT-009: Resolves agent identity from X-Spiffe-Id header when allowed")
    void testResolveFromSpiffeHeader() {
        String spiffeUri = "spiffe://cluster.local/ns/agents/sa/ingress-bot";

        AgentIdentity identity = resolver.resolve(null, null, spiffeUri);

        assertTrue(identity.authenticated());
        assertEquals(IdentityType.SPIFFE, identity.type());
        assertEquals("ns/agents/sa/ingress-bot", identity.id());
        assertEquals(spiffeUri, identity.spiffeId());
    }

    @Test
    @DisplayName("FEAT-009 / NFR-027: Anonymous request resolves to unauthenticated identity")
    void testAnonymousRequestFailsAuthentication() {
        AgentIdentity identity = resolver.resolve(null, null, null);

        assertFalse(identity.authenticated());
        assertEquals(IdentityType.ANONYMOUS, identity.type());
        assertEquals("anonymous", identity.id());
    }

    @Test
    @DisplayName("FEAT-009: Expired or untrusted credentials fail closed (resolveOrThrow throws AuthenticationException)")
    void testFailClosedOnInvalidCredentials() throws Exception {
        // Expired token
        String expiredToken = TestJwtGenerator.buildJwt(
                "oidc-key", "RS256", oidcRsaKeyPair.getPrivate(),
                ISSUER, AUDIENCE, "expired-agent",
                NOW.minusSeconds(300), NOW.minusSeconds(300), NOW.minusSeconds(120),
                List.of("agent")
        );

        AgentIdentity identity = resolver.resolve(null, "Bearer " + expiredToken, null);
        assertFalse(identity.authenticated());

        assertThrows(AuthenticationException.class, () ->
                resolver.resolveOrThrow(null, "Bearer " + expiredToken, null)
        );
    }

    @Test
    @DisplayName("FEAT-009 / C-001: Netty FullHttpRequest integration with Authorization header")
    void testNettyRequestResolution() throws Exception {
        String token = TestJwtGenerator.buildJwt(
                "oidc-key", "RS256", oidcRsaKeyPair.getPrivate(),
                ISSUER, AUDIENCE, "netty-agent-01",
                NOW.minusSeconds(30), NOW.minusSeconds(30), NOW.plusSeconds(3600),
                List.of("agent")
        );

        FullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/mcp/v1/rpc");
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Bearer " + token);

        AgentIdentity identity = resolver.resolve(request, null);

        assertTrue(identity.authenticated());
        assertEquals("netty-agent-01", identity.id());
    }
}
