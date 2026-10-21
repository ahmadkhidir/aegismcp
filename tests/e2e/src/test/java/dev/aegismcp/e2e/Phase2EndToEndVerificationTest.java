package dev.aegismcp.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.cli.AegisCliMain;
import dev.aegismcp.cli.StdioProxy;
import dev.aegismcp.cli.TerminalInspector;
import dev.aegismcp.gateway.dlp.DlpScrubber;
import dev.aegismcp.gateway.identity.AgentIdentityResolver;
import dev.aegismcp.gateway.identity.JwksKeyResolver;
import dev.aegismcp.gateway.identity.OidcTokenValidator;
import dev.aegismcp.gateway.identity.SpiffeSvidValidator;
import dev.aegismcp.gateway.killswitch.KillSwitchManager;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyCompiler;
import dev.aegismcp.gateway.policy.PolicyEvaluator;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
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
 * Comprehensive End-to-End Verification Suite for Phase 2 Gate: Visibility & Developer Experience.
 * Validates Contracts C-001, C-008, C-009, C-010 and Features FEAT-003, FEAT-008, FEAT-009, FEAT-010, NFR-020.
 */
class Phase2EndToEndVerificationTest {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private static KeyPair caKeyPair;
    private static X509Certificate caCert;

    private static KeyPair untrustedCaKeyPair;
    private static X509Certificate untrustedCaCert;

    private static KeyPair agentKeyPair;
    private static KeyPair oidcRsaKeyPair;
    private static String jwksJson;

    private static final String OIDC_ISSUER = "https://idp.enterprise.internal/auth";
    private static final String OIDC_AUDIENCE = "aegismcp-gateway";
    private static final String ADMIN_TOKEN = "Bearer admin-token-secret-999";

    private final ObjectMapper mapper = new ObjectMapper();
    private E2EGatewayFixture fixture;
    private HttpClient standardClient;

    @TempDir
    Path tempDir;

    @BeforeAll
    static void initCrypto() throws Exception {
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");

        caKeyPair = E2ECertificateGenerator.generateRsaKeyPair();
        Date caNotBefore = Date.from(NOW.minusSeconds(86400));
        Date caNotAfter = Date.from(NOW.plusSeconds(86400 * 365));
        caCert = E2ECertificateGenerator.createSelfSignedCa(caKeyPair, "Aegis Cluster CA", caNotBefore, caNotAfter);

        untrustedCaKeyPair = E2ECertificateGenerator.generateRsaKeyPair();
        untrustedCaCert = E2ECertificateGenerator.createSelfSignedCa(untrustedCaKeyPair, "Untrusted Rogue CA", caNotBefore, caNotAfter);

        agentKeyPair = E2ECertificateGenerator.generateRsaKeyPair();

        oidcRsaKeyPair = E2EJwtGenerator.generateRsaKeyPair();
        jwksJson = E2EJwtGenerator.createJwksJson("oidc-key-1", oidcRsaKeyPair, "RS256");
    }

    @AfterEach
    void tearDown() {
        if (fixture != null) {
            fixture.close();
            fixture = null;
        }
    }

    private AgentIdentityResolver createIdentityResolver() throws Exception {
        SpiffeSvidValidator spiffeValidator = new SpiffeSvidValidator(
                Set.of("cluster.local"),
                Set.of(caCert),
                FIXED_CLOCK
        );

        JwksKeyResolver keyResolver = new JwksKeyResolver();
        keyResolver.registerJwksJson(jwksJson);

        OidcTokenValidator oidcValidator = new OidcTokenValidator(
                keyResolver,
                OIDC_ISSUER,
                OIDC_AUDIENCE,
                Duration.ofSeconds(60),
                FIXED_CLOCK
        );

        return new AgentIdentityResolver(spiffeValidator, oidcValidator, true);
    }

    // =========================================================================
    // 1. FEAT-009 / C-001: Verified Agent Identity Integration (SPIFFE & OIDC)
    // =========================================================================

    @Test
    @DisplayName("FEAT-009 / C-001: Valid SPIFFE X.509 SVID authenticates agent workload and proxies tool execution")
    void testValidSpiffeSvidAuthentication() throws Exception {
        Date notBefore = Date.from(NOW.minusSeconds(60));
        Date notAfter = Date.from(NOW.plusSeconds(3600));
        String spiffeUri = "spiffe://cluster.local/ns/prod-agents/sa/support-bot";

        X509Certificate svid = E2ECertificateGenerator.createSpiffeSvid(
                agentKeyPair.getPublic(), "support-bot",
                caKeyPair.getPrivate(), "Aegis Cluster CA",
                spiffeUri, notBefore, notAfter
        );

        SslContext serverSslContext = SslContextBuilder.forServer(caKeyPair.getPrivate(), caCert)
                .trustManager(io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE)
                .clientAuth(ClientAuth.OPTIONAL)
                .build();

        AgentIdentityResolver resolver = createIdentityResolver();
        fixture = E2EGatewayFixture.forMtlsPhase2(resolver, serverSslContext);

        // Build HTTPS client with mutual TLS client certificate
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", agentKeyPair.getPrivate(), new char[0], new Certificate[]{svid, caCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("ca", caCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        SSLContext clientSslContext = SSLContext.getInstance("TLS");
        clientSslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        HttpClient httpsClient = HttpClient.newBuilder()
                .sslContext(clientSslContext)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        String rpcPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": 1,
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"msg": "hello from spiffe workload"}
                  }
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(rpcPayload))
                .build();

        HttpResponse<String> response = httpsClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        JsonNode json = mapper.readTree(response.body());
        assertTrue(json.has("result"), "Expected successful result from upstream");
        assertEquals(1, json.get("id").asInt());

        // Verify session was bound and immediately severed upon quarantine
        int severed = fixture.getKillSwitchManager().quarantineAgent("ns/prod-agents/sa/support-bot", "test verification");
        assertTrue(severed >= 1, "Session must be bound and severed upon quarantine");

        // Subsequent connection from quarantined agent is blocked with HTTP 403 / -32001 Policy Violation
        HttpClient freshClient = HttpClient.newBuilder()
                .sslContext(clientSslContext)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        HttpRequest blockedReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(rpcPayload))
                .build();

        HttpResponse<String> blockedResp = freshClient.send(blockedReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, blockedResp.statusCode());
        JsonNode blockedJson = mapper.readTree(blockedResp.body());
        assertEquals(-32001, blockedJson.get("error").get("code").asInt());
        assertTrue(blockedJson.get("error").get("message").asText().contains("quarantined"));
    }

    @Test
    @DisplayName("FEAT-009 / C-001: Expired SPIFFE certificate is rejected with HTTP 401 Unauthorized (-32000)")
    void testExpiredSpiffeCertificateRejected() throws Exception {
        // Expired SVID: valid between NOW - 7200 and NOW - 3600
        Date notBefore = Date.from(NOW.minusSeconds(7200));
        Date notAfter = Date.from(NOW.minusSeconds(3600));
        String spiffeUri = "spiffe://cluster.local/ns/prod-agents/sa/expired-bot";

        X509Certificate expiredSvid = E2ECertificateGenerator.createSpiffeSvid(
                agentKeyPair.getPublic(), "expired-bot",
                caKeyPair.getPrivate(), "Aegis Cluster CA",
                spiffeUri, notBefore, notAfter
        );

        SslContext serverSslContext = SslContextBuilder.forServer(caKeyPair.getPrivate(), caCert)
                .trustManager(io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE)
                .clientAuth(ClientAuth.OPTIONAL)
                .build();

        AgentIdentityResolver resolver = createIdentityResolver();
        fixture = E2EGatewayFixture.forMtlsPhase2(resolver, serverSslContext);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", agentKeyPair.getPrivate(), new char[0], new Certificate[]{expiredSvid, caCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("ca", caCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        SSLContext clientSslContext = SSLContext.getInstance("TLS");
        clientSslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        HttpClient httpsClient = HttpClient.newBuilder()
                .sslContext(clientSslContext)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        String rpcPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": 2,
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"msg": "should fail"}
                  }
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(rpcPayload))
                .build();

        HttpResponse<String> response = httpsClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, response.statusCode());

        JsonNode json = mapper.readTree(response.body());
        assertTrue(json.has("error"));
        assertEquals(-32000, json.get("error").get("code").asInt());
        assertTrue(json.get("error").get("message").asText().contains("Authentication Failed"));
    }

    @Test
    @DisplayName("FEAT-009 / C-001: Untrusted SPIFFE certificate rejected with HTTP 401 Unauthorized (-32000)")
    void testUntrustedSpiffeCertificateRejected() throws Exception {
        Date notBefore = Date.from(NOW.minusSeconds(60));
        Date notAfter = Date.from(NOW.plusSeconds(3600));
        String spiffeUri = "spiffe://cluster.local/ns/prod-agents/sa/untrusted-bot";

        // Signed by untrusted rogue CA
        X509Certificate untrustedSvid = E2ECertificateGenerator.createSpiffeSvid(
                agentKeyPair.getPublic(), "untrusted-bot",
                untrustedCaKeyPair.getPrivate(), "Untrusted Rogue CA",
                spiffeUri, notBefore, notAfter
        );

        SslContext serverSslContext = SslContextBuilder.forServer(caKeyPair.getPrivate(), caCert)
                .trustManager(io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE)
                .clientAuth(ClientAuth.OPTIONAL)
                .build();

        AgentIdentityResolver resolver = createIdentityResolver();
        fixture = E2EGatewayFixture.forMtlsPhase2(resolver, serverSslContext);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", agentKeyPair.getPrivate(), new char[0], new Certificate[]{untrustedSvid, untrustedCaCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, null);
        ts.setCertificateEntry("ca", caCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        SSLContext clientSslContext = SSLContext.getInstance("TLS");
        clientSslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        HttpClient httpsClient = HttpClient.newBuilder()
                .sslContext(clientSslContext)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        String rpcPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": 3,
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"msg": "untrusted ca"}
                  }
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(rpcPayload))
                .build();

        HttpResponse<String> response = httpsClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, response.statusCode());

        JsonNode json = mapper.readTree(response.body());
        assertTrue(json.has("error"));
        assertEquals(-32000, json.get("error").get("code").asInt());
    }

    @Test
    @DisplayName("FEAT-009 / C-001: Valid OIDC Bearer JWT validates signature, claims, and authenticates agent")
    void testValidOidcBearerJwtAuthentication() throws Exception {
        AgentIdentityResolver resolver = createIdentityResolver();
        fixture = E2EGatewayFixture.forPhase2(resolver);
        standardClient = HttpClient.newHttpClient();

        String validJwt = E2EJwtGenerator.buildJwt(
                "oidc-key-1", "RS256", oidcRsaKeyPair.getPrivate(),
                OIDC_ISSUER, OIDC_AUDIENCE, "agent-k8s-pod-123",
                NOW.minusSeconds(30), NOW.minusSeconds(30), NOW.plusSeconds(3600),
                List.of("agent", "tools:invoke")
        );

        String rpcPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": 10,
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"msg": "oidc authenticated"}
                  }
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + validJwt)
                .POST(HttpRequest.BodyPublishers.ofString(rpcPayload))
                .build();

        HttpResponse<String> response = standardClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        JsonNode json = mapper.readTree(response.body());
        assertTrue(json.has("result"));
        assertEquals(10, json.get("id").asInt());
    }

    @Test
    @DisplayName("FEAT-009 / C-001: Expired OIDC JWT (beyond 60s clock skew) rejected with HTTP 401 Unauthorized (-32000)")
    void testExpiredOidcJwtRejected() throws Exception {
        AgentIdentityResolver resolver = createIdentityResolver();
        fixture = E2EGatewayFixture.forPhase2(resolver);
        standardClient = HttpClient.newHttpClient();

        // Expired 120 seconds ago (beyond the 60s clock skew configured in OidcTokenValidator)
        String expiredJwt = E2EJwtGenerator.buildJwt(
                "oidc-key-1", "RS256", oidcRsaKeyPair.getPrivate(),
                OIDC_ISSUER, OIDC_AUDIENCE, "agent-expired",
                NOW.minusSeconds(3600), NOW.minusSeconds(3600), NOW.minusSeconds(120),
                List.of("agent")
        );

        String rpcPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": 11,
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"msg": "should be rejected"}
                  }
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + expiredJwt)
                .POST(HttpRequest.BodyPublishers.ofString(rpcPayload))
                .build();

        HttpResponse<String> response = standardClient.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, response.statusCode());

        JsonNode json = mapper.readTree(response.body());
        assertTrue(json.has("error"));
        assertEquals(-32000, json.get("error").get("code").asInt());
        assertTrue(json.get("error").get("message").asText().contains("Authentication Failed"));
    }

    // =========================================================================
    // 2. FEAT-010 / C-008, C-009, C-010: Emergency Kill-Switch & Circuit Breaker
    // =========================================================================

    @Test
    @DisplayName("FEAT-010 / C-008: POST /api/v1/emergency/kill quarantines rogue agent and blocks subsequent tool calls")
    void testEmergencyKillAgentQuarantine() throws Exception {
        fixture = new E2EGatewayFixture();
        standardClient = HttpClient.newHttpClient();

        // 1. Initial tool call succeeds
        String allowedCall = """
                {
                  "jsonrpc": "2.0",
                  "id": "init-1",
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"msg": "before quarantine"}
                  }
                }
                """;

        String rogueSpiffe = "spiffe://cluster.local/ns/prod/sa/rogue-agent-77";
        String rogueAgentId = "ns/prod/sa/rogue-agent-77";
        String safeSpiffe = "spiffe://cluster.local/ns/prod/sa/safe-worker-1";

        HttpRequest preReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("X-Spiffe-Id", rogueSpiffe)
                .POST(HttpRequest.BodyPublishers.ofString(allowedCall))
                .build();

        HttpResponse<String> preResp = standardClient.send(preReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, preResp.statusCode());

        // 2. Trigger Emergency Kill-Switch against rogue-agent-77
        String killPayload = String.format("""
                {
                  "targetType": "agent",
                  "targetId": "%s",
                  "reason": "Anomalous lateral movement detected"
                }
                """, rogueAgentId);

        HttpRequest killReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/api/v1/emergency/kill"))
                .header("Content-Type", "application/json")
                .header("Authorization", ADMIN_TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(killPayload))
                .build();

        HttpResponse<String> killResp = standardClient.send(killReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, killResp.statusCode());

        JsonNode killJson = mapper.readTree(killResp.body());
        assertEquals("QUARANTINED", killJson.get("status").asText());
        assertTrue(fixture.getKillSwitchManager().isAgentQuarantined(rogueAgentId));

        // 3. Subsequent tool call from quarantined agent is blocked immediately with 403 / -32001
        HttpRequest postReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("X-Spiffe-Id", rogueSpiffe)
                .POST(HttpRequest.BodyPublishers.ofString(allowedCall))
                .build();

        HttpResponse<String> postResp = standardClient.send(postReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, postResp.statusCode());

        JsonNode postJson = mapper.readTree(postResp.body());
        assertTrue(postJson.has("error"));
        assertEquals(-32001, postJson.get("error").get("code").asInt());
        assertTrue(postJson.get("error").get("message").asText().contains("quarantined"));

        // 4. Different, unquarantined agent is unaffected
        HttpRequest otherReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("X-Spiffe-Id", safeSpiffe)
                .POST(HttpRequest.BodyPublishers.ofString(allowedCall))
                .build();

        HttpResponse<String> otherResp = standardClient.send(otherReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, otherResp.statusCode());
    }

    @Test
    @DisplayName("FEAT-010 / C-008: POST /api/v1/emergency/kill sets tool-level quarantine and blocks specific tool")
    void testEmergencyKillToolQuarantine() throws Exception {
        fixture = new E2EGatewayFixture();
        standardClient = HttpClient.newHttpClient();

        // Quarantine 'curl:exec' tool
        String killPayload = """
                {
                  "targetType": "tool",
                  "targetId": "curl:exec",
                  "reason": "Vulnerability CVE-2026-9999 discovered in curl tool"
                }
                """;

        HttpRequest killReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/api/v1/emergency/kill"))
                .header("Content-Type", "application/json")
                .header("Authorization", ADMIN_TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(killPayload))
                .build();

        HttpResponse<String> killResp = standardClient.send(killReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, killResp.statusCode());

        // Call to quarantined tool is blocked with 403 / -32001
        String toolCall = """
                {
                  "jsonrpc": "2.0",
                  "id": "tool-call-1",
                  "method": "tools/call",
                  "params": {
                    "name": "curl:exec",
                    "arguments": {"url": "https://api.example.com"}
                  }
                }
                """;

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer valid-agent-token-1")
                .POST(HttpRequest.BodyPublishers.ofString(toolCall))
                .build();

        HttpResponse<String> resp = standardClient.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, resp.statusCode());

        JsonNode json = mapper.readTree(resp.body());
        assertEquals(-32001, json.get("error").get("code").asInt());
        assertTrue(json.get("error").get("message").asText().contains("Tool 'curl:exec' is quarantined"));

        // Call to non-quarantined tool 'echo' succeeds
        String echoCall = """
                {
                  "jsonrpc": "2.0",
                  "id": "echo-1",
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"msg": "still works"}
                  }
                }
                """;

        HttpRequest echoReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer valid-agent-token-1")
                .POST(HttpRequest.BodyPublishers.ofString(echoCall))
                .build();

        HttpResponse<String> echoResp = standardClient.send(echoReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, echoResp.statusCode());
    }

    @Test
    @DisplayName("FEAT-010 / C-008: Global emergency lockdown severs all subsequent tool invocations")
    void testGlobalEmergencyLockdown() throws Exception {
        fixture = new E2EGatewayFixture();
        standardClient = HttpClient.newHttpClient();

        String globalLockdownPayload = """
                {
                  "targetType": "global",
                  "targetId": "global",
                  "reason": "Active critical breach across infrastructure"
                }
                """;

        HttpRequest killReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/api/v1/emergency/kill"))
                .header("Content-Type", "application/json")
                .header("Authorization", ADMIN_TOKEN)
                .POST(HttpRequest.BodyPublishers.ofString(globalLockdownPayload))
                .build();

        HttpResponse<String> killResp = standardClient.send(killReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, killResp.statusCode());

        assertTrue(fixture.getKillSwitchManager().isGlobalLockdown());

        // Any subsequent tool call is blocked immediately
        String toolCall = """
                {
                  "jsonrpc": "2.0",
                  "id": "global-blocked",
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"msg": "any agent"}
                  }
                }
                """;

        HttpRequest rpcReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer any-agent-token")
                .POST(HttpRequest.BodyPublishers.ofString(toolCall))
                .build();

        HttpResponse<String> rpcResp = standardClient.send(rpcReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, rpcResp.statusCode());

        JsonNode json = mapper.readTree(rpcResp.body());
        assertEquals(-32001, json.get("error").get("code").asInt());
        assertTrue(json.get("error").get("message").asText().contains("Global emergency lockdown is active"));
    }

    @Test
    @DisplayName("FEAT-010 / C-009, C-010: GET /api/v1/system/status and /api/v1/metrics/summary report live system metrics")
    void testSystemStatusAndMetricsEndpoints() throws Exception {
        fixture = new E2EGatewayFixture();
        standardClient = HttpClient.newHttpClient();

        // 1. Query C-009 System Status
        HttpRequest statusReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/api/v1/system/status"))
                .header("Authorization", ADMIN_TOKEN)
                .GET()
                .build();

        HttpResponse<String> statusResp = standardClient.send(statusReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, statusResp.statusCode());

        JsonNode statusJson = mapper.readTree(statusResp.body());
        assertTrue(statusJson.has("status"));
        assertEquals("NORMAL", statusJson.get("status").asText());
        assertTrue(statusJson.has("activeConnections"));
        assertTrue(statusJson.has("totalRequests24h"));
        assertTrue(statusJson.has("blockedViolations24h"));
        assertTrue(statusJson.has("pendingApprovals"));

        // 2. Query C-010 Metrics Summary
        HttpRequest metricsReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/api/v1/metrics/summary"))
                .header("Authorization", ADMIN_TOKEN)
                .GET()
                .build();

        HttpResponse<String> metricsResp = standardClient.send(metricsReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, metricsResp.statusCode());

        JsonNode metricsJson = mapper.readTree(metricsResp.body());
        assertTrue(metricsJson.has("activeAgents"));
        assertTrue(metricsJson.has("toolCalls24h"));
        assertTrue(metricsJson.has("blockedViolations24h"));
        assertTrue(metricsJson.has("pendingApprovals"));
        assertTrue(metricsJson.has("uptimeSeconds"));

        // 3. Set global lockdown and verify C-009 reflects 'LOCKDOWN' threat level
        fixture.getKillSwitchManager().activateGlobalLockdown("Testing threat level escalation");

        HttpResponse<String> escalatedStatusResp = standardClient.send(statusReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, escalatedStatusResp.statusCode());
        JsonNode escalatedJson = mapper.readTree(escalatedStatusResp.body());
        assertEquals("LOCKDOWN", escalatedJson.get("status").asText());
    }

    @Test
    @DisplayName("FEAT-010: Invocation velocity circuit breaker trips and quarantines runaway agent")
    void testVelocityCircuitBreakerTripsAndQuarantines() throws Exception {
        // Configure low burst threshold of 5 calls within 10 seconds for testing
        fixture = new E2EGatewayFixture(
                dev.aegismcp.gateway.proxy.UpstreamClient.mockEcho(),
                true,
                100_000,
                5, // velocity threshold: 5 calls
                null,
                null
        );
        standardClient = HttpClient.newHttpClient();

        String callPayload = """
                {
                  "jsonrpc": "2.0",
                  "id": %d,
                  "method": "tools/call",
                  "params": {
                    "name": "echo",
                    "arguments": {"count": %d}
                  }
                }
                """;

        String token = "Bearer rapid-burst-worker-token";

        // First 5 rapid calls should succeed
        for (int i = 1; i <= 5; i++) {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", token)
                    .POST(HttpRequest.BodyPublishers.ofString(String.format(callPayload, i, i)))
                    .build();

            HttpResponse<String> resp = standardClient.send(req, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, resp.statusCode(), "Call " + i + " should succeed before threshold");
        }

        // 6th rapid call trips the velocity circuit breaker
        HttpRequest tripReq = HttpRequest.newBuilder()
                .uri(URI.create(fixture.getBaseUrl() + "/mcp/v1/rpc"))
                .header("Content-Type", "application/json")
                .header("Authorization", token)
                .POST(HttpRequest.BodyPublishers.ofString(String.format(callPayload, 6, 6)))
                .build();

        HttpResponse<String> tripResp = standardClient.send(tripReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, tripResp.statusCode(), "6th call should trip circuit breaker and return 403");

        JsonNode json = mapper.readTree(tripResp.body());
        assertEquals(-32001, json.get("error").get("code").asInt());
        assertTrue(json.get("error").get("message").asText().toLowerCase().contains("velocity circuit breaker tripped"));

        // Verify agent is quarantined in KillSwitchManager
        assertTrue(fixture.getKillSwitchManager().isAgentQuarantined("agent-bearer"));
    }

    // =========================================================================
    // 3. FEAT-003: aegis-cli Local Developer CLI Integration Testing
    // =========================================================================

    @Test
    @DisplayName("FEAT-003: aegis-cli lint validates policy YAML syntax and detects schema violations")
    void testAegisCliLintCommand() throws Exception {
        String validYaml = """
                id: cli-valid-policy
                name: Valid Developer Policy
                version: 1.0.0
                target_agents:
                  - dev-agent-*
                default_action: DENY
                rules:
                  - id: rule-allow-echo
                    tool: echo
                    action: ALLOW
                  - id: rule-allow-read
                    tool: read_file
                    action: ALLOW
                    constraints:
                      - argument: path
                        operator: STARTS_WITH
                        value: /tmp/
                """;

        Path validFile = tempDir.resolve("valid-policy.yaml");
        Files.writeString(validFile, validYaml);

        int exitCodeValid = AegisCliMain.execute("lint", validFile.toString());
        assertEquals(0, exitCodeValid, "Valid policy must return exit code 0");

        String invalidYaml = """
                id: invalid-policy
                rules:
                  - id: missing-tool-and-action
                """;

        Path invalidFile = tempDir.resolve("invalid-policy.yaml");
        Files.writeString(invalidFile, invalidYaml);

        int exitCodeInvalid = AegisCliMain.execute("lint", invalidFile.toString());
        assertEquals(1, exitCodeInvalid, "Invalid policy schema must return non-zero exit code 1");
    }

    @Test
    @DisplayName("FEAT-003 / FEAT-010 / C-008: aegis-cli kill dispatches emergency kill-switch command to running gateway")
    void testAegisCliKillCommandIntegration() throws Exception {
        fixture = new E2EGatewayFixture();

        String targetAgent = "agent-cli-quarantine-target";

        // Invoke 'aegis-cli kill' command targeting running gateway fixture
        int exitCode = AegisCliMain.execute(
                "kill",
                "-g", fixture.getBaseUrl(),
                "-t", "admin-token-secret-999",
                "-a", targetAgent,
                "-r", "Malicious activity flagged during CLI integration test"
        );

        assertEquals(0, exitCode, "KillCommand should succeed with exit code 0");

        // Assert agent is quarantined in live gateway fixture
        assertTrue(fixture.getKillSwitchManager().isAgentQuarantined(targetAgent),
                "Agent should be quarantined in gateway after CLI invocation");
    }

    @Test
    @DisplayName("FEAT-003 / FEAT-005: aegis-cli wrap intercepts JSON-RPC tool calls and applies DLP redaction on child process")
    void testAegisCliWrapWithDlpRedaction() throws Exception {
        String javaBin = ProcessHandle.current().info().command().orElse(System.getProperty("java.home") + "/bin/java");
        String classPath = System.getProperty("java.class.path");

        List<String> childCommand = List.of(javaBin, "-cp", classPath, "dev.aegismcp.e2e.E2EMockMcpChildServer");

        String policyYaml = """
                id: wrap-test-policy
                name: Wrap Test Policy
                version: 1.0.0
                target_agents:
                  - "*"
                default_action: DENY
                rules:
                  - id: allow-read
                    tool: read_file
                    action: ALLOW
                """;

        PolicyCache cache = new PolicyCache(PolicyCompiler.getInstance());
        SecurityPolicy policy = SecurityPolicy.of("wrap-test-policy", "Wrap Test Policy", "1.0.0", policyYaml, "test");
        cache.putPolicy(policy);
        cache.bindAgentToPolicy("*", policy.id());
        PolicyEvaluator evaluator = new PolicyEvaluator(cache);

        // Simulated tool call executing read_file that returns sensitive AWS access key
        String inputJsonRpc = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/file.txt\"}}}\n";
        ByteArrayInputStream parentIn = new ByteArrayInputStream(inputJsonRpc.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream parentOut = new ByteArrayOutputStream();
        ByteArrayOutputStream parentErr = new ByteArrayOutputStream();

        TerminalInspector inspector = new TerminalInspector(new PrintStream(parentErr), true);
        StdioProxy proxy = new StdioProxy(childCommand, evaluator, DlpScrubber.getInstance(), inspector);

        int exitCode = proxy.start(parentIn, new PrintStream(parentOut), new PrintStream(parentErr));
        assertEquals(0, exitCode, "Child proxy should complete with exit code 0");

        String output = parentOut.toString(StandardCharsets.UTF_8);
        assertFalse(output.contains("AKIAIOSFODNN7EXAMPLE"), "AWS access key must be scrubbed by DLP");
        assertTrue(output.contains("[REDACTED_API_KEY]"), "Scrubbed output should contain redaction token");
    }

    // =========================================================================
    // 4. FEAT-008: Web Console Automated Suite & Production Build Verification
    // =========================================================================

    @Test
    @DisplayName("FEAT-008: Web security console automated test suite and production build pass cleanly")
    void testWebConsoleTestSuiteAndBuild() throws Exception {
        // Locate apps/console directory relative to project root
        File consoleDir = new File("../../apps/console").getCanonicalFile();
        if (!consoleDir.exists()) {
            consoleDir = new File("apps/console").getCanonicalFile();
        }
        assertTrue(consoleDir.exists() && consoleDir.isDirectory(), "apps/console directory must exist at " + consoleDir);

        // 1. Run vitest test suite
        ProcessBuilder testPb = new ProcessBuilder("npm", "test", "--", "--run");
        testPb.directory(consoleDir);
        testPb.redirectErrorStream(true);
        Process testProcess = testPb.start();

        String testOutput = new String(testProcess.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int testExit = testProcess.waitFor();

        assertEquals(0, testExit, "Console npm test should exit with code 0. Output:\n" + testOutput);
        assertTrue(testOutput.contains("passed") || testOutput.contains("✓"), "Test output must indicate passing suites");

        // 2. Run production build
        ProcessBuilder buildPb = new ProcessBuilder("npm", "run", "build");
        buildPb.directory(consoleDir);
        buildPb.redirectErrorStream(true);
        Process buildProcess = buildPb.start();

        String buildOutput = new String(buildProcess.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int buildExit = buildProcess.waitFor();

        assertEquals(0, buildExit, "Console npm run build should exit with code 0. Output:\n" + buildOutput);
        assertTrue(buildOutput.contains("built in"), "Build output should indicate successful Vite build");

        File distDir = new File(consoleDir, "dist");
        assertTrue(distDir.exists() && distDir.isDirectory(), "dist/ directory must be created after build");
        assertTrue(new File(distDir, "index.html").exists(), "dist/index.html must exist");
    }
}
