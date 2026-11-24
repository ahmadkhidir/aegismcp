package dev.aegismcp.e2e.fixtures;

import com.sun.net.httpserver.HttpServer;
import dev.aegismcp.e2e.generators.E2EJwtGenerator;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Local OpenID Connect key endpoint and token issuer for one gateway process. It runs as its own
 * HTTP server outside the gateway; the artifact reaches it only through the configured JWKS URL.
 * Anchors: FEAT-009, NFR-020, C-001, C-002.
 */
public final class TestIdentityProvider implements AutoCloseable {

    private static final String KEY_ID = "e2e-signing-key";

    private final HttpServer server;
    private final KeyPair keyPair;
    private final String jwksJson;
    private final String issuer;
    private final String audience;

    public TestIdentityProvider() throws Exception {
        this.keyPair = E2EJwtGenerator.generateRsaKeyPair();
        this.jwksJson = E2EJwtGenerator.createJwksJson(KEY_ID, keyPair, "RS256");
        this.issuer = "https://idp.aegis.test";
        this.audience = "aegis-gateway";
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        this.server.createContext("/.well-known/jwks.json", exchange -> {
            byte[] body = jwksJson.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        this.server.start();
    }

    public String issuer() {
        return issuer;
    }

    public String audience() {
        return audience;
    }

    public String jwksUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/.well-known/jwks.json";
    }

    /** A valid token for the subject with the supplied RBAC roles. */
    public String token(String subject, String... roles) {
        return token(subject, List.of(roles), Map.of());
    }

    /** A valid token carrying deployment claims such as {@code auth_time} and {@code amr}. */
    public String token(String subject, List<String> roles, Map<String, Object> extraClaims) {
        Instant now = Instant.now();
        try {
            return E2EJwtGenerator.buildJwt(
                    KEY_ID, "RS256", keyPair.getPrivate(), issuer, audience, subject,
                    now.minus(Duration.ofSeconds(5)), now.minus(Duration.ofSeconds(5)),
                    now.plus(Duration.ofMinutes(10)), roles, extraClaims);
        } catch (Exception e) {
            throw new IllegalStateException("The harness could not sign a test token", e);
        }
    }

    /** A structurally valid token whose signature does not verify. */
    public String tamperedToken(String subject) {
        String token = token(subject, "admin");
        int lastDot = token.lastIndexOf('.');
        char last = token.charAt(token.length() - 1);
        return token.substring(0, token.length() - 1) + (last == 'A' ? 'B' : 'A');
    }

    /** A correctly signed token whose expiry is beyond the validator's clock skew. */
    public String expiredToken(String subject) {
        Instant now = Instant.now();
        try {
            return E2EJwtGenerator.buildJwt(
                    KEY_ID, "RS256", keyPair.getPrivate(), issuer, audience, subject,
                    now.minus(Duration.ofHours(2)), now.minus(Duration.ofHours(2)),
                    now.minus(Duration.ofMinutes(5)), List.of("admin"), Map.of());
        } catch (Exception e) {
            throw new IllegalStateException("The harness could not sign an expired test token", e);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
