package dev.aegismcp.gateway.identity;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link OidcTokenValidator}.
 * Anchors: FEAT-009, NFR-020, C-001.
 */
class OidcTokenValidatorTest {

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private static final String ISSUER = "https://idp.enterprise.internal/auth/realms/agents";
    private static final String AUDIENCE = "aegismcp-gateway";

    private static KeyPair rsaKeyPair;
    private static KeyPair ecKeyPair;
    private static JwksKeyResolver keyResolver;

    @BeforeAll
    static void setupKeys() throws Exception {
        rsaKeyPair = TestJwtGenerator.generateRsaKeyPair();
        ecKeyPair = TestJwtGenerator.generateEcKeyPair();

        String rsaJwks = TestJwtGenerator.createJwksJson("rsa-key-1", rsaKeyPair, "RS256");
        String ecJwks = TestJwtGenerator.createJwksJson("ec-key-1", ecKeyPair, "ES256");

        keyResolver = new JwksKeyResolver();
        keyResolver.registerJwksJson(rsaJwks);
        keyResolver.registerJwksJson(ecJwks);
    }

    @Test
    @DisplayName("FEAT-009 AC 2 / C-001: Valid RS256 OIDC token signature and claims parsing")
    void testValidRsaTokenSignatureAndClaimsParsing() throws Exception {
        String token = TestJwtGenerator.buildJwt(
                "rsa-key-1", "RS256", rsaKeyPair.getPrivate(),
                ISSUER, AUDIENCE, "agent-support-bot-01",
                NOW.minusSeconds(60), NOW.minusSeconds(60), NOW.plusSeconds(3600),
                List.of("agent", "operator", "tools:read")
        );

        OidcTokenValidator validator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);
        OidcValidationResult result = validator.validate(token);

        assertTrue(result.valid(), "Expected validation to succeed: " + result.errorMessage());
        assertEquals("agent-support-bot-01", result.subject());
        assertEquals(ISSUER, result.claims().get("iss"));
        assertEquals(AUDIENCE, result.claims().get("aud"));
        assertTrue(result.roles().containsAll(Set.of("agent", "operator", "tools:read")));
    }

    @Test
    @DisplayName("FEAT-009 AC 2 / C-001: Valid ES256 (ECDSA P-256) OIDC token signature and claims parsing")
    void testValidEcTokenSignatureAndClaimsParsing() throws Exception {
        String token = TestJwtGenerator.buildJwt(
                "ec-key-1", "ES256", ecKeyPair.getPrivate(),
                ISSUER, AUDIENCE, "agent-ec-worker",
                NOW.minusSeconds(60), NOW.minusSeconds(60), NOW.plusSeconds(1800),
                List.of("worker", "tools:execute")
        );

        OidcTokenValidator validator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);
        OidcValidationResult result = validator.validate(token);

        assertTrue(result.valid(), "Expected validation to succeed: " + result.errorMessage());
        assertEquals("agent-ec-worker", result.subject());
        assertTrue(result.roles().contains("worker"));
    }

    @Test
    @DisplayName("FEAT-009 Edge Case: Token expired within 60-second clock skew tolerance is accepted")
    void testTokenExpiredWithinClockSkewWindowIsAccepted() throws Exception {
        // Expired 30 seconds ago (within the 60-second leeway window)
        Instant expiredThirtySecsAgo = NOW.minusSeconds(30);

        String token = TestJwtGenerator.buildJwt(
                "rsa-key-1", "RS256", rsaKeyPair.getPrivate(),
                ISSUER, AUDIENCE, "skew-agent",
                NOW.minusSeconds(300), NOW.minusSeconds(300), expiredThirtySecsAgo,
                List.of("agent")
        );

        OidcTokenValidator validator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);
        OidcValidationResult result = validator.validate(token);

        assertTrue(result.valid(), "Expected token within 60s clock skew window to be accepted, but failed: " + result.errorMessage());
    }

    @Test
    @DisplayName("FEAT-009 Edge Case: Token expired beyond 60-second clock skew tolerance is rejected")
    void testTokenExpiredBeyondClockSkewWindowIsRejected() throws Exception {
        // Expired 65 seconds ago (> 60s clock skew window)
        Instant expiredSixtyFiveSecsAgo = NOW.minusSeconds(65);

        String token = TestJwtGenerator.buildJwt(
                "rsa-key-1", "RS256", rsaKeyPair.getPrivate(),
                ISSUER, AUDIENCE, "expired-agent",
                NOW.minusSeconds(300), NOW.minusSeconds(300), expiredSixtyFiveSecsAgo,
                List.of("agent")
        );

        OidcTokenValidator validator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);
        OidcValidationResult result = validator.validate(token);

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("expired"), "Expected expired error, got: " + result.errorMessage());
    }

    @Test
    @DisplayName("FEAT-009 Edge Case: Token not-before within 60s clock skew tolerance is accepted")
    void testTokenNotBeforeWithinClockSkewWindowIsAccepted() throws Exception {
        // Not before is 30 seconds in the future (within 60s clock skew leeway)
        Instant nbfThirtySecsFuture = NOW.plusSeconds(30);

        String token = TestJwtGenerator.buildJwt(
                "rsa-key-1", "RS256", rsaKeyPair.getPrivate(),
                ISSUER, AUDIENCE, "future-agent",
                NOW, nbfThirtySecsFuture, NOW.plusSeconds(3600),
                List.of("agent")
        );

        OidcTokenValidator validator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);
        OidcValidationResult result = validator.validate(token);

        assertTrue(result.valid(), "Expected token within 60s nbf clock skew to be accepted: " + result.errorMessage());
    }

    @Test
    @DisplayName("FEAT-009 Edge Case: Token not-before beyond 60s clock skew tolerance is rejected")
    void testTokenNotBeforeBeyondClockSkewWindowIsRejected() throws Exception {
        // Not before is 65 seconds in the future (> 60s clock skew leeway)
        Instant nbfSixtyFiveSecsFuture = NOW.plusSeconds(65);

        String token = TestJwtGenerator.buildJwt(
                "rsa-key-1", "RS256", rsaKeyPair.getPrivate(),
                ISSUER, AUDIENCE, "future-agent",
                NOW, nbfSixtyFiveSecsFuture, NOW.plusSeconds(3600),
                List.of("agent")
        );

        OidcTokenValidator validator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);
        OidcValidationResult result = validator.validate(token);

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("not yet valid"), "Expected not yet valid error, got: " + result.errorMessage());
    }

    @Test
    @DisplayName("FEAT-009 / NFR-027: Missing or malformed tokens fail-closed")
    void testMissingOrMalformedTokensFailClosed() {
        OidcTokenValidator validator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);

        assertFalse(validator.validate(null).valid());
        assertFalse(validator.validate("").valid());
        assertFalse(validator.validate("   ").valid());
        assertFalse(validator.validate("not-a-jwt").valid());
        assertFalse(validator.validate("only.two.parts.here.bad").valid());
        assertFalse(validator.validate("header.payload").valid());
        assertFalse(validator.validate("bad_b64.bad_b64.bad_sig").valid());
    }

    @Test
    @DisplayName("FEAT-009 / NFR-020: Tampered payload or wrong signing key fails signature verification")
    void testTamperedPayloadFailsVerification() throws Exception {
        KeyPair anotherKeyPair = TestJwtGenerator.generateRsaKeyPair();

        // Sign token with a key NOT registered in JWKS under rsa-key-1
        String token = TestJwtGenerator.buildJwt(
                "rsa-key-1", "RS256", anotherKeyPair.getPrivate(),
                ISSUER, AUDIENCE, "tampered-agent",
                NOW.minusSeconds(60), NOW.minusSeconds(60), NOW.plusSeconds(3600),
                List.of("agent")
        );

        OidcTokenValidator validator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);
        OidcValidationResult result = validator.validate(token);

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("signature"), "Expected signature failure, got: " + result.errorMessage());
    }

    @Test
    @DisplayName("FEAT-009: Algorithm 'none' is rejected immediately (fail-closed)")
    void testAlgorithmNoneIsRejected() {
        // Construct a token with alg=none
        String header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
        String payload = "{\"sub\":\"attacker\",\"iss\":\"" + ISSUER + "\",\"aud\":\"" + AUDIENCE + "\"}";

        String token = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes()) + "." +
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes()) + ".";

        OidcTokenValidator validator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);
        OidcValidationResult result = validator.validate(token);

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("alg=none is rejected"));
    }

    @Test
    @DisplayName("FEAT-009: Issuer mismatch fails validation")
    void testIssuerMismatchFailsValidation() throws Exception {
        String token = TestJwtGenerator.buildJwt(
                "rsa-key-1", "RS256", rsaKeyPair.getPrivate(),
                "https://untrusted-idp.example.com", AUDIENCE, "agent-01",
                NOW.minusSeconds(60), NOW.minusSeconds(60), NOW.plusSeconds(3600),
                List.of("agent")
        );

        OidcTokenValidator validator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);
        OidcValidationResult result = validator.validate(token);

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("Invalid JWT issuer"));
    }

    @Test
    @DisplayName("FEAT-009: Audience mismatch fails validation")
    void testAudienceMismatchFailsValidation() throws Exception {
        String token = TestJwtGenerator.buildJwt(
                "rsa-key-1", "RS256", rsaKeyPair.getPrivate(),
                ISSUER, "wrong-audience", "agent-01",
                NOW.minusSeconds(60), NOW.minusSeconds(60), NOW.plusSeconds(3600),
                List.of("agent")
        );

        OidcTokenValidator validator = new OidcTokenValidator(keyResolver, ISSUER, AUDIENCE, Duration.ofSeconds(60), FIXED_CLOCK);
        OidcValidationResult result = validator.validate(token);

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("Invalid JWT audience"));
    }

    @Test
    @DisplayName("FEAT-009 Edge Case: JWKS endpoint failure serves cached keys within grace period")
    void testJwksGracePeriodOnIdpFailure() throws Exception {
        KeyPair rotKeyPair = TestJwtGenerator.generateRsaKeyPair();
        String initialJwks = TestJwtGenerator.createJwksJson("rot-key-1", rotKeyPair, "RS256");

        AtomicBoolean idpAvailable = new AtomicBoolean(true);
        JwksKeyResolver dynamicResolver = new JwksKeyResolver(
                () -> {
                    if (!idpAvailable.get()) {
                        throw new RuntimeException("IdP 503 Service Unavailable");
                    }
                    return initialJwks;
                },
                Duration.ofSeconds(10), // Short TTL
                Duration.ofHours(1),    // 1-hour grace period
                FIXED_CLOCK
        );

        // Warm cache
        dynamicResolver.refreshKeys();
        assertNotNull(dynamicResolver.resolveKey("rot-key-1", "RS256"));

        // Simulate IdP failure
        idpAvailable.set(false);

        // Key should still resolve via grace period cache
        assertNotNull(dynamicResolver.resolveKey("rot-key-1", "RS256"));

        // Unknown key with failed IdP fails closed
        assertThrows(AuthenticationException.class, () -> dynamicResolver.resolveKey("unknown-key", "RS256"));
    }
}
