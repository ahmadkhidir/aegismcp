package dev.aegismcp.gateway.identity;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link SpiffeSvidValidator}.
 * Anchors: FEAT-009, NFR-020, C-001.
 */
class SpiffeSvidValidatorTest {

    private static KeyPair caKeyPair;
    private static X509Certificate caCert;
    private static KeyPair agentKeyPair;

    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @BeforeAll
    static void setupKeys() throws Exception {
        caKeyPair = TestCertificateGenerator.generateRsaKeyPair();
        Date caNotBefore = Date.from(NOW.minusSeconds(86400));
        Date caNotAfter = Date.from(NOW.plusSeconds(86400 * 365));
        caCert = TestCertificateGenerator.createSelfSignedCa(caKeyPair, "Test Cluster Root CA", caNotBefore, caNotAfter);

        agentKeyPair = TestCertificateGenerator.generateRsaKeyPair();
    }

    @Test
    @DisplayName("FEAT-009 AC 1 / C-001: Valid SPIFFE SVID extraction and trust domain validation")
    void testValidSpiffeSvidExtractionAndTrustDomain() throws Exception {
        Date notBefore = Date.from(NOW.minusSeconds(3600));
        Date notAfter = Date.from(NOW.plusSeconds(3600));
        String spiffeUri = "spiffe://cluster.local/ns/agents/sa/support-bot";

        X509Certificate svid = TestCertificateGenerator.createSpiffeSvid(
                agentKeyPair.getPublic(), "support-bot",
                caKeyPair.getPrivate(), "Test Cluster Root CA",
                spiffeUri, notBefore, notAfter
        );

        SpiffeSvidValidator validator = new SpiffeSvidValidator(
                Set.of("cluster.local"),
                Set.of(caCert),
                FIXED_CLOCK
        );

        SpiffeValidationResult result = validator.validate(new X509Certificate[]{svid, caCert});

        assertTrue(result.valid(), "Expected validation to succeed: " + result.errorMessage());
        assertNotNull(result.spiffeId());
        assertEquals("cluster.local", result.spiffeId().trustDomain());
        assertEquals("/ns/agents/sa/support-bot", result.spiffeId().path());
        assertEquals("ns/agents/sa/support-bot", result.workloadId());
        assertEquals("support-bot", result.spiffeId().kubernetesServiceAccount());
        assertEquals("agents", result.spiffeId().kubernetesNamespace());
    }

    @Test
    @DisplayName("FEAT-009 AC 3: Untrusted SPIFFE trust domain is rejected")
    void testUntrustedTrustDomainRejection() throws Exception {
        Date notBefore = Date.from(NOW.minusSeconds(3600));
        Date notAfter = Date.from(NOW.plusSeconds(3600));
        String spiffeUri = "spiffe://rogue.untrusted.domain/ns/agents/sa/rogue-agent";

        X509Certificate svid = TestCertificateGenerator.createSpiffeSvid(
                agentKeyPair.getPublic(), "rogue-agent",
                caKeyPair.getPrivate(), "Test Cluster Root CA",
                spiffeUri, notBefore, notAfter
        );

        SpiffeSvidValidator validator = new SpiffeSvidValidator(
                Set.of("cluster.local"),
                Set.of(caCert),
                FIXED_CLOCK
        );

        SpiffeValidationResult result = validator.validate(new X509Certificate[]{svid, caCert});

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("Untrusted SPIFFE trust domain"),
                "Expected trust domain error, got: " + result.errorMessage());
    }

    @Test
    @DisplayName("FEAT-009 AC 3: Expired SPIFFE certificate is rejected")
    void testExpiredSpiffeCertificateRejection() throws Exception {
        // Expired 1 hour ago
        Date notBefore = Date.from(NOW.minusSeconds(7200));
        Date notAfter = Date.from(NOW.minusSeconds(3600));
        String spiffeUri = "spiffe://cluster.local/ns/agents/sa/support-bot";

        X509Certificate svid = TestCertificateGenerator.createSpiffeSvid(
                agentKeyPair.getPublic(), "support-bot",
                caKeyPair.getPrivate(), "Test Cluster Root CA",
                spiffeUri, notBefore, notAfter
        );

        SpiffeSvidValidator validator = new SpiffeSvidValidator(
                Set.of("cluster.local"),
                Set.of(caCert),
                FIXED_CLOCK
        );

        SpiffeValidationResult result = validator.validate(new X509Certificate[]{svid, caCert});

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("expired"),
                "Expected expired error, got: " + result.errorMessage());
    }

    @Test
    @DisplayName("FEAT-009 AC 3: Not yet valid SPIFFE certificate is rejected")
    void testNotYetValidCertificateRejection() throws Exception {
        // Becomes valid 1 hour in the future
        Date notBefore = Date.from(NOW.plusSeconds(3600));
        Date notAfter = Date.from(NOW.plusSeconds(7200));
        String spiffeUri = "spiffe://cluster.local/ns/agents/sa/support-bot";

        X509Certificate svid = TestCertificateGenerator.createSpiffeSvid(
                agentKeyPair.getPublic(), "support-bot",
                caKeyPair.getPrivate(), "Test Cluster Root CA",
                spiffeUri, notBefore, notAfter
        );

        SpiffeSvidValidator validator = new SpiffeSvidValidator(
                Set.of("cluster.local"),
                Set.of(caCert),
                FIXED_CLOCK
        );

        SpiffeValidationResult result = validator.validate(new X509Certificate[]{svid, caCert});

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("not yet valid"),
                "Expected not yet valid error, got: " + result.errorMessage());
    }

    @Test
    @DisplayName("FEAT-009: Untrusted CA root signature fails validation")
    void testUntrustedCaSignatureFailsValidation() throws Exception {
        KeyPair rogueCa = TestCertificateGenerator.generateRsaKeyPair();
        Date notBefore = Date.from(NOW.minusSeconds(3600));
        Date notAfter = Date.from(NOW.plusSeconds(3600));
        String spiffeUri = "spiffe://cluster.local/ns/agents/sa/support-bot";

        X509Certificate svidSignedByRogue = TestCertificateGenerator.createSpiffeSvid(
                agentKeyPair.getPublic(), "support-bot",
                rogueCa.getPrivate(), "Rogue Untrusted CA",
                spiffeUri, notBefore, notAfter
        );

        SpiffeSvidValidator validator = new SpiffeSvidValidator(
                Set.of("cluster.local"),
                Set.of(caCert), // caCert does NOT trust rogueCa
                FIXED_CLOCK
        );

        SpiffeValidationResult result = validator.validate(new X509Certificate[]{svidSignedByRogue});

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("Untrusted certificate chain"),
                "Expected untrusted chain error, got: " + result.errorMessage());
    }

    @Test
    @DisplayName("FEAT-009: Missing SAN extension fails validation")
    void testMissingSanExtensionFailsValidation() throws Exception {
        Date notBefore = Date.from(NOW.minusSeconds(3600));
        Date notAfter = Date.from(NOW.plusSeconds(3600));

        // Create cert without SPIFFE SAN
        X509Certificate certWithoutSan = TestCertificateGenerator.createCertificate(
                agentKeyPair.getPublic(), "plain-cert",
                caKeyPair.getPrivate(), "Test Cluster Root CA",
                null, notBefore, notAfter
        );

        SpiffeSvidValidator validator = new SpiffeSvidValidator(
                Set.of("cluster.local"),
                Set.of(caCert),
                FIXED_CLOCK
        );

        SpiffeValidationResult result = validator.validate(new X509Certificate[]{certWithoutSan, caCert});

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("Subject Alternative Names"),
                "Expected missing SAN error, got: " + result.errorMessage());
    }

    @Test
    @DisplayName("FEAT-009: Multiple conflicting SPIFFE IDs in SAN extension fails validation")
    void testMultipleConflictingSpiffeIdsFailValidation() throws Exception {
        Date notBefore = Date.from(NOW.minusSeconds(3600));
        Date notAfter = Date.from(NOW.plusSeconds(3600));

        List<String> twoSpiffeUris = List.of(
                "spiffe://cluster.local/ns/agents/sa/bot-a",
                "spiffe://cluster.local/ns/agents/sa/bot-b"
        );

        X509Certificate certWithMultiSan = TestCertificateGenerator.createCertificate(
                agentKeyPair.getPublic(), "multi-san-cert",
                caKeyPair.getPrivate(), "Test Cluster Root CA",
                twoSpiffeUris, notBefore, notAfter
        );

        SpiffeSvidValidator validator = new SpiffeSvidValidator(
                Set.of("cluster.local"),
                Set.of(caCert),
                FIXED_CLOCK
        );

        SpiffeValidationResult result = validator.validate(new X509Certificate[]{certWithMultiSan, caCert});

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("multiple conflicting SPIFFE IDs"),
                "Expected conflicting SAN error, got: " + result.errorMessage());
    }

    @Test
    @DisplayName("FEAT-009: Raw SPIFFE ID string validation")
    void testValidateSpiffeIdString() {
        SpiffeSvidValidator validator = new SpiffeSvidValidator(Set.of("cluster.local"));

        SpiffeValidationResult valid = validator.validateSpiffeIdString("spiffe://cluster.local/ns/default/sa/worker");
        assertTrue(valid.valid());
        assertEquals("ns/default/sa/worker", valid.workloadId());

        SpiffeValidationResult untrusted = validator.validateSpiffeIdString("spiffe://other.domain/ns/default/sa/worker");
        assertFalse(untrusted.valid());
        assertTrue(untrusted.errorMessage().contains("Untrusted SPIFFE trust domain"));

        SpiffeValidationResult malformed = validator.validateSpiffeIdString("invalid-spiffe-uri");
        assertFalse(malformed.valid());
    }
}
