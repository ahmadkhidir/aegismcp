package dev.aegismcp.gateway.compliance;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests verifying SHA-256 HMAC digital attestation signing and non-repudiation.
 * Anchors: FEAT-011, NFR-041, C-011.
 */
class ComplianceAttestationSignerTest {

    @Test
    @DisplayName("FEAT-011 / NFR-041: Generates verifiable SHA-256 HMAC attestation signature")
    void testSignAndVerifyAttestation() {
        ComplianceAttestationSigner signer = new ComplianceAttestationSigner();

        String framework = "EU_AI_ACT";
        String reportId = "rep-12345";
        String merkleRoot = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        int recordCount = 42;
        int violationsCount = 2;
        int approvalsCount = 5;
        String generatedAt = Instant.now().toString();
        List<String> recordHashes = List.of("hash1", "hash2", "hash3");

        String signature = signer.signAttestation(
                framework,
                reportId,
                merkleRoot,
                recordCount,
                violationsCount,
                approvalsCount,
                generatedAt,
                recordHashes
        );

        assertNotNull(signature);
        assertFalse(signature.isBlank());
        // SHA-256 hex string is 64 characters
        assertTrue(signature.matches("^[0-9a-f]{64}$"), "HMAC-SHA256 signature must be 64 lowercase hex characters");

        // Verify valid attestation
        boolean verified = signer.verifyAttestation(
                framework,
                reportId,
                merkleRoot,
                recordCount,
                violationsCount,
                approvalsCount,
                generatedAt,
                recordHashes,
                signature
        );
        assertTrue(verified, "Cryptographic attestation signature must verify successfully");
    }

    @Test
    @DisplayName("FEAT-011: Tampered attestation parameters fail verification")
    void testTamperedAttestationFailsVerification() {
        ComplianceAttestationSigner signer = new ComplianceAttestationSigner();

        String framework = "SOC2_TYPE2";
        String reportId = "rep-secure-999";
        String merkleRoot = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";
        int recordCount = 100;
        int violationsCount = 0;
        int approvalsCount = 10;
        String generatedAt = Instant.now().toString();
        List<String> recordHashes = List.of("hashA", "hashB");

        String signature = signer.signAttestation(
                framework,
                reportId,
                merkleRoot,
                recordCount,
                violationsCount,
                approvalsCount,
                generatedAt,
                recordHashes
        );

        // Tamper record count
        assertFalse(signer.verifyAttestation(
                framework,
                reportId,
                merkleRoot,
                101, // modified count
                violationsCount,
                approvalsCount,
                generatedAt,
                recordHashes,
                signature
        ));

        // Tamper Merkle root
        assertFalse(signer.verifyAttestation(
                framework,
                reportId,
                "0000000000000000000000000000000000000000000000000000000000000000",
                recordCount,
                violationsCount,
                approvalsCount,
                generatedAt,
                recordHashes,
                signature
        ));

        // Tamper signature string
        assertFalse(signer.verifyAttestation(
                framework,
                reportId,
                merkleRoot,
                recordCount,
                violationsCount,
                approvalsCount,
                generatedAt,
                recordHashes,
                "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb"
        ));
    }

    @Test
    @DisplayName("FEAT-011: Custom secret key generates independent cryptographic signatures")
    void testCustomSecretKey() {
        byte[] key1 = "secret-key-alpha-1234567890123456".getBytes(StandardCharsets.UTF_8);
        byte[] key2 = "secret-key-bravo-1234567890123456".getBytes(StandardCharsets.UTF_8);

        ComplianceAttestationSigner signer1 = new ComplianceAttestationSigner(key1);
        ComplianceAttestationSigner signer2 = new ComplianceAttestationSigner(key2);

        String generatedAt = Instant.now().toString();
        String sig1 = signer1.signAttestation("EU_AI_ACT", "rep-1", "root1", 1, 0, 0, generatedAt, List.of("h1"));
        String sig2 = signer2.signAttestation("EU_AI_ACT", "rep-1", "root1", 1, 0, 0, generatedAt, List.of("h1"));

        assertNotNull(sig1);
        assertNotNull(sig2);
        assertFalse(sig1.equals(sig2), "Signatures with distinct secret keys must differ");

        assertFalse(signer2.verifyAttestation("EU_AI_ACT", "rep-1", "root1", 1, 0, 0, generatedAt, List.of("h1"), sig1));
    }

    @Test
    @DisplayName("FEAT-011: Rejects null or empty secret key")
    void testRejectsNullOrEmptyKey() {
        assertThrows(IllegalArgumentException.class, () -> new ComplianceAttestationSigner((byte[]) null));
        assertThrows(IllegalArgumentException.class, () -> new ComplianceAttestationSigner(new byte[0]));
    }
}
