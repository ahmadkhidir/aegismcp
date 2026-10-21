package dev.aegismcp.gateway.compliance;

import dev.aegismcp.gateway.audit.HashUtils;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;

/**
 * Cryptographic signer generating SHA-256 HMAC attestations over audit records, Merkle roots,
 * and report metadata to guarantee non-repudiation per NFR-041 and FEAT-011.
 * Anchors: FEAT-011, NFR-041, C-011.
 */
public class ComplianceAttestationSigner {

    public static final String DEFAULT_SIGNING_KEY_PROPERTY = "AEGIS_COMPLIANCE_SIGNING_KEY";
    private static final byte[] FALLBACK_SECRET_KEY = "aegismcp-tamper-evident-compliance-hmac-secret-v1".getBytes(StandardCharsets.UTF_8);

    private final byte[] secretKey;

    public ComplianceAttestationSigner() {
        this(resolveSigningKey());
    }

    public ComplianceAttestationSigner(byte[] secretKey) {
        if (secretKey == null || secretKey.length == 0) {
            throw new IllegalArgumentException("secretKey must not be null or empty");
        }
        this.secretKey = secretKey.clone();
    }

    private static byte[] resolveSigningKey() {
        String envKey = System.getenv(DEFAULT_SIGNING_KEY_PROPERTY);
        if (envKey != null && !envKey.isBlank()) {
            return envKey.trim().getBytes(StandardCharsets.UTF_8);
        }
        return FALLBACK_SECRET_KEY;
    }

    /**
     * Generates a deterministic SHA-256 HMAC digital attestation signature across report parameters,
     * Merkle tree root, and individual audit record hashes.
     */
    public String signAttestation(
            String framework,
            String reportId,
            String merkleRoot,
            int recordCount,
            int violationsCount,
            int approvalsCount,
            String generatedAt,
            List<String> recordHashes
    ) {
        String canonical = buildCanonicalPayload(framework, reportId, merkleRoot, recordCount,
                violationsCount, approvalsCount, generatedAt, recordHashes);
        return HashUtils.hmacSha256Hex(secretKey, canonical);
    }

    /**
     * Verifies that the provided signature matches the HMAC computed over the canonical attestation payload.
     */
    public boolean verifyAttestation(
            String framework,
            String reportId,
            String merkleRoot,
            int recordCount,
            int violationsCount,
            int approvalsCount,
            String generatedAt,
            List<String> recordHashes,
            String signature
    ) {
        if (signature == null || signature.isBlank()) {
            return false;
        }
        String expected = signAttestation(framework, reportId, merkleRoot, recordCount,
                violationsCount, approvalsCount, generatedAt, recordHashes);
        return MessageDigestUtils.constantTimeEquals(expected, signature.trim());
    }

    private String buildCanonicalPayload(
            String framework,
            String reportId,
            String merkleRoot,
            int recordCount,
            int violationsCount,
            int approvalsCount,
            String generatedAt,
            List<String> recordHashes
    ) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("AegisMCP-Attestation-v1|")
                .append(framework != null ? framework : "").append('|')
                .append(reportId != null ? reportId : "").append('|')
                .append(merkleRoot != null ? merkleRoot : "").append('|')
                .append(recordCount).append('|')
                .append(violationsCount).append('|')
                .append(approvalsCount).append('|')
                .append(generatedAt != null ? generatedAt : "");

        if (recordHashes != null && !recordHashes.isEmpty()) {
            sb.append('|');
            sb.append(String.join(",", recordHashes));
        }

        return sb.toString();
    }

    private static class MessageDigestUtils {
        static boolean constantTimeEquals(String a, String b) {
            if (a == null || b == null) {
                return a == b;
            }
            if (a.length() != b.length()) {
                return false;
            }
            int result = 0;
            for (int i = 0; i < a.length(); i++) {
                result |= a.charAt(i) ^ b.charAt(i);
            }
            return result == 0;
        }
    }
}
