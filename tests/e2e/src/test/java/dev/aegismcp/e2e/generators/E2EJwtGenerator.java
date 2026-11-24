package dev.aegismcp.e2e.generators;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Deterministic JWT and JWKS material for the hermetic identity provider the harness starts.
 * This generator holds no assertions and no process control.
 * Anchors: FEAT-009, NFR-020, C-001.
 */
public final class E2EJwtGenerator {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private E2EJwtGenerator() {
    }

    public static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    public static String createJwksJson(String kid, KeyPair keyPair, String alg) throws Exception {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kid", kid);
        jwk.put("use", "sig");
        jwk.put("alg", alg);
        if (keyPair.getPublic() instanceof RSAPublicKey rsa) {
            jwk.put("kty", "RSA");
            jwk.put("n", base64Url(toUnsignedByteArray(rsa.getModulus())));
            jwk.put("e", base64Url(toUnsignedByteArray(rsa.getPublicExponent())));
        } else if (keyPair.getPublic() instanceof ECPublicKey ec) {
            jwk.put("kty", "EC");
            jwk.put("crv", "P-256");
            jwk.put("x", base64Url(toFixedLengthByteArray(ec.getW().getAffineX(), 32)));
            jwk.put("y", base64Url(toFixedLengthByteArray(ec.getW().getAffineY(), 32)));
        }
        return MAPPER.writeValueAsString(Map.of("keys", List.of(jwk)));
    }

    /**
     * Builds a signed JWT. {@code extraClaims} carries deployment-specific claims such as
     * {@code auth_time} and {@code amr} used by the C-008 multi-factor requirement.
     */
    public static String buildJwt(
            String kid,
            String alg,
            PrivateKey privateKey,
            String issuer,
            String audience,
            String subject,
            Instant issuedAt,
            Instant notBefore,
            Instant expiresAt,
            List<String> roles,
            Map<String, Object> extraClaims
    ) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "JWT");
        header.put("alg", alg);
        if (kid != null) {
            header.put("kid", kid);
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        if (issuer != null) payload.put("iss", issuer);
        if (audience != null) payload.put("aud", audience);
        if (subject != null) payload.put("sub", subject);
        if (issuedAt != null) payload.put("iat", issuedAt.getEpochSecond());
        if (notBefore != null) payload.put("nbf", notBefore.getEpochSecond());
        if (expiresAt != null) payload.put("exp", expiresAt.getEpochSecond());
        if (roles != null && !roles.isEmpty()) payload.put("roles", roles);
        if (extraClaims != null) payload.putAll(extraClaims);

        String headerBase64 = base64Url(MAPPER.writeValueAsBytes(header));
        String payloadBase64 = base64Url(MAPPER.writeValueAsBytes(payload));
        String signingInput = headerBase64 + "." + payloadBase64;

        String jcaAlgorithm = switch (alg) {
            case "RS256" -> "SHA256withRSA";
            case "ES256" -> "SHA256withECDSA";
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        };

        Signature signer = Signature.getInstance(jcaAlgorithm);
        signer.initSign(privateKey);
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        byte[] signature = signer.sign();
        byte[] encoded = alg.startsWith("ES") ? derToRawEcdsa(signature, 32) : signature;
        return signingInput + "." + base64Url(encoded);
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] toUnsignedByteArray(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static byte[] toFixedLengthByteArray(BigInteger value, int length) {
        byte[] bytes = toUnsignedByteArray(value);
        if (bytes.length == length) {
            return bytes;
        }
        byte[] result = new byte[length];
        if (bytes.length < length) {
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
        } else {
            System.arraycopy(bytes, bytes.length - length, result, 0, length);
        }
        return result;
    }

    private static byte[] derToRawEcdsa(byte[] der, int coordinateLength) {
        if (der.length == coordinateLength * 2) {
            return der;
        }
        int offset = 2;
        if ((der[1] & 0x80) != 0) {
            offset += (der[1] & 0x7f);
        }
        offset++;
        int rLength = der[offset++];
        byte[] rBytes = Arrays.copyOfRange(der, offset, offset + rLength);
        offset += rLength;
        offset++;
        int sLength = der[offset++];
        byte[] sBytes = Arrays.copyOfRange(der, offset, offset + sLength);

        byte[] raw = new byte[coordinateLength * 2];
        System.arraycopy(toFixedLengthByteArray(new BigInteger(rBytes), coordinateLength), 0, raw, 0, coordinateLength);
        System.arraycopy(toFixedLengthByteArray(new BigInteger(sBytes), coordinateLength), 0, raw,
                coordinateLength, coordinateLength);
        return raw;
    }
}
