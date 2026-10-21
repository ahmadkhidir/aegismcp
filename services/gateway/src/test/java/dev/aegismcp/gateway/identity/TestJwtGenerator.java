package dev.aegismcp.gateway.identity;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
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
import java.util.*;

/**
 * Pure Java JWT and JWKS builder for unit testing OIDC token validation.
 * Uses synthetic names and in-memory mock keys.
 * Anchors: FEAT-009, NFR-020.
 */
public class TestJwtGenerator {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    public static String createJwksJson(String kid, KeyPair keyPair, String alg) throws Exception {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kid", kid);
        jwk.put("use", "sig");
        jwk.put("alg", alg);

        if (keyPair.getPublic() instanceof RSAPublicKey rsaPub) {
            jwk.put("kty", "RSA");
            jwk.put("n", Base64.getUrlEncoder().withoutPadding().encodeToString(toUnsignedByteArray(rsaPub.getModulus())));
            jwk.put("e", Base64.getUrlEncoder().withoutPadding().encodeToString(toUnsignedByteArray(rsaPub.getPublicExponent())));
        } else if (keyPair.getPublic() instanceof ECPublicKey ecPub) {
            jwk.put("kty", "EC");
            jwk.put("crv", "P-256");
            byte[] xBytes = toFixedLengthByteArray(ecPub.getW().getAffineX(), 32);
            byte[] yBytes = toFixedLengthByteArray(ecPub.getW().getAffineY(), 32);
            jwk.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(xBytes));
            jwk.put("y", Base64.getUrlEncoder().withoutPadding().encodeToString(yBytes));
        }

        Map<String, Object> root = Map.of("keys", List.of(jwk));
        return MAPPER.writeValueAsString(root);
    }

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
            List<String> roles
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

        String headerBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(MAPPER.writeValueAsBytes(header));
        String payloadBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(MAPPER.writeValueAsBytes(payload));
        String signingInput = headerBase64 + "." + payloadBase64;

        String jcaAlg = switch (alg) {
            case "RS256" -> "SHA256withRSA";
            case "ES256" -> "SHA256withECDSA";
            default -> throw new IllegalArgumentException("Unsupported alg: " + alg);
        };

        Signature signer = Signature.getInstance(jcaAlg);
        signer.initSign(privateKey);
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        byte[] sigBytes = signer.sign();

        byte[] finalSig = alg.startsWith("ES") ? derToRawEcdsa(sigBytes, 32) : sigBytes;
        String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(finalSig);

        return signingInput + "." + signatureBase64;
    }

    private static byte[] toUnsignedByteArray(BigInteger bi) {
        byte[] bytes = bi.toByteArray();
        if (bytes[0] == 0 && bytes.length > 1) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static byte[] toFixedLengthByteArray(BigInteger bi, int len) {
        byte[] bytes = toUnsignedByteArray(bi);
        if (bytes.length == len) {
            return bytes;
        }
        byte[] result = new byte[len];
        if (bytes.length < len) {
            System.arraycopy(bytes, 0, result, len - bytes.length, bytes.length);
        } else {
            System.arraycopy(bytes, bytes.length - len, result, 0, len);
        }
        return result;
    }

    private static byte[] derToRawEcdsa(byte[] derSig, int coordLen) {
        if (derSig.length == coordLen * 2) {
            return derSig;
        }
        // DER sequence: 0x30, len, 0x02, rLen, rBytes, 0x02, sLen, sBytes
        int offset = 2; // skip 0x30, len
        if ((derSig[1] & 0x80) != 0) {
            offset += (derSig[1] & 0x7f);
        }
        offset++; // skip 0x02
        int rLen = derSig[offset++];
        byte[] rBytes = Arrays.copyOfRange(derSig, offset, offset + rLen);
        offset += rLen;
        offset++; // skip 0x02
        int sLen = derSig[offset++];
        byte[] sBytes = Arrays.copyOfRange(derSig, offset, offset + sLen);

        BigInteger r = new BigInteger(rBytes);
        BigInteger s = new BigInteger(sBytes);

        byte[] raw = new byte[coordLen * 2];
        byte[] rRaw = toFixedLengthByteArray(r, coordLen);
        byte[] sRaw = toFixedLengthByteArray(s, coordLen);
        System.arraycopy(rRaw, 0, raw, 0, coordLen);
        System.arraycopy(sRaw, 0, raw, coordLen, coordLen);
        return raw;
    }
}
