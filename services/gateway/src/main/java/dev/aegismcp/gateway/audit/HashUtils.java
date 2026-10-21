package dev.aegismcp.gateway.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Cryptographic hash utilities for SHA-256 computation in the audit ledger.
 * Anchors: FEAT-007, NFR-004.
 */
public final class HashUtils {

    private static final String SHA_256 = "SHA-256";
    private static final HexFormat HEX_FORMAT = HexFormat.of();

    private HashUtils() {
    }

    /**
     * Computes the SHA-256 hash of a UTF-8 string, returning lowercase 64-char hex string.
     */
    public static String sha256Hex(String input) {
        if (input == null) {
            return sha256Hex(new byte[0]);
        }
        return sha256Hex(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Computes the SHA-256 hash of byte array, returning lowercase 64-char hex string.
     */
    public static String sha256Hex(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            byte[] hash = digest.digest(input);
            return HEX_FORMAT.formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 message digest algorithm not available", e);
        }
    }

    /**
     * Computes the SHA-256 hash of two concatenated byte arrays.
     */
    public static String sha256Hex(byte[] left, byte[] right) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            digest.update(left);
            digest.update(right);
            return HEX_FORMAT.formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 message digest algorithm not available", e);
        }
    }

    private static final String HMAC_SHA_256 = "HmacSHA256";

    /**
     * Computes the HMAC-SHA256 of UTF-8 string data using a secret key, returning lowercase 64-char hex string.
     */
    public static String hmacSha256Hex(byte[] secretKey, String data) {
        if (secretKey == null || secretKey.length == 0) {
            throw new IllegalArgumentException("secretKey must not be null or empty");
        }
        String inputData = data != null ? data : "";
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance(HMAC_SHA_256);
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(secretKey, HMAC_SHA_256);
            mac.init(keySpec);
            byte[] rawHmac = mac.doFinal(inputData.getBytes(StandardCharsets.UTF_8));
            return HEX_FORMAT.formatHex(rawHmac);
        } catch (NoSuchAlgorithmException | java.security.InvalidKeyException e) {
            throw new IllegalStateException("Failed to calculate HMAC-SHA256", e);
        }
    }

    /**
     * Computes the HMAC-SHA256 of UTF-8 string data using a UTF-8 secret key string.
     */
    public static String hmacSha256Hex(String secretKey, String data) {
        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalArgumentException("secretKey must not be null or empty");
        }
        return hmacSha256Hex(secretKey.getBytes(StandardCharsets.UTF_8), data);
    }
}
