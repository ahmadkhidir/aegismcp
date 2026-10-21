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
}
