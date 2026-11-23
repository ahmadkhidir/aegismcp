package dev.aegismcp.gateway.approval;

import java.security.SecureRandom;

/**
 * Runtime-generated values for the approval test fixtures.
 *
 * <p>Nothing here is a credential: every value is random per test JVM, so a committed literal can
 * never be mistaken for a real Slack signing secret, approval token, or provider key, and no static
 * scanner has a fixed string to flag. The tests that need a deterministic comparison hold the
 * generated value in a constant and assert against that same value.
 *
 * <p>Anchors: FEAT-006, NFR-023.
 */
final class TestCredentials {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    private TestCredentials() {
    }

    /** Lower-case hex of {@code bytes} random bytes. */
    static String hex(int bytes) {
        byte[] data = new byte[bytes];
        RANDOM.nextBytes(data);
        StringBuilder encoded = new StringBuilder(bytes * 2);
        for (byte value : data) {
            encoded.append(HEX[(value >> 4) & 0x0F]).append(HEX[value & 0x0F]);
        }
        return encoded.toString();
    }

    /** A signing secret shaped like a Slack workspace secret: 48 hex characters. */
    static String signingSecret() {
        return hex(24);
    }

    /** A ticket token shaped as FEAT-006 fixes: {@code appr_} plus 26 base32 characters. */
    static String ticketId() {
        return "appr_" + base32(26);
    }

    /**
     * A provider key shaped like an OpenAI secret so the DLP scanner detects it, assembled from a
     * prefix and random characters: no contiguous credential-shaped literal exists in the source.
     */
    static String providerKey() {
        return "sk-" + hex(18);
    }

    private static String base32(int length) {
        StringBuilder encoded = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            encoded.append(BASE32[RANDOM.nextInt(BASE32.length)]);
        }
        return encoded.toString();
    }
}
