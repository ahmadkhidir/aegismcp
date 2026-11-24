package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the canonical arguments digest sealed on an audit record.
 * Anchors: FEAT-007, C-013, schema.md#AuditBlock.
 */
class ArgumentDigestTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private JsonNode tree(String json) throws Exception {
        return mapper.readTree(json);
    }

    @Test
    @DisplayName("C-013: the digest ignores member order but keeps array order")
    void digestIsCanonical() throws Exception {
        String first = ArgumentDigest.of(tree("{\"b\":2,\"a\":{\"d\":4,\"c\":3}}"));
        String reordered = ArgumentDigest.of(tree("{\"a\":{\"c\":3,\"d\":4},\"b\":2}"));

        assertEquals(first, reordered, "Same arguments in a different field order must seal identically");
        assertTrueHex(first);
        assertNotEquals(first, ArgumentDigest.of(tree("{\"a\":{\"c\":3,\"d\":4},\"b\":3}")));
        assertNotEquals(ArgumentDigest.of(tree("{\"steps\":[1,2]}")),
                ArgumentDigest.of(tree("{\"steps\":[2,1]}")),
                "Array order is part of the value");
    }

    @Test
    @DisplayName("C-013: the digest never embeds or reveals the arguments")
    void digestDoesNotRevealArguments() throws Exception {
        String secret = "sk-live-canonical-secret";
        String digest = ArgumentDigest.of(tree("{\"token\":\"" + secret + "\"}"));

        assertTrueHex(digest);
        assertFalse(digest.contains(secret));
        assertEquals(HashUtils.sha256Hex("{\"token\":\"" + secret + "\"}"), digest,
                "The digest is the SHA-256 of the canonical JSON form");
    }

    @Test
    @DisplayName("C-013: absent arguments digest the empty object")
    void absentArgumentsUseEmptyObject() {
        assertEquals(HashUtils.sha256Hex("{}"), ArgumentDigest.of(null));
        assertEquals(HashUtils.sha256Hex("{}"), ArgumentDigest.of(treeOrNull("null")));
        assertEquals(ArgumentDigest.EMPTY_ARGUMENTS, ArgumentDigest.canonicalize(null));
    }

    private JsonNode treeOrNull(String json) {
        try {
            return mapper.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void assertTrueHex(String value) {
        assertEquals(64, value.length(), "SHA-256 hex digest must be 64 characters");
        assertTrue(value.matches("[0-9a-f]{64}"), "Digest must be lowercase hex: " + value);
    }
}
