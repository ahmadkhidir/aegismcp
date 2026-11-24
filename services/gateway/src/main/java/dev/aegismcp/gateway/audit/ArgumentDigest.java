package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Computes the SHA-256 digest of a tool call's canonicalized arguments, the value sealed on an
 * audit record as {@code argumentsHash} (C-013, schema.md#AuditBlock).
 *
 * <p>The canonical form sorts every object's members by name and drops insignificant whitespace, so
 * two requests that carry the same arguments in a different field order produce the same digest,
 * while the arguments themselves never leave the process. Arrays keep their order because order is
 * part of the value.
 *
 * <p>Anchors: FEAT-007, C-013, schema.md#AuditBlock.
 */
public final class ArgumentDigest {

    /** The canonical form of an absent arguments object. */
    public static final String EMPTY_ARGUMENTS = "{}";

    private ArgumentDigest() {
    }

    /**
     * Returns the digest of the supplied arguments, or the digest of {@code {}} when the call
     * carried none. A digest is one-way, so a secret inside an argument is never exposed.
     */
    public static String of(JsonNode arguments) {
        return HashUtils.sha256Hex(canonicalize(arguments));
    }

    /** Renders the canonical JSON form the digest is taken over. */
    public static String canonicalize(JsonNode arguments) {
        if (arguments == null || arguments.isNull() || arguments.isMissingNode()) {
            return EMPTY_ARGUMENTS;
        }
        return canonicalizeNode(arguments).toString();
    }

    private static JsonNode canonicalizeNode(JsonNode node) {
        if (node == null || node.isNull()) {
            return NullNode.getInstance();
        }
        if (node.isObject()) {
            ObjectNode sorted = JsonNodeFactory.instance.objectNode();
            List<String> names = new ArrayList<>();
            node.fieldNames().forEachRemaining(names::add);
            Collections.sort(names);
            for (String name : names) {
                sorted.set(name, canonicalizeNode(node.get(name)));
            }
            return sorted;
        }
        if (node.isArray()) {
            ArrayNode ordered = JsonNodeFactory.instance.arrayNode();
            for (JsonNode element : node) {
                ordered.add(canonicalizeNode(element));
            }
            return ordered;
        }
        return node;
    }
}
