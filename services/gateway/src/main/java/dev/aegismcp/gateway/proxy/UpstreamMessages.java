package dev.aegismcp.gateway.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.gateway.codec.JsonRpcId;

/**
 * Shared limits and correlation helpers for the upstream transports.
 *
 * <p>C-001 fixes the output ceiling at 20 MB: a transport stops reading at that bound rather than
 * accumulating an unbounded upstream body in memory. Responses are matched to the request that
 * produced them by the JSON-RPC {@code id}, including its JSON type, so a numeric {@code 1} never
 * matches a string {@code "1"}.
 *
 * <p>Anchors: FEAT-001, C-001, NFR-002.
 */
final class UpstreamMessages {

    /** C-001 output ceiling for one upstream response. */
    static final int MAX_RESPONSE_BYTES = 20 * 1024 * 1024;

    private UpstreamMessages() {
    }

    /**
     * Correlation key for a JSON-RPC request id, or {@code null} when the message carries no id and
     * therefore cannot receive a response (a notification).
     */
    static String idKey(JsonRpcId id) {
        if (id == null || id instanceof JsonRpcId.NullId) {
            return null;
        }
        if (id instanceof JsonRpcId.StringId stringId) {
            return "s:" + stringId.stringValue();
        }
        return "n:" + ((JsonRpcId.NumberId) id).numberValue();
    }

    /** True when the response belongs to the request, comparing both id type and value. */
    static boolean matches(JsonRpcId requestId, JsonRpcId responseId) {
        String requestKey = idKey(requestId);
        return requestKey != null && requestKey.equals(idKey(responseId));
    }

    /** Reads the contract's {@code data.code} machine code from an upstream error, if present. */
    static String machineCode(JsonNode data) {
        if (data == null || !data.isObject()) {
            return null;
        }
        JsonNode code = data.get("code");
        return code != null && code.isTextual() ? code.asText() : null;
    }
}
