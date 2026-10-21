package dev.aegismcp.gateway.codec;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * Model representing a JSON-RPC 2.0 Response.
 * Anchors: FEAT-001, C-001.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record JsonRpcResponse(
        @JsonProperty(value = "jsonrpc", required = true) String jsonrpc,
        @JsonProperty("id") JsonRpcId id,
        @JsonProperty("result") JsonNode result,
        @JsonProperty("error") JsonRpcError error
) implements JsonRpcMessage {

    public JsonRpcResponse {
        if (jsonrpc == null || jsonrpc.isBlank()) {
            jsonrpc = JSONRPC_VERSION;
        }
    }

    public static JsonRpcResponse success(JsonRpcId id, JsonNode result) {
        return new JsonRpcResponse(JSONRPC_VERSION, id, result, null);
    }

    public static JsonRpcResponse error(JsonRpcId id, JsonRpcError error) {
        return new JsonRpcResponse(JSONRPC_VERSION, id, null, error);
    }

    public boolean isSuccess() {
        return error == null;
    }

    public boolean isError() {
        return error != null;
    }
}
