package dev.aegismcp.gateway.codec;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Objects;

/**
 * Model representing a JSON-RPC 2.0 Request or Notification.
 * Anchors: FEAT-001, C-001.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record JsonRpcRequest(
        @JsonProperty(value = "jsonrpc", required = true) String jsonrpc,
        @JsonProperty("id") JsonRpcId id,
        @JsonProperty(value = "method", required = true) String method,
        @JsonProperty("params") JsonNode params
) implements JsonRpcMessage {

    public static final String METHOD_TOOLS_CALL = "tools/call";
    public static final String METHOD_TOOLS_LIST = "tools/list";
    public static final String METHOD_INITIALIZE = "initialize";
    public static final String METHOD_PING = "ping";

    public JsonRpcRequest {
        if (jsonrpc == null || jsonrpc.isBlank()) {
            jsonrpc = JSONRPC_VERSION;
        }
    }

    public JsonRpcRequest(JsonRpcId id, String method, JsonNode params) {
        this(JSONRPC_VERSION, id, method, params);
    }

    /**
     * Checks if this request is a Model Context Protocol tool call (tools/call).
     */
    public boolean isToolCall() {
        return METHOD_TOOLS_CALL.equals(method);
    }

    /**
     * Extracts the target tool name if this request is an MCP tool invocation.
     */
    public String toolName() {
        if (!isToolCall() || params == null || !params.hasNonNull("name")) {
            return null;
        }
        return params.get("name").asText();
    }

    /**
     * Extracts tool arguments if present in the params object.
     */
    public JsonNode toolArguments() {
        if (!isToolCall() || params == null || !params.has("arguments")) {
            return null;
        }
        return params.get("arguments");
    }

    /**
     * Identifies if this message is a JSON-RPC notification (no id).
     */
    public boolean isNotification() {
        return id == null || id instanceof JsonRpcId.NullId;
    }
}
