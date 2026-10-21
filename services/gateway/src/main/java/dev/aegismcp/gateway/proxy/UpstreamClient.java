package dev.aegismcp.gateway.proxy;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;

import java.util.concurrent.CompletableFuture;

/**
 * Interface for non-blocking forwarding of JSON-RPC requests to upstream MCP servers.
 * Anchors: FEAT-001, C-001.
 */
public interface UpstreamClient {

    CompletableFuture<JsonRpcResponse> forward(SecurityContext context, JsonRpcRequest request);

    /**
     * Creates an in-memory mock client that echoes back success results.
     */
    static UpstreamClient mockEcho() {
        return (context, request) -> {
            ObjectNode result = JsonNodeFactory.instance.objectNode();
            result.put("status", "executed");
            result.put("method", request.method());
            if (request.isToolCall()) {
                result.put("tool", request.toolName());
            }
            if (request.params() != null) {
                result.set("receivedParams", request.params());
            }
            return CompletableFuture.completedFuture(JsonRpcResponse.success(request.id(), result));
        };
    }
}
