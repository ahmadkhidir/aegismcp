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
     * Test double only: the shipped composition root never selects it (FEAT-001).
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

    /**
     * Fail-closed client used when no upstream endpoint is configured: every forwarded call fails
     * as {@code UPSTREAM_UNAVAILABLE} instead of inventing a success body (C-001, NFR-027).
     */
    static UpstreamClient unconfigured() {
        return (context, request) -> CompletableFuture.failedFuture(
                new UpstreamException("No upstream MCP server is configured"));
    }
}
