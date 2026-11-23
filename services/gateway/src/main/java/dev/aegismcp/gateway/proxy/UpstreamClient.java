package dev.aegismcp.gateway.proxy;

import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;

import java.util.concurrent.CompletableFuture;

/**
 * Boundary for non-blocking forwarding of JSON-RPC requests to an upstream MCP server over one of
 * the transports FEAT-001 assigns an upstream: HTTPS request/response, Server-Sent Events, or
 * WebSocket.
 *
 * <p>Implementations match each response to its request by JSON-RPC {@code id}, never buffer more
 * than the C-001 20 MB output ceiling, and fail with {@link UpstreamException} so the proxy answers
 * the contract's {@code UPSTREAM_UNAVAILABLE} row instead of inventing a result.
 *
 * <p>Anchors: FEAT-001, C-001, NFR-001.
 */
public interface UpstreamClient {

    CompletableFuture<JsonRpcResponse> forward(SecurityContext context, JsonRpcRequest request);

    /** Releases the upstream connection, reader thread, and pending calls. Idempotent. */
    default void close() {
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
