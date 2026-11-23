package dev.aegismcp.gateway.proxy;

/**
 * Signals that the configured upstream MCP server could not be reached, refused the call, or
 * answered something that is not a JSON-RPC 2.0 response. The proxy maps it to the C-001
 * {@code UPSTREAM_UNAVAILABLE} failure without exposing the underlying detail.
 * Anchors: FEAT-001, C-001.
 */
public class UpstreamException extends RuntimeException {

    public UpstreamException(String message) {
        super(message);
    }

    public UpstreamException(String message, Throwable cause) {
        super(message, cause);
    }
}
