package dev.aegismcp.gateway.proxy;

/**
 * The upstream transports FEAT-001 assigns to a configured MCP server. The gateway uses the same
 * three transports it exposes to agents, one per configured upstream.
 *
 * <p>Anchors: FEAT-001, C-001.
 */
public enum UpstreamTransport {
    /** One HTTPS request and response per call ({@code POST} of one JSON-RPC object). */
    HTTP,
    /** A long-lived event stream carrying the message endpoint and every response. */
    SSE,
    /** One WebSocket text frame per JSON-RPC message, correlated by {@code id}. */
    WEBSOCKET;

    /**
     * Resolves an operator-supplied transport name, inferring WebSocket from a {@code ws}/{@code wss}
     * endpoint and defaulting to HTTP otherwise.
     */
    public static UpstreamTransport from(String value) {
        if (value == null || value.isBlank()) {
            return HTTP;
        }
        String normalized = value.trim().toUpperCase(java.util.Locale.ROOT);
        return switch (normalized) {
            case "HTTP", "HTTPS", "REQUEST_RESPONSE" -> HTTP;
            case "SSE", "EVENT_STREAM" -> SSE;
            case "WS", "WSS", "WEBSOCKET" -> WEBSOCKET;
            default -> throw new IllegalArgumentException("Unknown upstream transport: " + value);
        };
    }
}
