package dev.aegismcp.gateway.proxy;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * Builds the upstream client for the transport an operator configured. The composition root calls
 * this once; every transport applies the same request ceiling and failure mapping.
 *
 * <p>Anchors: FEAT-001, C-001.
 */
public final class UpstreamClientFactory {

    private UpstreamClientFactory() {
    }

    public static UpstreamClient create(URI endpoint, UpstreamTransport transport,
                                        Duration connectTimeout, Duration requestTimeout) {
        Objects.requireNonNull(endpoint, "endpoint must not be null");
        Objects.requireNonNull(transport, "transport must not be null");
        return switch (transport) {
            case HTTP -> new HttpUpstreamClient(endpoint, connectTimeout, requestTimeout);
            case SSE -> new SseUpstreamClient(endpoint, connectTimeout, requestTimeout);
            case WEBSOCKET -> new WebSocketUpstreamClient(endpoint, connectTimeout, requestTimeout);
        };
    }
}
