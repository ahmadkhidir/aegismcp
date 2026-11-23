package dev.aegismcp.gateway.proxy;

import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;

/**
 * Upstream MCP over WebSocket.
 *
 * <p>One text frame carries exactly one complete JSON-RPC message in either direction. Requests may
 * be pipelined, so several calls can be in flight at once; each response is matched to its request
 * by JSON-RPC {@code id} and an unmatched frame is discarded. A frame larger than the C-001 20 MB
 * ceiling, a protocol error, or a closed socket fails every in-flight call with
 * {@link UpstreamException}; the next call reconnects.
 *
 * <p>The socket is driven asynchronously by the JDK WebSocket client and the gateway only completes
 * futures from listener callbacks, so nothing here blocks a Netty event-loop thread (NFR-001).
 *
 * <p>Anchors: FEAT-001, C-001, NFR-001.
 */
public final class WebSocketUpstreamClient implements UpstreamClient {

    private static final Logger logger = LoggerFactory.getLogger(WebSocketUpstreamClient.class);

    private final URI endpoint;
    private final Duration connectTimeout;
    private final Duration requestTimeout;
    private final HttpClient httpClient;
    private final JsonRpcCodec codec;

    private final Object connectionLock = new Object();
    private volatile Connection connection;
    private volatile boolean closed;

    public WebSocketUpstreamClient(URI endpoint, Duration connectTimeout, Duration requestTimeout) {
        this(endpoint, connectTimeout, requestTimeout, JsonRpcCodec.getInstance(),
                HttpClient.newBuilder()
                        .connectTimeout(Objects.requireNonNull(connectTimeout, "connectTimeout must not be null"))
                        .build());
    }

    WebSocketUpstreamClient(URI endpoint, Duration connectTimeout, Duration requestTimeout,
                            JsonRpcCodec codec, HttpClient httpClient) {
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
        this.connectTimeout = Objects.requireNonNull(connectTimeout, "connectTimeout must not be null");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout must not be null");
        this.codec = Objects.requireNonNull(codec, "codec must not be null");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
    }

    @Override
    public CompletableFuture<JsonRpcResponse> forward(SecurityContext context, JsonRpcRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        String key = UpstreamMessages.idKey(request.id());
        if (key == null) {
            return CompletableFuture.failedFuture(
                    new UpstreamException("A JSON-RPC notification cannot receive an upstream response"));
        }
        if (closed) {
            return CompletableFuture.failedFuture(new UpstreamException("Upstream client is closed"));
        }

        Connection conn = connection();
        CompletableFuture<JsonRpcResponse> response = new CompletableFuture<>();
        byte[] payload = codec.encode(request);
        return conn.socket.thenCompose(webSocket -> {
                    synchronized (conn.lock) {
                        if (conn.terminated) {
                            return CompletableFuture.<JsonRpcResponse>failedFuture(
                                    new UpstreamException("Upstream WebSocket is closed"));
                        }
                        if (conn.pending.putIfAbsent(key, response) != null) {
                            return CompletableFuture.<JsonRpcResponse>failedFuture(
                                    new UpstreamException("A call with this id is already in flight"));
                        }
                    }
                    send(conn, webSocket, new String(payload, StandardCharsets.UTF_8))
                            .whenComplete((ignored, failure) -> {
                                if (failure != null && removePending(conn, key, response)) {
                                    response.completeExceptionally(unwrap(failure));
                                }
                            });
                    return response;
                })
                .orTimeout(requestTimeout.toMillis(), TimeUnit.MILLISECONDS)
                .whenComplete((result, failure) -> removePending(conn, key, response));
    }

    @Override
    public void close() {
        closed = true;
        Connection current = connection;
        if (current != null) {
            terminate(current, new UpstreamException("Upstream client is closed"));
        }
    }

    public URI getEndpoint() {
        return endpoint;
    }

    private Connection connection() {
        synchronized (connectionLock) {
            if (connection != null && !connection.terminated) {
                return connection;
            }
            Connection created = new Connection();
            connection = created;
            httpClient.newWebSocketBuilder()
                    .connectTimeout(connectTimeout)
                    .buildAsync(endpoint, new Listener(created))
                    .whenComplete((webSocket, failure) -> {
                        if (failure != null) {
                            terminate(created, new UpstreamException(
                                    "Upstream WebSocket connection failed", unwrap(failure)));
                            return;
                        }
                        created.webSocket = webSocket;
                        created.socket.complete(webSocket);
                    });
            return created;
        }
    }

    /**
     * Serializes sends on one socket: the JDK client requires at most one outstanding send per
     * connection, while callers may forward concurrently.
     */
    private CompletableFuture<Void> send(Connection conn, WebSocket webSocket, String text) {
        synchronized (conn.lock) {
            CompletableFuture<Void> next = conn.sendChain
                    .handle((ignored, failure) -> null)
                    .thenCompose(ignored -> webSocket.sendText(text, true))
                    .thenApply(sent -> (Void) null);
            conn.sendChain = next.handle((ignored, failure) -> null);
            return next;
        }
    }

    private void handleText(Connection conn, String text) {
        JsonRpcResponse response;
        try {
            response = codec.decodeResponse(text.getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            logger.debug("Discarding an unparseable upstream WebSocket frame");
            return;
        }

        String key = UpstreamMessages.idKey(response.id());
        if (key == null) {
            return; // server notification or an id-less message matches no call
        }
        CompletableFuture<JsonRpcResponse> pending;
        synchronized (conn.lock) {
            pending = conn.pending.remove(key);
        }
        if (pending == null) {
            logger.debug("Discarding an upstream WebSocket response that matches no in-flight call");
            return;
        }
        pending.complete(response);
    }

    private boolean removePending(Connection conn, String key,
                                  CompletableFuture<JsonRpcResponse> response) {
        synchronized (conn.lock) {
            return conn.pending.remove(key, response);
        }
    }

    private void terminate(Connection conn, UpstreamException failure) {
        WebSocket webSocket;
        synchronized (conn.lock) {
            if (conn.terminated) {
                return;
            }
            conn.terminated = true;
            webSocket = conn.webSocket;
            conn.socket.completeExceptionally(failure);
            for (CompletableFuture<JsonRpcResponse> pending : conn.pending.values()) {
                pending.completeExceptionally(failure);
            }
            conn.pending.clear();
        }
        if (webSocket != null) {
            try {
                webSocket.abort();
            } catch (RuntimeException ignored) {
                // The socket is already failing; nothing further to release.
            }
        }
        synchronized (connectionLock) {
            if (connection == conn) {
                connection = null;
            }
        }
    }

    private static Throwable unwrap(Throwable failure) {
        Throwable current = failure;
        while (current instanceof CompletionException && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private final class Listener implements WebSocket.Listener {
        private final Connection conn;
        private final StringBuilder partial = new StringBuilder();

        private Listener(Connection conn) {
            this.conn = conn;
        }

        @Override
        public void onOpen(WebSocket webSocket) {
            webSocket.request(1);
        }

        @Override
        public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
            partial.append(data);
            if (partial.length() > UpstreamMessages.MAX_RESPONSE_BYTES) {
                terminate(conn, new UpstreamException("Upstream MCP server exceeded the 20 MB output ceiling"));
                webSocket.abort();
                return null;
            }
            if (last) {
                String message = partial.toString();
                partial.setLength(0);
                handleText(conn, message);
            }
            webSocket.request(1);
            return null;
        }

        @Override
        public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
            terminate(conn, new UpstreamException("Upstream WebSocket closed"));
            return null;
        }

        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            terminate(conn, new UpstreamException("Upstream WebSocket failed", error));
        }
    }

    private static final class Connection {
        private final Object lock = new Object();
        private final CompletableFuture<WebSocket> socket = new CompletableFuture<>();
        private final Map<String, CompletableFuture<JsonRpcResponse>> pending = new HashMap<>();
        private volatile CompletableFuture<Void> sendChain = CompletableFuture.completedFuture(null);
        private volatile WebSocket webSocket;
        private volatile boolean terminated;
    }
}
