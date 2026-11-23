package dev.aegismcp.gateway.proxy;

import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

/**
 * Upstream MCP over the Server-Sent Events transport.
 *
 * <p>The gateway holds one event stream to the configured endpoint. The stream's first
 * {@code endpoint} event names the message URL; each call is posted there, and the response arrives
 * on the stream as an {@code event: message} frame. Responses are correlated by JSON-RPC {@code id},
 * so calls may be in flight at once, and a frame that matches no in-flight call is discarded rather
 * than delivered to another session (FEAT-001).
 *
 * <p>The stream is read on a virtual thread and only complete frames are decoded, so no event body
 * grows past the C-001 20 MB ceiling. A stream that closes, fails, or answers a non-200 status
 * fails every in-flight call with {@link UpstreamException}, which the proxy maps to the contract's
 * {@code UPSTREAM_UNAVAILABLE} row; the next call opens a fresh stream.
 *
 * <p>Anchors: FEAT-001, C-001, NFR-001.
 */
public final class SseUpstreamClient implements UpstreamClient {

    private static final Logger logger = LoggerFactory.getLogger(SseUpstreamClient.class);
    private static final String ENDPOINT_EVENT = "endpoint";
    private static final String MESSAGE_EVENT = "message";

    private final URI streamEndpoint;
    private final Duration requestTimeout;
    private final HttpClient httpClient;
    private final JsonRpcCodec codec;

    private final Object connectionLock = new Object();
    private volatile Connection connection;
    private volatile boolean closed;

    public SseUpstreamClient(URI streamEndpoint, Duration connectTimeout, Duration requestTimeout) {
        this(streamEndpoint, requestTimeout, JsonRpcCodec.getInstance(),
                HttpClient.newBuilder()
                        .connectTimeout(Objects.requireNonNull(connectTimeout, "connectTimeout must not be null"))
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build());
    }

    SseUpstreamClient(URI streamEndpoint, Duration requestTimeout, JsonRpcCodec codec, HttpClient httpClient) {
        this.streamEndpoint = Objects.requireNonNull(streamEndpoint, "streamEndpoint must not be null");
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
        return conn.ready.thenCompose(messageEndpoint -> {
                    synchronized (conn.lock) {
                        if (conn.terminated) {
                            return CompletableFuture.<JsonRpcResponse>failedFuture(
                                    new UpstreamException("Upstream SSE session is closed"));
                        }
                        if (conn.pending.containsKey(key)) {
                            return CompletableFuture.<JsonRpcResponse>failedFuture(
                                    new UpstreamException("A call with this id is already in flight"));
                        }
                        conn.pending.put(key, response);
                    }
                    post(messageEndpoint, codec.encode(request)).whenComplete((ignored, failure) -> {
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

    public URI getStreamEndpoint() {
        return streamEndpoint;
    }

    private Connection connection() {
        synchronized (connectionLock) {
            if (connection != null && !connection.terminated) {
                return connection;
            }
            Connection created = new Connection();
            connection = created;
            Thread.ofVirtual().name("aegis-upstream-sse").start(() -> readStream(created));
            return created;
        }
    }

    private CompletableFuture<Void> post(URI messageEndpoint, byte[] payload) {
        HttpRequest request;
        try {
            request = HttpRequest.newBuilder(messageEndpoint)
                    .timeout(requestTimeout)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(payload))
                    .build();
        } catch (IllegalArgumentException e) {
            return CompletableFuture.failedFuture(new UpstreamException("Invalid upstream message URL", e));
        }
        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                .thenAccept(response -> {
                    int status = response.statusCode();
                    if (status < 200 || status >= 300) {
                        throw new CompletionException(new UpstreamException(
                                "Upstream MCP server answered HTTP " + status));
                    }
                });
    }

    private void readStream(Connection conn) {
        UpstreamException failure = new UpstreamException("Upstream SSE stream closed");
        try {
            HttpRequest request = HttpRequest.newBuilder(streamEndpoint)
                    .header("Accept", "text/event-stream")
                    .header("Cache-Control", "no-cache")
                    .GET()
                    .build();
            HttpResponse<InputStream> response = httpClient
                    .sendAsync(request, HttpResponse.BodyHandlers.ofInputStream())
                    .orTimeout(requestTimeout.toMillis(), TimeUnit.MILLISECONDS)
                    .get();
            if (response.statusCode() != 200) {
                closeQuietly(response.body());
                throw new UpstreamException("Upstream SSE endpoint answered HTTP " + response.statusCode());
            }
            synchronized (conn.lock) {
                conn.body = response.body();
            }
            readEvents(conn, new BufferedReader(new InputStreamReader(response.body(), StandardCharsets.UTF_8)));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            failure = new UpstreamException("Upstream SSE reader was interrupted", e);
        } catch (java.util.concurrent.ExecutionException e) {
            failure = new UpstreamException("Upstream SSE endpoint did not answer", e.getCause());
        } catch (UpstreamException e) {
            failure = e;
        } catch (IOException e) {
            failure = new UpstreamException("Upstream SSE stream failed", e);
        } catch (RuntimeException e) {
            failure = new UpstreamException("Upstream SSE reader failed", e);
        } finally {
            terminate(conn, failure);
        }
    }

    private void readEvents(Connection conn, BufferedReader reader) throws IOException {
        String event = null;
        StringBuilder data = null;
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.isEmpty()) {
                if (data != null && !data.isEmpty()) {
                    dispatch(conn, event, data.toString());
                }
                event = null;
                data = null;
                continue;
            }
            if (line.startsWith(":")) {
                continue; // keepalive comment
            }
            int colon = line.indexOf(':');
            String field = colon >= 0 ? line.substring(0, colon) : line;
            String value = colon >= 0 ? line.substring(colon + 1) : "";
            if (value.startsWith(" ")) {
                value = value.substring(1);
            }
            switch (field) {
                case "event" -> event = value;
                case "data" -> {
                    if (data == null) {
                        data = new StringBuilder();
                    } else {
                        data.append('\n');
                    }
                    data.append(value);
                    if (data.length() > UpstreamMessages.MAX_RESPONSE_BYTES) {
                        throw new UpstreamException("Upstream MCP server exceeded the 20 MB output ceiling");
                    }
                }
                default -> {
                    // id/retry are stream metadata, not part of the JSON-RPC envelope.
                }
            }
        }
    }

    private void dispatch(Connection conn, String event, String data) {
        if (ENDPOINT_EVENT.equals(event)) {
            URI messageEndpoint;
            try {
                messageEndpoint = streamEndpoint.resolve(data.trim());
            } catch (IllegalArgumentException e) {
                throw new UpstreamException("Upstream SSE endpoint named an invalid message URL", e);
            }
            conn.ready.complete(messageEndpoint);
            return;
        }
        if (event != null && !MESSAGE_EVENT.equals(event)) {
            return;
        }

        JsonRpcResponse response;
        try {
            response = codec.decodeResponse(data.getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            logger.debug("Discarding an unparseable upstream SSE frame");
            return;
        }

        String key = UpstreamMessages.idKey(response.id());
        if (key == null) {
            return; // a notification or a response without an id matches nothing
        }
        CompletableFuture<JsonRpcResponse> pending;
        synchronized (conn.lock) {
            pending = conn.pending.remove(key);
        }
        if (pending == null) {
            logger.debug("Discarding an upstream SSE response that matches no in-flight call");
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
        InputStream body;
        synchronized (conn.lock) {
            if (conn.terminated) {
                return;
            }
            conn.terminated = true;
            body = conn.body;
            conn.ready.completeExceptionally(failure);
            for (CompletableFuture<JsonRpcResponse> pending : conn.pending.values()) {
                pending.completeExceptionally(failure);
            }
            conn.pending.clear();
        }
        closeQuietly(body);
        synchronized (connectionLock) {
            if (connection == conn) {
                connection = null;
            }
        }
    }

    private static void closeQuietly(InputStream body) {
        if (body == null) {
            return;
        }
        try {
            body.close();
        } catch (IOException ignored) {
            // Nothing to recover: the stream is already failing.
        }
    }

    private static Throwable unwrap(Throwable failure) {
        Throwable current = failure;
        while (current instanceof CompletionException && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static final class Connection {
        private final Object lock = new Object();
        private final CompletableFuture<URI> ready = new CompletableFuture<>();
        private final Map<String, CompletableFuture<JsonRpcResponse>> pending = new HashMap<>();
        private volatile InputStream body;
        private volatile boolean terminated;
    }
}
