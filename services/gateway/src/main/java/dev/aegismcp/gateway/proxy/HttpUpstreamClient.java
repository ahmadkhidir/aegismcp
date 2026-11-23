package dev.aegismcp.gateway.proxy;

import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Forwards one JSON-RPC request per HTTPS call to the configured upstream MCP server and returns
 * the response with its identifier intact.
 *
 * <p>The exchange runs asynchronously on the JDK HTTP client, so the Netty event loop only frames
 * and schedules; no upstream read, DNS lookup, or TLS handshake happens on it (NFR-001, NFR-002).
 * The agent's credential is never forwarded: the upstream sees only the tool call. A connection
 * failure, timeout, non-2xx answer, mismatched id, or unparseable body becomes an
 * {@link UpstreamException}, which the proxy reports as C-001 {@code UPSTREAM_UNAVAILABLE}.
 *
 * <p>The body is streamed, not buffered blindly: a plain JSON answer stops at the C-001 20 MB
 * ceiling, and a {@code text/event-stream} answer (the Streamable HTTP form of the SSE transport)
 * is read frame by frame until the frame carrying this request's id arrives.
 *
 * <p>Anchors: FEAT-001, C-001, NFR-001, NFR-002.
 */
public final class HttpUpstreamClient implements UpstreamClient {

    /**
     * Shared reader pool: reading a response body blocks, so it runs on a virtual thread rather than
     * on the HTTP client's selector thread or the Netty event loop.
     */
    private static final class WorkerHolder {
        private static final ExecutorService WORKER =
                Executors.newVirtualThreadPerTaskExecutor();
    }

    private final URI endpoint;
    private final Duration requestTimeout;
    private final HttpClient httpClient;
    private final JsonRpcCodec codec;

    public HttpUpstreamClient(URI endpoint, Duration connectTimeout, Duration requestTimeout) {
        this(endpoint, connectTimeout, requestTimeout, JsonRpcCodec.getInstance(),
                HttpClient.newBuilder()
                        .connectTimeout(Objects.requireNonNull(connectTimeout, "connectTimeout must not be null"))
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build());
    }

    HttpUpstreamClient(URI endpoint, Duration connectTimeout, Duration requestTimeout,
                       JsonRpcCodec codec, HttpClient httpClient) {
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout must not be null");
        this.codec = Objects.requireNonNull(codec, "codec must not be null");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
    }

    @Override
    public CompletableFuture<JsonRpcResponse> forward(SecurityContext context, JsonRpcRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        byte[] payload = codec.encode(request);

        HttpRequest upstreamRequest;
        try {
            upstreamRequest = HttpRequest.newBuilder(endpoint)
                    .timeout(requestTimeout)
                    .header("Content-Type", "application/json")
                    // Streamable HTTP may answer either shape on the same endpoint.
                    .header("Accept", "application/json, text/event-stream")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(payload))
                    .build();
        } catch (IllegalArgumentException e) {
            return CompletableFuture.failedFuture(new UpstreamException("Invalid upstream endpoint", e));
        }

        return httpClient.sendAsync(upstreamRequest, HttpResponse.BodyHandlers.ofInputStream())
                .thenCompose(response -> {
                    if (response.statusCode() < 200 || response.statusCode() >= 300) {
                        closeQuietly(response.body());
                        return CompletableFuture.failedFuture(new UpstreamException(
                                "Upstream MCP server answered HTTP " + response.statusCode()));
                    }
                    return CompletableFuture.supplyAsync(() -> readResponse(response, request), WorkerHolder.WORKER);
                })
                .handle((response, failure) -> {
                    if (failure != null) {
                        throw upstreamFailure(failure);
                    }
                    return response;
                });
    }

    @Override
    public void close() {
        // One request per exchange: there is no persistent connection to release. The shared
        // virtual-thread reader pool is process-wide and daemon-backed.
    }

    public URI getEndpoint() {
        return endpoint;
    }

    private JsonRpcResponse readResponse(HttpResponse<InputStream> response, JsonRpcRequest request) {
        String contentType = response.headers().firstValue("Content-Type").orElse("");
        try (InputStream body = response.body()) {
            JsonRpcResponse rpcResponse = contentType.toLowerCase().contains("text/event-stream")
                    ? readEventStream(body, request)
                    : readJsonBody(body, request);
            if (!UpstreamMessages.matches(request.id(), rpcResponse.id())) {
                throw new UpstreamException("Upstream MCP server answered a response for another request");
            }
            return rpcResponse;
        } catch (IOException e) {
            throw new UpstreamException("Upstream MCP server did not answer", e);
        }
    }

    private JsonRpcResponse readJsonBody(InputStream body, JsonRpcRequest request) throws IOException {
        byte[] payload = readAtMost(body);
        try {
            return codec.decodeResponse(payload);
        } catch (RuntimeException e) {
            throw new UpstreamException("Upstream MCP server answered an invalid JSON-RPC body", e);
        }
    }

    /**
     * Reads a Streamable HTTP event stream until the response that belongs to {@code request}
     * arrives. Frames for other requests or server notifications are discarded. A single frame is
     * bounded by the C-001 ceiling, so a hostile peer cannot grow the buffer without limit.
     */
    private JsonRpcResponse readEventStream(InputStream body, JsonRpcRequest request) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(body, StandardCharsets.UTF_8));
        String event = null;
        StringBuilder data = null;
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.isEmpty()) {
                if (data != null && !data.isEmpty()) {
                    JsonRpcResponse matched = responseFromEvent(event, data.toString(), request);
                    if (matched != null) {
                        return matched;
                    }
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
                        throw new UpstreamException(
                                "Upstream MCP server exceeded the 20 MB output ceiling");
                    }
                }
                default -> {
                    // id/retry are event metadata, not part of the JSON-RPC envelope.
                }
            }
        }
        throw new UpstreamException("Upstream MCP server closed the response stream without answering");
    }

    private JsonRpcResponse responseFromEvent(String event, String data, JsonRpcRequest request) {
        if (event != null && !event.equals("message")) {
            return null;
        }
        JsonRpcResponse response;
        try {
            response = codec.decodeResponse(data.getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            return null; // a malformed frame is discarded, never delivered to an agent
        }
        return UpstreamMessages.matches(request.id(), response.id()) ? response : null;
    }

    /** Reads until EOF, refusing to buffer more than the C-001 output ceiling. */
    private static byte[] readAtMost(InputStream body) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = body.read(chunk)) != -1) {
            if (out.size() + read > UpstreamMessages.MAX_RESPONSE_BYTES) {
                throw new UpstreamException("Upstream MCP server exceeded the 20 MB output ceiling");
            }
            out.write(chunk, 0, read);
        }
        return out.toByteArray();
    }

    private static UpstreamException upstreamFailure(Throwable failure) {
        Throwable cause = unwrap(failure);
        if (cause instanceof UpstreamException upstream) {
            return upstream;
        }
        return new UpstreamException("Upstream MCP server did not answer", cause);
    }

    private static Throwable unwrap(Throwable failure) {
        Throwable current = failure;
        while (current instanceof CompletionException && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static void closeQuietly(InputStream body) {
        try {
            body.close();
        } catch (IOException ignored) {
            // Nothing to recover: the exchange is already a failure.
        }
    }
}
