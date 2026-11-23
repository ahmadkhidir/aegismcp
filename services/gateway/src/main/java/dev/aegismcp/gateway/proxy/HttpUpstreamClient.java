package dev.aegismcp.gateway.proxy;

import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * Forwards one JSON-RPC request per HTTPS call to the configured upstream MCP server and returns
 * the response with its identifier intact.
 *
 * <p>The exchange runs asynchronously on the JDK HTTP client, so the Netty event loop only frames
 * and schedules; no upstream read, DNS lookup, or TLS handshake happens on it (NFR-001, NFR-002).
 * The agent's credential is never forwarded: the upstream sees only the tool call. A connection
 * failure, timeout, non-2xx answer, or unparseable body becomes an {@link UpstreamException}, which
 * the proxy reports as C-001 {@code UPSTREAM_UNAVAILABLE}.
 *
 * <p>Anchors: FEAT-001, C-001, NFR-001.
 */
public final class HttpUpstreamClient implements UpstreamClient {

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
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(payload))
                    .build();
        } catch (IllegalArgumentException e) {
            return CompletableFuture.failedFuture(new UpstreamException("Invalid upstream endpoint", e));
        }

        return httpClient.sendAsync(upstreamRequest, HttpResponse.BodyHandlers.ofByteArray())
                .handle((response, failure) -> {
                    if (failure != null) {
                        Throwable cause = failure instanceof CompletionException && failure.getCause() != null
                                ? failure.getCause()
                                : failure;
                        throw new UpstreamException("Upstream MCP server did not answer", cause);
                    }
                    if (response.statusCode() < 200 || response.statusCode() >= 300) {
                        throw new UpstreamException(
                                "Upstream MCP server answered HTTP " + response.statusCode());
                    }
                    try {
                        return codec.decodeResponse(response.body());
                    } catch (RuntimeException e) {
                        throw new UpstreamException("Upstream MCP server answered an invalid JSON-RPC body", e);
                    }
                });
    }

    public URI getEndpoint() {
        return endpoint;
    }
}
