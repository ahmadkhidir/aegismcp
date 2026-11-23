package dev.aegismcp.gateway.identity;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Fetches the identity provider's JSON Web Key Set over HTTPS for {@link JwksKeyResolver}.
 *
 * <p>The fetch runs on the virtual thread that is validating a token, never on a Netty event loop.
 * A non-2xx answer or an unreadable body fails the fetch so {@link JwksKeyResolver} can decide
 * between a cached key inside its grace period and a rejected token; it never fabricates a key.
 *
 * <p>Anchors: FEAT-009, NFR-020, NFR-027.
 */
public final class HttpJwksSupplier implements Supplier<String> {

    private final HttpClient httpClient;
    private final URI jwksUri;
    private final Duration requestTimeout;

    public HttpJwksSupplier(URI jwksUri, Duration connectTimeout, Duration requestTimeout) {
        this.jwksUri = Objects.requireNonNull(jwksUri, "jwksUri must not be null");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout must not be null");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Objects.requireNonNull(connectTimeout, "connectTimeout must not be null"))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public String get() {
        HttpRequest request = HttpRequest.newBuilder(jwksUri)
                .timeout(requestTimeout)
                .header("Accept", "application/json")
                .GET()
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new AuthenticationException(
                        "Identity provider JWKS endpoint answered HTTP " + response.statusCode());
            }
            return response.body();
        } catch (IOException e) {
            throw new AuthenticationException("Identity provider JWKS endpoint unreachable", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthenticationException("Identity provider JWKS fetch interrupted", e);
        }
    }
}
