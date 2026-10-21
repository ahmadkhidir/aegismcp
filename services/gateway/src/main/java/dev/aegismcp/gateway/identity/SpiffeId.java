package dev.aegismcp.gateway.identity;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parsed SPIFFE ID representation conforming to the SPIFFE ID specification.
 * Format: {@code spiffe://<trust-domain>/<path>}
 * Anchors: FEAT-009, NFR-020.
 */
public final class SpiffeId {

    public static final String SCHEME = "spiffe";
    private static final Pattern K8S_PATH_PATTERN = Pattern.compile("^/ns/([^/]+)/sa/([^/]+)(?:/.*)?$");

    private final String rawUri;
    private final String trustDomain;
    private final String path;
    private final String workloadId;

    private SpiffeId(String rawUri, String trustDomain, String path) {
        this.rawUri = rawUri;
        this.trustDomain = trustDomain;
        this.path = path;
        this.workloadId = path.startsWith("/") ? path.substring(1) : path;
    }

    /**
     * Parses a SPIFFE ID from string representation.
     *
     * @param uriString SPIFFE URI string (e.g. spiffe://cluster.local/ns/agents/sa/support-bot)
     * @return validated SpiffeId
     * @throws IllegalArgumentException if the URI is malformed or violates SPIFFE standard
     */
    public static SpiffeId parse(String uriString) {
        if (uriString == null || uriString.isBlank()) {
            throw new IllegalArgumentException("SPIFFE ID cannot be null or blank");
        }

        URI uri;
        try {
            uri = new URI(uriString);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Malformed SPIFFE URI: " + uriString, e);
        }

        if (!SCHEME.equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("SPIFFE ID scheme must be 'spiffe': " + uriString);
        }

        String host = uri.getAuthority();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("SPIFFE ID trust domain cannot be empty: " + uriString);
        }

        if (uri.getUserInfo() != null || uri.getPort() != -1) {
            throw new IllegalArgumentException("SPIFFE ID cannot contain userinfo or port: " + uriString);
        }

        String path = uri.getPath();
        if (path == null || path.isEmpty() || !path.startsWith("/")) {
            throw new IllegalArgumentException("SPIFFE ID path must start with '/': " + uriString);
        }

        if (uri.getQuery() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("SPIFFE ID cannot contain query or fragment: " + uriString);
        }

        String normalizedTrustDomain = host.toLowerCase();
        String normalizedUri = SCHEME + "://" + normalizedTrustDomain + path;
        return new SpiffeId(normalizedUri, normalizedTrustDomain, path);
    }

    /**
     * Checks if a string is a valid SPIFFE ID without throwing.
     */
    public static boolean isValid(String uriString) {
        try {
            parse(uriString);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public String trustDomain() {
        return trustDomain;
    }

    public String path() {
        return path;
    }

    /**
     * Returns the workload path without leading slash, e.g. "ns/agents/sa/support-bot".
     */
    public String workloadId() {
        return workloadId;
    }

    /**
     * If the workload path follows Kubernetes convention (/ns/{namespace}/sa/{serviceaccount}),
     * extracts the service account name.
     */
    public String kubernetesServiceAccount() {
        Matcher matcher = K8S_PATH_PATTERN.matcher(path);
        return matcher.matches() ? matcher.group(2) : null;
    }

    /**
     * If the workload path follows Kubernetes convention, extracts the namespace.
     */
    public String kubernetesNamespace() {
        Matcher matcher = K8S_PATH_PATTERN.matcher(path);
        return matcher.matches() ? matcher.group(1) : null;
    }

    public boolean matchesTrustDomain(String expectedDomain) {
        if (expectedDomain == null) {
            return false;
        }
        return trustDomain.equalsIgnoreCase(expectedDomain.trim());
    }

    @Override
    public String toString() {
        return rawUri;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SpiffeId spiffeId)) return false;
        return rawUri.equals(spiffeId.rawUri);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rawUri);
    }
}
