package dev.aegismcp.gateway.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import dev.aegismcp.gateway.approval.ApprovalNotificationConfig;
import dev.aegismcp.gateway.proxy.UpstreamTransport;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable operator configuration for the gateway, resolved from environment variables and an
 * optional YAML document at startup.
 *
 * <p>Environment variables win over the YAML document, which wins over the built-in default. A
 * value that is present but malformed, or a setting whose companion setting is absent, raises
 * {@link ConfigurationException} naming the key instead of silently falling back to a development
 * value. The two deployable paths are {@link #load()} (environment and optional YAML) and
 * {@link #local(String, int)} (the in-process default used by the probe and unit-test seam: no
 * upstream, no identity provider, no policy document, every agent request fails closed).
 *
 * <p>A gateway that is not explicitly probe-only must carry every setting an agent-facing proxy
 * needs — a TLS listener (or an explicit {@code AEGIS_TLS_ENABLED=false}), an upstream, an identity
 * provider, and a policy document. When one is absent, startup fails with one error naming every
 * missing key; no development default is substituted (NFR-010, NFR-027). Probe-only mode
 * ({@value #PROBE_ONLY_ENV}) is the only way to boot without them, and it serves the health and
 * readiness probes only.
 *
 * <p>Anchors: FEAT-001, FEAT-009, NFR-010, NFR-021, NFR-027.
 */
public record GatewayConfiguration(
        String host,
        int port,
        boolean probeOnly,
        Tls tls,
        Upstream upstream,
        Identity identity,
        Path policyDocument,
        ApprovalNotificationConfig approvals,
        Duration approvalTtl,
        int maxContentLength,
        int velocityThreshold,
        Duration velocityWindow
) {

    /** Name of the YAML configuration document environment variable. */
    public static final String CONFIG_FILE_ENV = "AEGIS_GATEWAY_CONFIG";

    /**
     * Explicit opt-in to a probe-only node: the listener serves {@code GET /health} and
     * {@code GET /ready}, reports {@code CONFIGURATION_INVALID}, and refuses every agent request.
     * It is the only deployment that may omit the serving configuration.
     */
    public static final String PROBE_ONLY_ENV = "AEGIS_GATEWAY_PROBE_ONLY";

    public static final String DEFAULT_HOST = "0.0.0.0";
    public static final int DEFAULT_PORT = 8443;
    public static final int DEFAULT_MAX_CONTENT_LENGTH = 16 * 1024 * 1024;
    public static final Duration DEFAULT_APPROVAL_TTL = Duration.ofSeconds(300);
    public static final int DEFAULT_VELOCITY_THRESHOLD = 100;
    public static final Duration DEFAULT_VELOCITY_WINDOW = Duration.ofSeconds(10);

    public GatewayConfiguration {
        Objects.requireNonNull(host, "host must not be null");
        if (port < 0 || port > 65535) {
            throw new ConfigurationException("AEGIS_GATEWAY_PORT must be between 0 and 65535, got " + port);
        }
        Objects.requireNonNull(tls, "tls must not be null");
        Objects.requireNonNull(upstream, "upstream must not be null");
        Objects.requireNonNull(identity, "identity must not be null");
        Objects.requireNonNull(approvals, "approvals must not be null");
        Objects.requireNonNull(approvalTtl, "approvalTtl must not be null");
        if (maxContentLength <= 0) {
            throw new ConfigurationException("limits.maxContentLength must be positive, got " + maxContentLength);
        }
        if (velocityThreshold <= 0) {
            throw new ConfigurationException("limits.velocityThreshold must be positive, got " + velocityThreshold);
        }
        Objects.requireNonNull(velocityWindow, "velocityWindow must not be null");

        if (!probeOnly) {
            List<String> missing = missingServingSettings(tls, upstream, identity, policyDocument);
            if (!missing.isEmpty()) {
                throw new ConfigurationException(
                        "Gateway serving configuration is incomplete; missing: "
                                + String.join(", ", missing)
                                + ". Set " + PROBE_ONLY_ENV + "=true to boot a probe-only node.");
            }
        }
    }

    /** Names every setting an agent-facing proxy needs that the supplied configuration lacks. */
    private static List<String> missingServingSettings(
            Tls tls, Upstream upstream, Identity identity, Path policyDocument) {
        List<String> missing = new ArrayList<>();
        if (!tls.servesTraffic()) {
            missing.add("AEGIS_TLS_KEYSTORE_PATH");
        }
        if (!upstream.configured()) {
            missing.add("AEGIS_UPSTREAM_URL");
        }
        if (!identity.configured()) {
            missing.add("AEGIS_OIDC_JWKS_URL/AEGIS_SPIFFE_TRUST_DOMAINS");
        }
        if (policyDocument == null) {
            missing.add("AEGIS_POLICY_FILE");
        }
        return missing;
    }

    /**
     * TLS listener configuration; {@code enabled} is only true when a keystore was supplied.
     * {@code explicitlyDisabled} records an operator's {@code AEGIS_TLS_ENABLED=false}, which is
     * the only plaintext listener a serving node accepts; an absent TLS setting is not a default.
     */
    public record Tls(
            boolean enabled,
            boolean explicitlyDisabled,
            Path keystorePath,
            String keystorePassword,
            String keystoreType,
            String keyPassword,
            Path truststorePath,
            String truststorePassword,
            ClientAuth clientAuth
    ) {
        public Tls {
            Objects.requireNonNull(clientAuth, "clientAuth must not be null");
            if (enabled) {
                if (keystorePath == null) {
                    throw new ConfigurationException("AEGIS_TLS_KEYSTORE_PATH is required when TLS is enabled");
                }
                requireReadable(keystorePath, "AEGIS_TLS_KEYSTORE_PATH");
                if (keystoreType == null || keystoreType.isBlank()) {
                    throw new ConfigurationException("AEGIS_TLS_KEYSTORE_TYPE must not be blank when TLS is enabled");
                }
            }
            if (clientAuth == ClientAuth.REQUIRE && truststorePath == null) {
                throw new ConfigurationException(
                        "AEGIS_TLS_TRUSTSTORE_PATH is required when AEGIS_TLS_CLIENT_AUTH is REQUIRE");
            }
            if (truststorePath != null) {
                requireReadable(truststorePath, "AEGIS_TLS_TRUSTSTORE_PATH");
            }
        }

        public static Tls disabled() {
            return new Tls(false, false, null, null, "PKCS12", null, null, null, ClientAuth.NONE);
        }

        /** True when the listener is configured to serve: TLS enabled, or plaintext explicitly chosen. */
        public boolean servesTraffic() {
            return enabled || explicitlyDisabled;
        }
    }

    /** Mutual-TLS peer requirement. */
    public enum ClientAuth {
        NONE,
        OPTIONAL,
        REQUIRE
    }

    /** Upstream MCP server endpoint, transport, and timeouts; a null {@code url} means no upstream is wired. */
    public record Upstream(URI url, UpstreamTransport transport, Duration connectTimeout, Duration requestTimeout) {
        public Upstream {
            if (connectTimeout == null || connectTimeout.isNegative() || connectTimeout.isZero()) {
                throw new ConfigurationException("AEGIS_UPSTREAM_CONNECT_TIMEOUT_MS must be positive");
            }
            if (requestTimeout == null || requestTimeout.isNegative() || requestTimeout.isZero()) {
                throw new ConfigurationException("AEGIS_UPSTREAM_REQUEST_TIMEOUT_MS must be positive");
            }
            if (transport == null) {
                throw new ConfigurationException("AEGIS_UPSTREAM_TRANSPORT must name a transport");
            }
            if (url != null) {
                String scheme = url.getScheme() != null ? url.getScheme().toLowerCase(Locale.ROOT) : "";
                boolean webSocketScheme = scheme.equals("ws") || scheme.equals("wss");
                if (transport == UpstreamTransport.WEBSOCKET && !webSocketScheme) {
                    throw new ConfigurationException(
                            "AEGIS_UPSTREAM_URL must be a ws or wss URL when AEGIS_UPSTREAM_TRANSPORT is websocket, got "
                                    + url);
                }
                if (transport != UpstreamTransport.WEBSOCKET
                        && !scheme.equals("http") && !scheme.equals("https")) {
                    throw new ConfigurationException(
                            "AEGIS_UPSTREAM_URL must be an http or https URL for the "
                                    + transport.name().toLowerCase(Locale.ROOT) + " transport, got " + url);
                }
            }
        }

        public static Upstream none() {
            return new Upstream(null, UpstreamTransport.HTTP, Duration.ofSeconds(2), Duration.ofSeconds(30));
        }

        public boolean configured() {
            return url != null;
        }
    }

    /** Identity-provider material used to verify agent credentials at the edge (FEAT-009). */
    public record Identity(
            String oidcIssuer,
            String oidcAudience,
            URI jwksUrl,
            Duration jwksCacheTtl,
            Duration jwksGracePeriod,
            Duration jwksConnectTimeout,
            Duration jwksRequestTimeout,
            Set<String> spiffeTrustDomains,
            Path spiffeTrustBundle
    ) {
        public Identity {
            spiffeTrustDomains = spiffeTrustDomains != null ? Set.copyOf(spiffeTrustDomains) : Set.of();
            if (jwksUrl != null) {
                String scheme = jwksUrl.getScheme() != null ? jwksUrl.getScheme().toLowerCase(Locale.ROOT) : "";
                if (!scheme.equals("http") && !scheme.equals("https")) {
                    throw new ConfigurationException(
                            "AEGIS_OIDC_JWKS_URL must be an http or https URL, got " + jwksUrl);
                }
                if (oidcIssuer == null || oidcIssuer.isBlank()) {
                    throw new ConfigurationException(
                            "AEGIS_OIDC_ISSUER is required when AEGIS_OIDC_JWKS_URL is set");
                }
            }
            if (jwksCacheTtl == null || jwksCacheTtl.isNegative()) {
                throw new ConfigurationException("AEGIS_OIDC_JWKS_CACHE_TTL_SECONDS must not be negative");
            }
            if (jwksGracePeriod == null || jwksGracePeriod.isNegative()) {
                throw new ConfigurationException("AEGIS_OIDC_JWKS_GRACE_SECONDS must not be negative");
            }
            if (spiffeTrustBundle != null) {
                requireReadable(spiffeTrustBundle, "AEGIS_SPIFFE_TRUST_BUNDLE_PATH");
            }
        }

        public static Identity none() {
            return new Identity(null, null, null, Duration.ofHours(1), Duration.ofHours(24),
                    Duration.ofSeconds(2), Duration.ofSeconds(5), Set.of(), null);
        }

        public boolean oidcConfigured() {
            return jwksUrl != null;
        }

        public boolean spiffeConfigured() {
            return !spiffeTrustDomains.isEmpty() || spiffeTrustBundle != null;
        }

        public boolean configured() {
            return oidcConfigured() || spiffeConfigured();
        }
    }

    /**
     * Configuration for an in-process probe-only gateway: health and readiness only, every agent
     * call fails closed. The probe and unit-test seams use it instead of relying on an absent
     * serving configuration.
     */
    public static GatewayConfiguration local(String host, int port) {
        return new GatewayConfiguration(
                host,
                port,
                true,
                Tls.disabled(),
                Upstream.none(),
                Identity.none(),
                null,
                ApprovalNotificationConfig.none(),
                DEFAULT_APPROVAL_TTL,
                DEFAULT_MAX_CONTENT_LENGTH,
                DEFAULT_VELOCITY_THRESHOLD,
                DEFAULT_VELOCITY_WINDOW
        );
    }

    /**
     * Reads the environment, then the YAML document named by {@value #CONFIG_FILE_ENV} when present,
     * and validates the result.
     */
    public static GatewayConfiguration load() {
        return load(System.getenv());
    }

    /** Test seam for {@link #load()}: resolves the same rules against a supplied environment. */
    public static GatewayConfiguration load(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment must not be null");
        String configFile = environment.get(CONFIG_FILE_ENV);
        JsonNode document = JsonNodeFactoryHolder.MISSING;
        if (configFile != null && !configFile.isBlank()) {
            document = readYaml(Path.of(configFile));
        }
        // Approval destinations are part of the gateway configuration and are validated in the
        // same startup pass, so a half-configured channel fails here rather than inside the
        // approval manager after the listener is already accepting connections (FEAT-006).
        ApprovalNotificationConfig approvals = ApprovalNotificationConfig.load(environment);
        return resolve(new Lookup(environment, document), approvals);
    }

    /** True when the configuration supplies what an agent-facing proxy needs to serve traffic. */
    public boolean rpcConfigured() {
        return !probeOnly && tls.servesTraffic() && upstream.configured()
                && identity.configured() && policyDocument != null;
    }

    /** Names every serving setting that is absent, in the order a startup error reports them. */
    public List<String> missingServingSettings() {
        if (probeOnly) {
            return List.of();
        }
        return missingServingSettings(tls, upstream, identity, policyDocument);
    }

    private static GatewayConfiguration resolve(
            Lookup lookup, ApprovalNotificationConfig approvals) {
        String host = lookup.text("AEGIS_GATEWAY_HOST", "gateway.host", DEFAULT_HOST);
        int port = lookup.integer("AEGIS_GATEWAY_PORT", "gateway.port", DEFAULT_PORT);
        boolean probeOnly = lookup.bool(PROBE_ONLY_ENV, "gateway.probeOnly", false);

        Path keystore = lookup.path("AEGIS_TLS_KEYSTORE_PATH", "tls.keystore");
        String tlsEnabledSetting = lookup.text("AEGIS_TLS_ENABLED", "tls.enabled", null);
        boolean tlsExplicitlyDisabled = "false".equalsIgnoreCase(tlsEnabledSetting);
        boolean tlsEnabled = lookup.bool("AEGIS_TLS_ENABLED", "tls.enabled", keystore != null);
        Path truststore = lookup.path("AEGIS_TLS_TRUSTSTORE_PATH", "tls.truststore");
        ClientAuth clientAuth = parseClientAuth(lookup.text("AEGIS_TLS_CLIENT_AUTH", "tls.clientAuth",
                truststore != null ? "OPTIONAL" : "NONE"));
        Tls tls = new Tls(
                tlsEnabled,
                tlsExplicitlyDisabled,
                keystore,
                lookup.text("AEGIS_TLS_KEYSTORE_PASSWORD", "tls.keystorePassword", null),
                lookup.text("AEGIS_TLS_KEYSTORE_TYPE", "tls.keystoreType", "PKCS12"),
                lookup.text("AEGIS_TLS_KEY_PASSWORD", "tls.keyPassword", null),
                truststore,
                lookup.text("AEGIS_TLS_TRUSTSTORE_PASSWORD", "tls.truststorePassword", null),
                clientAuth
        );

        String upstreamUrl = lookup.text("AEGIS_UPSTREAM_URL", "upstream.url", null);
        UpstreamTransport upstreamTransport = resolveUpstreamTransport(
                lookup.text("AEGIS_UPSTREAM_TRANSPORT", "upstream.transport", null), upstreamUrl);
        Upstream upstream = new Upstream(
                upstreamUrl != null ? uri("AEGIS_UPSTREAM_URL", upstreamUrl) : null,
                upstreamTransport,
                Duration.ofMillis(lookup.integer("AEGIS_UPSTREAM_CONNECT_TIMEOUT_MS",
                        "upstream.connectTimeoutMs", 2000)),
                Duration.ofMillis(lookup.integer("AEGIS_UPSTREAM_REQUEST_TIMEOUT_MS",
                        "upstream.requestTimeoutMs", 30_000))
        );

        String jwksUrl = lookup.text("AEGIS_OIDC_JWKS_URL", "identity.oidc.jwksUrl", null);
        Identity identity = new Identity(
                lookup.text("AEGIS_OIDC_ISSUER", "identity.oidc.issuer", null),
                lookup.text("AEGIS_OIDC_AUDIENCE", "identity.oidc.audience", null),
                jwksUrl != null ? uri("AEGIS_OIDC_JWKS_URL", jwksUrl) : null,
                Duration.ofSeconds(lookup.integer("AEGIS_OIDC_JWKS_CACHE_TTL_SECONDS",
                        "identity.oidc.jwksCacheTtlSeconds", 3600)),
                Duration.ofSeconds(lookup.integer("AEGIS_OIDC_JWKS_GRACE_SECONDS",
                        "identity.oidc.jwksGraceSeconds", 86_400)),
                Duration.ofMillis(lookup.integer("AEGIS_OIDC_JWKS_CONNECT_TIMEOUT_MS",
                        "identity.oidc.jwksConnectTimeoutMs", 2000)),
                Duration.ofMillis(lookup.integer("AEGIS_OIDC_JWKS_REQUEST_TIMEOUT_MS",
                        "identity.oidc.jwksRequestTimeoutMs", 5000)),
                lookup.csv("AEGIS_SPIFFE_TRUST_DOMAINS", "identity.spiffe.trustDomains"),
                lookup.path("AEGIS_SPIFFE_TRUST_BUNDLE_PATH", "identity.spiffe.trustBundle")
        );

        Path policyDocument = lookup.path("AEGIS_POLICY_FILE", "policy.document");
        if (policyDocument != null) {
            requireReadable(policyDocument, "AEGIS_POLICY_FILE");
        }

        Duration approvalTtl = Duration.ofSeconds(lookup.integer("AEGIS_APPROVAL_TTL_SECONDS",
                "approval.ttlSeconds", (int) DEFAULT_APPROVAL_TTL.toSeconds()));

        return new GatewayConfiguration(
                host,
                port,
                probeOnly,
                tls,
                upstream,
                identity,
                policyDocument,
                approvals,
                approvalTtl,
                lookup.integer("AEGIS_MAX_CONTENT_LENGTH", "limits.maxContentLength", DEFAULT_MAX_CONTENT_LENGTH),
                lookup.integer("AEGIS_VELOCITY_THRESHOLD", "limits.velocityThreshold", DEFAULT_VELOCITY_THRESHOLD),
                Duration.ofSeconds(lookup.integer("AEGIS_VELOCITY_WINDOW_SECONDS",
                        "limits.velocityWindowSeconds", (int) DEFAULT_VELOCITY_WINDOW.toSeconds()))
        );
    }

    /**
     * Resolves the configured upstream transport. An explicit setting must name one of the three
     * transports FEAT-001 assigns an upstream; otherwise a {@code ws}/{@code wss} endpoint infers
     * WebSocket and every other endpoint defaults to one request per HTTPS call.
     */
    private static UpstreamTransport resolveUpstreamTransport(String configured, String url) {
        if (configured != null) {
            try {
                return UpstreamTransport.from(configured);
            } catch (IllegalArgumentException e) {
                throw new ConfigurationException(
                        "AEGIS_UPSTREAM_TRANSPORT must be http, sse, or websocket; got '" + configured + "'");
            }
        }
        if (url != null) {
            String scheme = url.toLowerCase(Locale.ROOT);
            if (scheme.startsWith("ws://") || scheme.startsWith("wss://")) {
                return UpstreamTransport.WEBSOCKET;
            }
        }
        return UpstreamTransport.HTTP;
    }

    private static ClientAuth parseClientAuth(String value) {
        try {
            return ClientAuth.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException(
                    "AEGIS_TLS_CLIENT_AUTH must be one of NONE, OPTIONAL, REQUIRE; got '" + value + "'");
        }
    }

    private static URI uri(String key, String value) {
        try {
            return new URI(value.trim());
        } catch (URISyntaxException e) {
            throw new ConfigurationException(key + " is not a valid URI: " + e.getMessage(), e);
        }
    }

    private static void requireReadable(Path path, String key) {
        if (!Files.isReadable(path)) {
            throw new ConfigurationException(key + " is not readable: " + path);
        }
    }

    private static JsonNode readYaml(Path path) {
        if (!Files.isReadable(path)) {
            throw new ConfigurationException(CONFIG_FILE_ENV + " is not readable: " + path);
        }
        try {
            return new ObjectMapper(new YAMLFactory()).readTree(path.toFile());
        } catch (IOException e) {
            throw new ConfigurationException(CONFIG_FILE_ENV + " is not valid YAML: " + path, e);
        }
    }

    /** Environment-then-YAML lookup shared by every setting. */
    private static final class Lookup {
        private final Map<String, String> environment;
        private final JsonNode document;

        private Lookup(Map<String, String> environment, JsonNode document) {
            this.environment = environment;
            this.document = document;
        }

        private String text(String envKey, String yamlPath, String fallback) {
            String fromEnv = environment.get(envKey);
            if (fromEnv != null && !fromEnv.isBlank()) {
                return fromEnv.trim();
            }
            JsonNode node = node(yamlPath);
            if (node != null && !node.isNull() && !node.isMissingNode()) {
                String value = node.asText();
                if (value != null && !value.isBlank()) {
                    return value.trim();
                }
            }
            return fallback;
        }

        private int integer(String envKey, String yamlPath, int fallback) {
            String value = text(envKey, yamlPath, null);
            if (value == null) {
                return fallback;
            }
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                throw new ConfigurationException(envKey + " must be an integer, got '" + value + "'");
            }
        }

        private boolean bool(String envKey, String yamlPath, boolean fallback) {
            String value = text(envKey, yamlPath, null);
            if (value == null) {
                return fallback;
            }
            if ("true".equalsIgnoreCase(value)) {
                return true;
            }
            if ("false".equalsIgnoreCase(value)) {
                return false;
            }
            throw new ConfigurationException(envKey + " must be true or false, got '" + value + "'");
        }

        private Path path(String envKey, String yamlPath) {
            String value = text(envKey, yamlPath, null);
            return value != null ? Path.of(value) : null;
        }

        private Set<String> csv(String envKey, String yamlPath) {
            JsonNode node = node(yamlPath);
            Set<String> values = new LinkedHashSet<>();
            if (node != null && node.isArray()) {
                for (JsonNode item : node) {
                    if (item != null && !item.asText().isBlank()) {
                        values.add(item.asText().trim());
                    }
                }
            } else {
                String fromEnv = environment.get(envKey);
                String raw = fromEnv != null && !fromEnv.isBlank() ? fromEnv : (node != null ? node.asText(null) : null);
                if (raw != null) {
                    for (String part : raw.split(",")) {
                        if (!part.isBlank()) {
                            values.add(part.trim());
                        }
                    }
                }
            }
            return Set.copyOf(values);
        }

        private JsonNode node(String dottedPath) {
            JsonNode current = document;
            for (String segment : dottedPath.split("\\.")) {
                if (current == null || !current.isObject()) {
                    return null;
                }
                current = current.get(segment);
            }
            return current;
        }
    }

    /** Holds a missing JSON node without making every caller null-check the root. */
    private static final class JsonNodeFactoryHolder {
        private static final JsonNode MISSING =
                com.fasterxml.jackson.databind.node.MissingNode.getInstance();
    }
}
