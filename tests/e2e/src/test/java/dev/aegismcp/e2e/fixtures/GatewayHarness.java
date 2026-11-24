package dev.aegismcp.e2e.fixtures;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

/**
 * One hermetic gateway deployment for a test: the packaged artifact in a child process, a local
 * identity provider, a mock MCP upstream, and a mock Slack webhook. The test reaches the artifact
 * only over HTTPS on the routes an agent or the console uses.
 *
 * <p>Every method that reads gateway state does so through the public HTTP surface. Nothing in this
 * class constructs a gateway handler, interceptor, cache, ledger, or pipeline.
 */
public final class GatewayHarness implements AutoCloseable {

    public static final ObjectMapper MAPPER = new ObjectMapper();
    public static final Duration HTTP_TIMEOUT = Duration.ofSeconds(20);

    public static final String ADMIN_SUBJECT = "admin@aegis.test";
    public static final String OPERATOR_SUBJECT = "operator@aegis.test";
    public static final String AUDITOR_SUBJECT = "auditor@aegis.test";
    public static final String VIEWER_SUBJECT = "viewer@aegis.test";

    private final Path workDirectory;
    private final TlsMaterial tls;
    private final TestIdentityProvider identityProvider;
    private final TestUpstreamServer upstream;
    private final TestSlackWebhook slackWebhook;
    private final GatewayProcess process;
    private final HttpClient client;
    private final HttpClient mtlsClient;
    private final GatewayOptions options;

    private GatewayHarness(
            Path workDirectory,
            TlsMaterial tls,
            TestIdentityProvider identityProvider,
            TestUpstreamServer upstream,
            TestSlackWebhook slackWebhook,
            GatewayProcess process,
            GatewayOptions options
    ) throws Exception {
        this.workDirectory = workDirectory;
        this.tls = tls;
        this.identityProvider = identityProvider;
        this.upstream = upstream;
        this.slackWebhook = slackWebhook;
        this.process = process;
        this.options = options;
        this.client = HttpClient.newBuilder()
                .sslContext(tls.anonymousClientContext())
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.mtlsClient = HttpClient.newBuilder()
                .sslContext(tls.mtlsClientContext())
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public static GatewayHarness start() throws Exception {
        return start(GatewayOptions.defaults());
    }

    public static GatewayHarness start(GatewayOptions options) throws Exception {
        Path workDirectory = Files.createTempDirectory("aegis-e2e-");
        TlsMaterial tls = TlsMaterial.generate(workDirectory.resolve("tls"));
        TestIdentityProvider identityProvider = new TestIdentityProvider();
        TestUpstreamServer upstream = new TestUpstreamServer();
        TestSlackWebhook slackWebhook = options.slackConfigured ? new TestSlackWebhook() : null;

        Path policyFile = workDirectory.resolve("policy.yaml");
        Files.writeString(policyFile, options.policyYaml);
        Map<String, String> environment = new LinkedHashMap<>();
        environment.put("AEGIS_GATEWAY_HOST", "127.0.0.1");
        environment.put("AEGIS_GATEWAY_PORT", "0");
        if (options.probeOnly) {
            // The only deployment that may omit the serving configuration; it reports
            // CONFIGURATION_INVALID and attaches no agent request path (C-023, NFR-027).
            environment.put("AEGIS_GATEWAY_PROBE_ONLY", "true");
        } else {
            if (options.tlsEnabled) {
                environment.put("AEGIS_TLS_KEYSTORE_PATH", tls.serverKeystore.toString());
                environment.put("AEGIS_TLS_KEYSTORE_PASSWORD", "changeit");
                environment.put("AEGIS_TLS_KEYSTORE_TYPE", "PKCS12");
                environment.put("AEGIS_TLS_TRUSTSTORE_PATH", tls.serverTruststore.toString());
                environment.put("AEGIS_TLS_TRUSTSTORE_PASSWORD", "changeit");
                environment.put("AEGIS_TLS_CLIENT_AUTH", "OPTIONAL");
            } else {
                // A plaintext serving listener is allowed only as an explicit operator choice.
                environment.put("AEGIS_TLS_ENABLED", "false");
            }
            if (options.upstreamConfigured) {
                environment.put("AEGIS_UPSTREAM_URL", upstream.url());
            }
            environment.put("AEGIS_UPSTREAM_TRANSPORT", "http");
            environment.put("AEGIS_UPSTREAM_CONNECT_TIMEOUT_MS", "2000");
            environment.put("AEGIS_UPSTREAM_REQUEST_TIMEOUT_MS", "5000");
            environment.put("AEGIS_OIDC_JWKS_URL", identityProvider.jwksUrl());
            environment.put("AEGIS_OIDC_ISSUER", identityProvider.issuer());
            environment.put("AEGIS_OIDC_AUDIENCE", identityProvider.audience());
            environment.put("AEGIS_OIDC_JWKS_CACHE_TTL_SECONDS", "30");
            environment.put("AEGIS_SPIFFE_TRUST_DOMAINS", "aegis.dev");
            environment.put("AEGIS_SPIFFE_TRUST_BUNDLE_PATH", tls.trustBundlePem.toString());
            if (options.policyConfigured) {
                environment.put("AEGIS_POLICY_FILE", policyFile.toString());
            }
            environment.put("AEGIS_APPROVAL_TTL_SECONDS", String.valueOf(options.approvalTtl.toSeconds()));
            environment.put("AEGIS_VELOCITY_THRESHOLD", String.valueOf(options.velocityThreshold));
            environment.put("AEGIS_VELOCITY_WINDOW_SECONDS", String.valueOf(options.velocityWindowSeconds));
            if (options.slackConfigured) {
                environment.put("AEGIS_SLACK_APPROVAL_WEBHOOK_URL", slackWebhook.url());
                environment.put("AEGIS_SLACK_SIGNING_SECRET", SlackFixtures.SIGNING_SECRET);
                environment.put("AEGIS_SLACK_OPERATORS", SlackFixtures.OPERATOR_MAP);
            }
        }

        GatewayProcess process;
        try {
            process = GatewayProcess.start(environment);
        } catch (Exception e) {
            identityProvider.close();
            upstream.close();
            if (slackWebhook != null) {
                slackWebhook.close();
            }
            // A startup failure must not leave the generated TLS material, policy, or identity
            // fixtures behind, even though no harness instance exists to close them.
            deleteRecursively(workDirectory);
            throw e;
        }

        return new GatewayHarness(workDirectory, tls, identityProvider, upstream, slackWebhook, process, options);
    }

    public URI baseUri() {
        boolean tls = options.tlsEnabled && !options.probeOnly;
        return URI.create((tls ? "https" : "http") + "://127.0.0.1:" + process.port());
    }

    public String url(String path) {
        return baseUri() + path;
    }

    public int port() {
        return process.port();
    }

    public TestUpstreamServer upstream() {
        return upstream;
    }

    public TestSlackWebhook slackWebhook() {
        return slackWebhook;
    }

    public TlsMaterial tls() {
        return tls;
    }

    public GatewayOptions options() {
        return options;
    }

    public Path workDirectory() {
        return workDirectory;
    }

    public HttpClient anonymousClient() {
        return client;
    }

    public HttpClient mtlsClient() {
        return mtlsClient;
    }

    public String token(String subject, String... roles) {
        return identityProvider.token(subject, roles);
    }

    public String token(String subject, List<String> roles, Map<String, Object> extraClaims) {
        return identityProvider.token(subject, roles, extraClaims);
    }

    public String tamperedToken(String subject) {
        return identityProvider.tamperedToken(subject);
    }

    public String expiredToken(String subject) {
        return identityProvider.expiredToken(subject);
    }

    public String adminToken() {
        return token(ADMIN_SUBJECT, "admin");
    }

    public String operatorToken() {
        return token(OPERATOR_SUBJECT, "operator");
    }

    public String auditorToken() {
        return token(AUDITOR_SUBJECT, "auditor");
    }

    public String viewerToken() {
        return token(VIEWER_SUBJECT, "viewer");
    }

    public String agentToken(String subject) {
        return token(subject);
    }

    /** A token whose bearer is syntactically a JWT but whose signature does not verify. */
    public String invalidToken() {
        return "not-a-valid-jwt";
    }

    public HttpResponse<String> get(String path, String token) throws Exception {
        return send(request(path, token).GET().build());
    }

    public HttpResponse<String> postJson(String path, String token, String body) throws Exception {
        return send(request(path, token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build());
    }

    public HttpResponse<String> putJson(String path, String token, String body) throws Exception {
        return send(request(path, token)
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build());
    }

    public HttpResponse<String> postRaw(String path, String contentType, String body, Map<String, String> headers)
            throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url(path)))
                .timeout(HTTP_TIMEOUT);
        if (contentType != null) {
            builder.header("Content-Type", contentType);
        }
        headers.forEach(builder::header);
        builder.POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        return send(builder.build());
    }

    public HttpResponse<String> exchange(HttpClient httpClient, HttpRequest request) throws Exception {
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    public HttpResponse<String> send(HttpRequest request) throws Exception {
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    public CompletableFuture<HttpResponse<String>> sendAsync(HttpRequest request) {
        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    public HttpRequest.Builder request(String path, String token) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url(path)))
                .timeout(HTTP_TIMEOUT)
                .header("Accept", "application/json");
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        return builder;
    }

    public static JsonNode json(HttpResponse<String> response) throws IOException {
        if (response.body() == null || response.body().isBlank()) {
            return MAPPER.nullNode();
        }
        return MAPPER.readTree(response.body());
    }

    /** Builds a JSON-RPC tools/call body. */
    public static String toolCall(Object id, String tool, String argumentsJson) {
        String renderedId = id instanceof String ? "\"" + id + "\"" : String.valueOf(id);
        return "{\"jsonrpc\":\"2.0\",\"id\":" + renderedId
                + ",\"method\":\"tools/call\",\"params\":{\"name\":\"" + tool
                + "\",\"arguments\":" + argumentsJson + "}}";
    }

    /** Opens the live event stream and returns a reader that yields parsed SSE events. */
    public SseStream openStream(String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url("/api/v1/stream/traffic")))
                .header("Accept", "text/event-stream")
                .GET();
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        HttpResponse<InputStream> response = client.send(builder.build(),
                HttpResponse.BodyHandlers.ofInputStream());
        return new SseStream(response);
    }

    /** A suspended tool call and the ticket the gateway created for it. */
    public record PendingCall(String ticketId, CompletableFuture<HttpResponse<String>> response) {
    }

    /**
     * Issues an approval-bound tool call and waits for the gateway to expose its ticket. The Slack
     * notification payload carries the unredacted ticket token, so the harness reads the real
     * identifier from that out-of-band message; the pending queue is consulted only to confirm the
     * ticket exists. The caller decides or rejects it, or lets the configured TTL expire.
     */
    public PendingCall createPendingCall(String agentId, String tool, String argumentsJson) throws Exception {
        CompletableFuture<HttpResponse<String>> response = sendAsync(request("/mcp/v1/rpc", agentToken(agentId))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(toolCall("pending-" + System.nanoTime(), tool, argumentsJson)))
                .build());

        String ticketId = awaitSlackTicket(agentId);
        if (ticketId == null) {
            ticketId = awaitPendingTicket(agentId, response);
        }
        return new PendingCall(ticketId, response);
    }

    private String awaitSlackTicket(String agentId) throws InterruptedException {
        if (slackWebhook == null) {
            return null;
        }
        java.util.regex.Pattern token = java.util.regex.Pattern.compile("appr_[A-Z2-7]{26}");
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (System.nanoTime() < deadline) {
            for (String payload : slackWebhook.payloads()) {
                if (!payload.contains(agentId)) {
                    continue;
                }
                java.util.regex.Matcher matcher = token.matcher(payload);
                if (matcher.find()) {
                    return matcher.group();
                }
            }
            Thread.sleep(100);
        }
        return null;
    }

    private String awaitPendingTicket(
            String agentId,
            CompletableFuture<HttpResponse<String>> response
    ) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (System.nanoTime() < deadline) {
            HttpResponse<String> pending = get("/api/v1/approvals/pending", operatorToken());
            if (pending.statusCode() == 200) {
                JsonNode tickets = json(pending).path("tickets");
                for (JsonNode ticket : tickets) {
                    if (agentId.equals(ticket.path("agentId").asText())) {
                        return ticket.path("id").asText();
                    }
                }
            }
            Thread.sleep(100);
        }
        if (response.isDone()) {
            throw new IllegalStateException("The approval-bound call completed without a ticket: "
                    + response.get().statusCode() + " " + response.get().body());
        }
        throw new IllegalStateException("The gateway did not expose a pending approval ticket");
    }

    @Override
    public void close() {
        try {
            process.close();
        } finally {
            if (identityProvider != null) {
                identityProvider.close();
            }
            if (upstream != null) {
                upstream.close();
            }
            if (slackWebhook != null) {
                slackWebhook.close();
            }
            deleteRecursively(workDirectory);
        }
    }

    private static void deleteRecursively(Path directory) {
        if (directory == null || !Files.exists(directory)) {
            return;
        }
        try (var paths = Files.walk(directory)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // Best-effort cleanup.
                }
            });
        } catch (IOException ignored) {
            // Best-effort cleanup.
        }
    }

    /** One parsed server-sent event. A comment frame is reported with name {@code comment}. */
    public record SseEvent(String event, String id, String data) {
    }

    /** Reads the live event stream in a background thread and offers events to the test. */
    public static final class SseStream implements AutoCloseable {

        private final BlockingQueue<SseEvent> events = new LinkedBlockingQueue<>();
        private final HttpResponse<InputStream> response;
        private final Thread reader;

        private SseStream(HttpResponse<InputStream> response) {
            this.response = response;
            this.reader = new Thread(this::read, "aegis-sse-reader");
            this.reader.setDaemon(true);
            this.reader.start();
        }

        public int statusCode() {
            return response.statusCode();
        }

        public String header(String name) {
            return response.headers().firstValue(name).orElse(null);
        }

        public SseEvent awaitEvent(String name, Duration timeout) throws InterruptedException {
            return awaitEvent(name, event -> true, timeout);
        }

        public SseEvent awaitEvent(String name, Predicate<SseEvent> predicate, Duration timeout)
                throws InterruptedException {
            long deadline = System.nanoTime() + timeout.toNanos();
            while (System.nanoTime() < deadline) {
                SseEvent event = events.poll(100, TimeUnit.MILLISECONDS);
                if (event != null && name.equals(event.event()) && predicate.test(event)) {
                    return event;
                }
            }
            return null;
        }

        private void read() {
            try (BufferedReader bufferedReader = new BufferedReader(
                    new InputStreamReader(response.body(), StandardCharsets.UTF_8))) {
                String eventName = null;
                String id = null;
                StringBuilder data = new StringBuilder();
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    if (line.isEmpty()) {
                        if (eventName != null || data.length() > 0) {
                            events.offer(new SseEvent(eventName != null ? eventName : "message",
                                    id, data.toString()));
                        }
                        eventName = null;
                        id = null;
                        data.setLength(0);
                        continue;
                    }
                    if (line.startsWith(":")) {
                        events.offer(new SseEvent("comment", null, line));
                        continue;
                    }
                    int colon = line.indexOf(':');
                    String field = colon >= 0 ? line.substring(0, colon) : line;
                    String value = colon >= 0 ? line.substring(colon + 1) : "";
                    if (value.startsWith(" ")) {
                        value = value.substring(1);
                    }
                    switch (field) {
                        case "event" -> eventName = value;
                        case "id" -> id = value;
                        case "retry" -> events.offer(new SseEvent("retry", null, value));
                        case "data" -> {
                            if (data.length() > 0) {
                                data.append('\n');
                            }
                            data.append(value);
                        }
                        default -> {
                            // retry directives and unknown fields are not part of the assertions
                        }
                    }
                }
            } catch (IOException ignored) {
                // The stream ends when the gateway or the test closes it.
            }
        }

        @Override
        public void close() {
            try {
                response.body().close();
            } catch (IOException ignored) {
                // Already closed.
            }
            reader.interrupt();
        }
    }
}
