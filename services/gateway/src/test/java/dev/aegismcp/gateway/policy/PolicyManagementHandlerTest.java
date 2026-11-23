package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests verifying the policy management endpoints conforming to contracts C-005, C-006,
 * C-017, and C-018. Authentication is delegated to a test double that models the verified-token
 * role outcome.
 *
 * <p>Anchors: FEAT-002, C-005, C-006, C-017, C-018.
 */
class PolicyManagementHandlerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private PolicyCache cache;
    private PolicyManagementHandler handler;
    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        cache = new PolicyCache();
        handler = new PolicyManagementHandler(cache, PolicyCompiler.getInstance(), mapper,
                (method, bearerToken) -> {
                    if (bearerToken == null || bearerToken.isBlank()) {
                        return PolicyManagementHandler.PolicyAuthorizer.AuthResult
                                .unauthenticated("Missing authentication credentials");
                    }
                    boolean write = HttpMethod.POST.equals(method) || HttpMethod.PUT.equals(method);
                    if (write && bearerToken.contains("readonly")) {
                        return PolicyManagementHandler.PolicyAuthorizer.AuthResult
                                .forbidden("Insufficient permissions for this operation");
                    }
                    return PolicyManagementHandler.PolicyAuthorizer.AuthResult.allow();
                });
        channel = new EmbeddedChannel(handler);
    }

    private FullHttpResponse sendRequest(HttpMethod method, String uri, String payload, String authHeader) {
        ByteBuf content = (payload != null)
                ? Unpooled.wrappedBuffer(payload.getBytes(StandardCharsets.UTF_8))
                : Unpooled.EMPTY_BUFFER;

        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                method,
                uri,
                content
        );
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        request.headers().set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        if (authHeader != null) {
            request.headers().set(HttpHeaderNames.AUTHORIZATION, authHeader);
        }

        channel.writeInbound(request);
        return channel.readOutbound();
    }

    private JsonNode parseBody(FullHttpResponse response) throws Exception {
        byte[] bytes = new byte[response.content().readableBytes()];
        response.content().readBytes(bytes);
        return mapper.readTree(bytes);
    }

    private FullHttpResponse publish(String rawYaml, String name, String version) throws Exception {
        String payload = mapper.writeValueAsString(new PolicyDto.CreatePolicyRequest(
                name, version, rawYaml, "commit-hash-789"));
        return sendRequest(HttpMethod.POST, "/api/v1/policies", payload, "Bearer admin-token");
    }

    @Test
    @DisplayName("C-005: GET /api/v1/policies without a token returns 401")
    void testGetPoliciesUnauthorized() throws Exception {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/policies", null, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
        assertTrue(parseBody(response).has("error"));
    }

    @Test
    @DisplayName("C-005: GET /api/v1/policies returns the policy catalogue")
    void testGetPoliciesSuccess() throws Exception {
        String yaml = """
                id: pol_active_1
                name: Active Policy
                version: 1.0.0
                rules: []
                """;
        cache.putPolicy(SecurityPolicy.of("pol_active_1", "Active Policy", "1.0.0", yaml, "git-sha-1"));

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/policies", null, "Bearer admin-token-123");
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode body = parseBody(response);
        JsonNode policies = body.get("policies");
        assertEquals(1, policies.size());
        JsonNode p1 = policies.get(0);
        assertEquals("pol_active_1", p1.get("id").asText());
        assertEquals("active", p1.get("status").asText());
        assertEquals("git-sha-1", p1.get("gitCommitHash").asText());
    }

    @Test
    @DisplayName("C-005: status filtering selects drafts and an undeclared status is answered 400")
    void testGetPoliciesStatusFilter() throws Exception {
        String y1 = "id: p1\nname: P1\nversion: 1.0\nrules: []\n";
        String y2 = "id: p2\nname: P2\nversion: 1.0\nrules: []\n";
        cache.putPolicy(new SecurityPolicy("p1", "P1", "1.0", y1, SecurityPolicy.STATUS_ACTIVE, null,
                "2026-10-21T08:00:00Z"));
        cache.putPolicy(new SecurityPolicy("p2", "P2", "1.0", y2, SecurityPolicy.STATUS_DRAFT, null,
                "2026-10-21T08:00:00Z"));

        FullHttpResponse draft = sendRequest(HttpMethod.GET, "/api/v1/policies?status=draft", null,
                "Bearer auditor-token");
        assertEquals(HttpResponseStatus.OK, draft.status());
        JsonNode draftBody = parseBody(draft);
        assertEquals(1, draftBody.get("policies").size());
        assertEquals("p2", draftBody.get("policies").get(0).get("id").asText());

        FullHttpResponse invalid = sendRequest(HttpMethod.GET, "/api/v1/policies?status=bogus", null,
                "Bearer auditor-token");
        assertEquals(HttpResponseStatus.BAD_REQUEST, invalid.status());
    }

    @Test
    @DisplayName("C-006: publishing without a token is 401 and without the admin role is 403")
    void testPostPolicyAuthFailures() {
        String payload = "{\"name\": \"New Policy\", \"version\": \"1.0.0\", "
                + "\"rawYaml\": \"id: p\\nname: p\\nversion: 1\\nrules: []\"}";

        FullHttpResponse unauthorized = sendRequest(HttpMethod.POST, "/api/v1/policies", payload, null);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, unauthorized.status());
        unauthorized.release();

        FullHttpResponse forbidden = sendRequest(HttpMethod.POST, "/api/v1/policies", payload,
                "Bearer readonly-token-xyz");
        assertEquals(HttpResponseStatus.FORBIDDEN, forbidden.status());
        forbidden.release();
    }

    @Test
    @DisplayName("C-006: an invalid YAML document is answered 400")
    void testPostPolicyInvalidYamlSyntax() throws Exception {
        FullHttpResponse response = publish("id: broken\nname: [unclosed list", "Broken Policy", "1.0.0");
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
        assertTrue(parseBody(response).get("error").asText().contains("Syntax error"));
    }

    @Test
    @DisplayName("C-006: a published version is stored as a draft and never governs traffic")
    void testPostPolicyStoresDraft() throws Exception {
        String rawYaml = """
                id: pol_staging_k8s
                name: Staging K8s Tool Policy
                version: 1.2.0
                targetAgents: ["agent-worker"]
                rules:
                  - tool: "kubectl_get"
                    action: allow
                """;

        FullHttpResponse response = publish(rawYaml, "Staging K8s Tool Policy", "1.2.0");
        assertEquals(HttpResponseStatus.CREATED, response.status());

        JsonNode body = parseBody(response);
        assertEquals("pol_staging_k8s", body.get("id").asText());
        assertEquals("draft", body.get("status").asText());
        assertTrue(body.has("createdAt"));

        SecurityPolicy cached = cache.getPolicy("pol_staging_k8s");
        assertNotNull(cached);
        assertEquals("draft", cached.status());
        assertEquals("commit-hash-789", cached.gitCommitHash());
        assertNull(cache.getPolicyForAgent("agent-worker", null),
                "A draft must not govern traffic before activation");
    }

    @Test
    @DisplayName("C-017: GET /api/v1/policies/active is 404 before activation and returns the document after")
    void testActivePolicyBeforeAndAfterActivation() throws Exception {
        FullHttpResponse missing = sendRequest(HttpMethod.GET, "/api/v1/policies/active", null,
                "Bearer operator-token");
        assertEquals(HttpResponseStatus.NOT_FOUND, missing.status());
        missing.release();

        String rawYaml = "id: pol_live\nname: Live Policy\nversion: 2.0.0\nrules: []\n";
        publish(rawYaml, "Live Policy", "2.0.0");

        String activation = "{\"version\": \"2.0.0\", \"baseVersionId\": \"\", \"rawYaml\": "
                + mapper.writeValueAsString(rawYaml) + "}";
        cache.putPolicy(new SecurityPolicy("pol_live", "Live Policy", "2.0.0", rawYaml,
                SecurityPolicy.STATUS_DRAFT, "commit-hash-789", "2026-10-21T08:00:00Z"));

        FullHttpResponse activated = sendRequest(HttpMethod.PUT, "/api/v1/policies/active", activation,
                "Bearer admin-token");
        assertEquals(HttpResponseStatus.OK, activated.status());

        JsonNode activatedBody = parseBody(activated);
        assertEquals("pol_live", activatedBody.get("id").asText());
        assertEquals("active", activatedBody.get("status").asText());
        assertEquals("commit-hash-789", activatedBody.get("gitCommitHash").asText());

        FullHttpResponse active = sendRequest(HttpMethod.GET, "/api/v1/policies/active", null,
                "Bearer auditor-token");
        assertEquals(HttpResponseStatus.OK, active.status());
        JsonNode activeBody = parseBody(active);
        assertEquals("active", activeBody.get("status").asText());
        assertEquals(rawYaml, activeBody.get("rawYaml").asText());
    }

    @Test
    @DisplayName("C-018: a stale baseVersionId is answered 409 and leaves the active policy in force")
    void testActivationConflict() throws Exception {
        String firstYaml = "id: pol_one\nname: One\nversion: 1.0.0\nrules: []\n";
        String secondYaml = "id: pol_two\nname: Two\nversion: 2.0.0\nrules: []\n";

        FullHttpResponse first = sendRequest(HttpMethod.PUT, "/api/v1/policies/active",
                "{\"version\": \"1.0.0\", \"baseVersionId\": \"\", \"rawYaml\": "
                        + mapper.writeValueAsString(firstYaml) + "}", "Bearer admin-token");
        assertEquals(HttpResponseStatus.OK, first.status());

        FullHttpResponse stale = sendRequest(HttpMethod.PUT, "/api/v1/policies/active",
                "{\"version\": \"2.0.0\", \"baseVersionId\": \"\", \"rawYaml\": "
                        + mapper.writeValueAsString(secondYaml) + "}", "Bearer admin-token");
        assertEquals(HttpResponseStatus.CONFLICT, stale.status());

        FullHttpResponse active = sendRequest(HttpMethod.GET, "/api/v1/policies/active", null,
                "Bearer admin-token");
        assertEquals("pol_one", parseBody(active).get("id").asText());
    }

    @Test
    @DisplayName("C-018: an absent baseVersionId field is answered 400")
    void testActivationRequiresBaseVersionId() throws Exception {
        String rawYaml = "id: pol_three\nname: Three\nversion: 3.0.0\nrules: []\n";
        FullHttpResponse response = sendRequest(HttpMethod.PUT, "/api/v1/policies/active",
                "{\"version\": \"3.0.0\", \"rawYaml\": " + mapper.writeValueAsString(rawYaml) + "}",
                "Bearer admin-token");
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
    }

    @Test
    @DisplayName("C-018: activation requires the admin role")
    void testActivationRequiresAdmin() {
        FullHttpResponse response = sendRequest(HttpMethod.PUT, "/api/v1/policies/active",
                "{\"version\": \"1.0.0\", \"baseVersionId\": \"\", \"rawYaml\": \"id: x\"}",
                "Bearer readonly-token");
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
        response.release();
    }

    @Test
    @DisplayName("FEAT-002: a non-policy endpoint is passed through to the next handler")
    void testUnmatchedPathPassesThrough() {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.GET,
                "/health"
        );

        assertTrue(channel.writeInbound(request));
        DefaultFullHttpRequest forwarded = channel.readInbound();
        assertNotNull(forwarded);
        assertEquals("/health", forwarded.uri());
        forwarded.release();
    }
}
