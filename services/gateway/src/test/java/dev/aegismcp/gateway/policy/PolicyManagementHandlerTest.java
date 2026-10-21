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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying Policy Management API conforming to contracts C-005 and C-006.
 * Anchors: C-005, C-006, FEAT-002.
 */
class PolicyManagementHandlerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private PolicyCache cache;
    private PolicyManagementHandler handler;
    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        cache = new PolicyCache();
        handler = new PolicyManagementHandler(cache);
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

    @Test
    @DisplayName("C-005: GET /api/v1/policies without Bearer token returns 401 Unauthorized")
    void testGetPoliciesUnauthorized() throws Exception {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/policies", null, null);

        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
        JsonNode body = parseBody(response);
        assertTrue(body.has("error"));
    }

    @Test
    @DisplayName("C-005: GET /api/v1/policies with Bearer token returns 200 OK and policy list")
    void testGetPoliciesSuccess() throws Exception {
        String yaml = """
                id: pol_active_1
                name: Active Policy
                version: 1.0.0
                rules: []
                """;
        cache.putPolicy(SecurityPolicy.of("pol_active_1", "Active Policy", "1.0.0", yaml, "git-sha-1"));

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/policies", null, "Bearer admin-token-123");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode body = parseBody(response);
        assertTrue(body.has("policies"));
        JsonNode policies = body.get("policies");
        assertTrue(policies.isArray());
        assertEquals(1, policies.size());

        JsonNode p1 = policies.get(0);
        assertEquals("pol_active_1", p1.get("id").asText());
        assertEquals("Active Policy", p1.get("name").asText());
        assertEquals("1.0.0", p1.get("version").asText());
        assertEquals("active", p1.get("status").asText());
        assertEquals("git-sha-1", p1.get("gitCommitHash").asText());
    }

    @Test
    @DisplayName("C-005: GET /api/v1/policies?status=draft filters correctly")
    void testGetPoliciesWithStatusFilter() throws Exception {
        String y1 = "id: p1\nname: P1\nversion: 1.0\nrules: []\n";
        String y2 = "id: p2\nname: P2\nversion: 1.0\nrules: []\n";

        cache.putPolicy(new SecurityPolicy("p1", "P1", "1.0", y1, SecurityPolicy.STATUS_ACTIVE, null, "2026-10-21T08:00:00Z"));
        cache.putPolicy(new SecurityPolicy("p2", "P2", "1.0", y2, SecurityPolicy.STATUS_DRAFT, null, "2026-10-21T08:00:00Z"));

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/policies?status=draft", null, "Bearer user-token");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode body = parseBody(response);
        JsonNode policies = body.get("policies");
        assertEquals(1, policies.size());
        assertEquals("p2", policies.get(0).get("id").asText());
    }

    @Test
    @DisplayName("C-006: POST /api/v1/policies without Bearer token returns 401 Unauthorized")
    void testPostPolicyUnauthorized() throws Exception {
        String payload = """
                {
                  "name": "New Policy",
                  "version": "1.0.0",
                  "rawYaml": "id: p\\nname: p\\nversion: 1\\nrules: []",
                  "gitCommitHash": "sha123"
                }
                """;

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/policies", payload, null);

        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
    }

    @Test
    @DisplayName("C-006: POST /api/v1/policies with readonly token returns 403 Forbidden")
    void testPostPolicyForbidden() throws Exception {
        String payload = """
                {
                  "name": "New Policy",
                  "version": "1.0.0",
                  "rawYaml": "id: p\\nname: p\\nversion: 1\\nrules: []",
                  "gitCommitHash": "sha123"
                }
                """;

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/policies", payload, "Bearer readonly-token-xyz");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
        JsonNode body = parseBody(response);
        assertTrue(body.has("error"));
        assertTrue(body.get("error").asText().contains("Insufficient permissions"));
    }

    @Test
    @DisplayName("C-006: POST /api/v1/policies with syntax error in YAML returns 400 Bad Request")
    void testPostPolicyInvalidYamlSyntax() throws Exception {
        String payload = """
                {
                  "name": "Broken Policy",
                  "version": "1.0.0",
                  "rawYaml": "id: broken\\nname: [unclosed list",
                  "gitCommitHash": "sha999"
                }
                """;

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/policies", payload, "Bearer admin-token");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());

        JsonNode body = parseBody(response);
        assertTrue(body.has("error"));
        assertTrue(body.get("error").asText().contains("Syntax error in YAML or invalid AST policy rules"));
    }

    @Test
    @DisplayName("C-006: POST /api/v1/policies with valid YAML returns 201 Created and registers policy")
    void testPostPolicySuccess() throws Exception {
        String rawYaml = """
                id: pol_staging_k8s
                name: Staging K8s Tool Policy
                version: 1.2.0
                targetAgents: ["agent-worker"]
                rules:
                  - tool: "kubectl_get"
                    action: allow
                """;

        String payload = mapper.writeValueAsString(new PolicyDto.CreatePolicyRequest(
                "Staging K8s Tool Policy",
                "1.2.0",
                rawYaml,
                "commit-hash-789"
        ));

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/policies", payload, "Bearer admin-token");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.CREATED, response.status());

        JsonNode body = parseBody(response);
        assertEquals("pol_staging_k8s", body.get("id").asText());
        assertEquals("Staging K8s Tool Policy", body.get("name").asText());
        assertEquals("1.2.0", body.get("version").asText());
        assertEquals("active", body.get("status").asText());
        assertTrue(body.has("createdAt"));

        // Verify policy is immediately active in in-memory cache
        SecurityPolicy cached = cache.getPolicy("pol_staging_k8s");
        assertNotNull(cached);
        assertEquals("commit-hash-789", cached.gitCommitHash());

        PolicyAst ast = cache.getPolicyForAgent("agent-worker", null);
        assertNotNull(ast);
        assertEquals("pol_staging_k8s", ast.id());
    }

    @Test
    @DisplayName("FEAT-002: Non-policy endpoint is passed through to next handler in Netty pipeline")
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
    }
}
