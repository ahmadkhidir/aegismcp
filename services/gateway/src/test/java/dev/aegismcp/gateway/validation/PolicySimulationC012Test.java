package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyCompiler;
import dev.aegismcp.gateway.policy.PolicyDto;
import dev.aegismcp.gateway.policy.PolicyManagementHandler;
import dev.aegismcp.gateway.policy.SecurityPolicy;
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
 * Unit tests verifying Contract C-012: POST /api/v1/policies/simulate including parameter validation.
 * Anchors: C-012, FEAT-012, FEAT-002.
 */
class PolicySimulationC012Test {

    private final ObjectMapper mapper = new ObjectMapper();
    private PolicyCache policyCache;
    private DynamicParameterValidator parameterValidator;
    private PolicyManagementHandler handler;
    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() throws Exception {
        policyCache = new PolicyCache();
        parameterValidator = new DynamicParameterValidator();

        // Register tool schema in parameterValidator
        String fileSchema = """
                {
                  "type": "object",
                  "properties": {
                    "path": { "type": "string" },
                    "maxBytes": { "type": "integer" }
                  },
                  "required": ["path"]
                }
                """;
        parameterValidator.getSchemaRegistry().registerSchema(
                "read_file",
                mapper.readTree(fileSchema),
                "/var/app/data"
        );

        // Register a policy in policyCache
        String policyYaml = """
                id: "pol-sim-test"
                name: "Simulation Test Policy"
                version: "1.0.0"
                target_agents:
                  - "agent-analyst"
                rules:
                  - id: "rule-read"
                    tool: "read_file"
                    action: "ALLOW"
                  - id: "rule-deploy"
                    tool: "deploy_service"
                    action: "REQUIRE_APPROVAL"
                  - id: "rule-delete"
                    tool: "delete_database"
                    action: "DENY"
                """;
        SecurityPolicy policy = new SecurityPolicy(
                "pol-sim-test",
                "Simulation Test Policy",
                "1.0.0",
                policyYaml,
                SecurityPolicy.STATUS_ACTIVE,
                null,
                "2026-10-21T00:00:00Z"
        );
        policyCache.putPolicy(policy);

        handler = new PolicyManagementHandler(
                policyCache,
                PolicyCompiler.getInstance(),
                mapper,
                PolicyManagementHandler.defaultAuthorizer(),
                parameterValidator
        );

        channel = new EmbeddedChannel(handler);
    }

    @Test
    @DisplayName("C-012: Missing Authorization Bearer token returns 401 Unauthorized")
    void testMissingAuthReturns401() {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "/api/v1/policies/simulate",
                Unpooled.wrappedBuffer("{}".getBytes(StandardCharsets.UTF_8))
        );

        channel.writeInbound(request);
        FullHttpResponse response = channel.readOutbound();
        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
    }

    @Test
    @DisplayName("C-012: Malformed JSON payload returns 400 Bad Request")
    void testMalformedJsonReturns400() {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "/api/v1/policies/simulate",
                Unpooled.wrappedBuffer("{not-valid-json".getBytes(StandardCharsets.UTF_8))
        );
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Bearer test-admin-token");

        channel.writeInbound(request);
        FullHttpResponse response = channel.readOutbound();
        assertNotNull(response);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
    }

    @Test
    @DisplayName("C-012 / FEAT-012: Schema parameter violation yields verdict BLOCKED with violations list")
    void testSchemaViolationYieldsBlockedVerdict() throws Exception {
        ObjectNode simReq = mapper.createObjectNode();
        simReq.put("agentId", "agent-analyst");
        simReq.put("toolName", "read_file");
        ObjectNode args = mapper.createObjectNode();
        args.put("path", "data.txt");
        args.put("maxBytes", "not-a-number"); // schema mismatch
        simReq.set("arguments", args);

        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "/api/v1/policies/simulate",
                Unpooled.wrappedBuffer(mapper.writeValueAsBytes(simReq))
        );
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Bearer admin-token");

        channel.writeInbound(request);
        FullHttpResponse response = channel.readOutbound();
        assertEquals(HttpResponseStatus.OK, response.status());

        String json = response.content().toString(StandardCharsets.UTF_8);
        PolicyDto.SimulatePolicyResponse simResp = mapper.readValue(json, PolicyDto.SimulatePolicyResponse.class);

        assertEquals("BLOCKED", simResp.verdict());
        assertEquals("parameter_validation", simResp.ruleMatched());
        assertFalse(simResp.violations().isEmpty());
        assertTrue(simResp.violations().get(0).contains("type mismatch"));
    }

    @Test
    @DisplayName("C-012 / FEAT-012: Path traversal yields verdict BLOCKED")
    void testPathTraversalYieldsBlockedVerdict() throws Exception {
        ObjectNode simReq = mapper.createObjectNode();
        simReq.put("agentId", "agent-analyst");
        simReq.put("toolName", "read_file");
        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/var/app/data/../../etc/shadow");
        simReq.set("arguments", args);

        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "/api/v1/policies/simulate",
                Unpooled.wrappedBuffer(mapper.writeValueAsBytes(simReq))
        );
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Bearer admin-token");

        channel.writeInbound(request);
        FullHttpResponse response = channel.readOutbound();
        assertEquals(HttpResponseStatus.OK, response.status());

        String json = response.content().toString(StandardCharsets.UTF_8);
        PolicyDto.SimulatePolicyResponse simResp = mapper.readValue(json, PolicyDto.SimulatePolicyResponse.class);

        assertEquals("BLOCKED", simResp.verdict());
        assertFalse(simResp.violations().isEmpty());
        assertTrue(simResp.violations().get(0).contains("Path traversal"));
    }

    @Test
    @DisplayName("C-012: Explicit policy DENY yields verdict BLOCKED with ruleMatched")
    void testPolicyDenyYieldsBlockedVerdict() throws Exception {
        ObjectNode simReq = mapper.createObjectNode();
        simReq.put("agentId", "agent-analyst");
        simReq.put("toolName", "delete_database");
        simReq.set("arguments", mapper.createObjectNode());

        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "/api/v1/policies/simulate",
                Unpooled.wrappedBuffer(mapper.writeValueAsBytes(simReq))
        );
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Bearer admin-token");

        channel.writeInbound(request);
        FullHttpResponse response = channel.readOutbound();
        assertEquals(HttpResponseStatus.OK, response.status());

        String json = response.content().toString(StandardCharsets.UTF_8);
        PolicyDto.SimulatePolicyResponse simResp = mapper.readValue(json, PolicyDto.SimulatePolicyResponse.class);

        assertEquals("BLOCKED", simResp.verdict());
        assertEquals("rule-delete", simResp.ruleMatched());
    }

    @Test
    @DisplayName("C-012: Sensitive tool requiring approval yields verdict REQUIRE_APPROVAL")
    void testRequireApprovalYieldsRequireApprovalVerdict() throws Exception {
        ObjectNode simReq = mapper.createObjectNode();
        simReq.put("agentId", "agent-analyst");
        simReq.put("toolName", "deploy_service");
        simReq.set("arguments", mapper.createObjectNode());

        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "/api/v1/policies/simulate",
                Unpooled.wrappedBuffer(mapper.writeValueAsBytes(simReq))
        );
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Bearer admin-token");

        channel.writeInbound(request);
        FullHttpResponse response = channel.readOutbound();
        assertEquals(HttpResponseStatus.OK, response.status());

        String json = response.content().toString(StandardCharsets.UTF_8);
        PolicyDto.SimulatePolicyResponse simResp = mapper.readValue(json, PolicyDto.SimulatePolicyResponse.class);

        assertEquals("REQUIRE_APPROVAL", simResp.verdict());
        assertEquals("rule-deploy", simResp.ruleMatched());
        assertTrue(simResp.violations().isEmpty());
    }

    @Test
    @DisplayName("C-012: Authorized compliant invocation yields verdict ALLOWED")
    void testCompliantInvocationYieldsAllowed() throws Exception {
        ObjectNode simReq = mapper.createObjectNode();
        simReq.put("agentId", "agent-analyst");
        simReq.put("toolName", "read_file");
        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/var/app/data/metrics.txt");
        args.put("maxBytes", 1024);
        simReq.set("arguments", args);

        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "/api/v1/policies/simulate",
                Unpooled.wrappedBuffer(mapper.writeValueAsBytes(simReq))
        );
        request.headers().set(HttpHeaderNames.AUTHORIZATION, "Bearer admin-token");

        channel.writeInbound(request);
        FullHttpResponse response = channel.readOutbound();
        assertEquals(HttpResponseStatus.OK, response.status());

        String json = response.content().toString(StandardCharsets.UTF_8);
        PolicyDto.SimulatePolicyResponse simResp = mapper.readValue(json, PolicyDto.SimulatePolicyResponse.class);

        assertEquals("ALLOWED", simResp.verdict());
        assertEquals("rule-read", simResp.ruleMatched());
        assertTrue(simResp.violations().isEmpty());
    }
}
