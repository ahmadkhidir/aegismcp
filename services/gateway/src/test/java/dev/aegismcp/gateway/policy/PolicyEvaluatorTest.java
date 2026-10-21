package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for least-privilege declarative tool policy evaluation.
 * Anchors: FEAT-002, NFR-001, NFR-027.
 */
class PolicyEvaluatorTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private PolicyCache cache;
    private PolicyEvaluator evaluator;

    private static final String DEFAULT_POLICY_YAML = """
            id: pol_enterprise_v1
            name: Enterprise DevSecOps Tool Policy
            version: 1.0.0
            targetAgents:
              - "support-bot"
              - "spiffe://cluster.local/ns/agents/sa/support-bot"
            rules:
              - id: rule_fs_read
                tool: filesystem_read
                action: allow
                constraints:
                  - argument: path
                    operator: starts_with
                    value: "/workspace"
              - id: rule_sql_query
                tool: db_query
                action: allow
                constraints:
                  - argument: query
                    operator: matches_regex
                    value: "(?i)^\\\\s*SELECT\\\\s+.*"
                  - argument: max_rows
                    operator: lte
                    value: 1000
              - id: rule_http_fetch
                tool: http_fetch
                action: allow
                constraints:
                  - argument: domain
                    operator: in
                    value: ["api.internal.corp", "status.corp"]
              - id: rule_deploy_prod
                tool: deploy_application
                action: require_approval
                description: "Production deployments mandate manual human sign-off"
              - id: rule_drop_table
                tool: db_drop
                action: deny
            """;

    @BeforeEach
    void setUp() {
        cache = new PolicyCache();
        evaluator = new PolicyEvaluator(cache);

        SecurityPolicy policy = new SecurityPolicy(
                "pol_enterprise_v1",
                "Enterprise DevSecOps Tool Policy",
                "1.0.0",
                DEFAULT_POLICY_YAML,
                SecurityPolicy.STATUS_ACTIVE,
                "commit-abc123",
                "2026-10-21T08:00:00Z"
        );
        cache.putPolicy(policy);
    }

    @Test
    @DisplayName("FEAT-002 AC 1: Whitelist tool call with compliant arguments is ALLOWED")
    void testWhitelistToolWithCompliantArgumentsAllowed() {
        AgentIdentity identity = AgentIdentity.fromCredentials("spiffe://cluster.local/ns/agents/sa/support-bot", null);
        SecurityContext context = SecurityContext.of(identity, new InetSocketAddress("127.0.0.1", 12345));

        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/workspace/src/App.java");

        PolicyEvaluationResult result = evaluator.evaluate(context, "filesystem_read", args);

        assertTrue(result.isAllowed());
        assertEquals(PolicyVerdict.ALLOW, result.verdict());
        assertEquals("pol_enterprise_v1", result.policyId());
        assertEquals("rule_fs_read", result.ruleId());
        assertFalse(result.argumentViolation());
    }

    @Test
    @DisplayName("FEAT-002 AC 2: Unauthorized tool execution is DENIED immediately (fail-closed)")
    void testUnauthorizedToolCallDenied() {
        AgentIdentity identity = AgentIdentity.fromBearer("token-support-bot");
        cache.bindAgentToPolicy(identity.agentId(), "pol_enterprise_v1");

        ObjectNode args = mapper.createObjectNode();
        args.put("command", "rm -rf /");

        PolicyEvaluationResult result = evaluator.evaluate(identity, "execute_shell_command", args);

        assertTrue(result.isDenied());
        assertEquals(PolicyVerdict.DENY, result.verdict());
        assertEquals("pol_enterprise_v1", result.policyId());
        assertFalse(result.argumentViolation());
        assertTrue(result.reason().contains("is not permitted in policy"));
    }

    @Test
    @DisplayName("FEAT-002 AC 3: Path argument constraint violation (/etc/passwd) is DENIED and flagged")
    void testArgumentPathConstraintViolationDenied() {
        AgentIdentity identity = AgentIdentity.fromCredentials("spiffe://cluster.local/ns/agents/sa/support-bot", null);

        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/etc/passwd"); // Violates starts_with /workspace

        PolicyEvaluationResult result = evaluator.evaluate(identity, "filesystem_read", args);

        assertTrue(result.isDenied());
        assertEquals(PolicyVerdict.DENY, result.verdict());
        assertTrue(result.argumentViolation(), "Should be flagged as argument violation");
        assertTrue(result.reason().contains("violated constraint: STARTS_WITH /workspace"));
    }

    @Test
    @DisplayName("FEAT-002: SQL Regex constraint prevents DROP TABLE injection attempt")
    void testRegexConstraintBlocksInjection() {
        AgentIdentity identity = AgentIdentity.fromCredentials("spiffe://cluster.local/ns/agents/sa/support-bot", null);

        // Compliant SELECT passes
        ObjectNode validArgs = mapper.createObjectNode();
        validArgs.put("query", "SELECT id, name FROM users WHERE active = true");
        validArgs.put("max_rows", 500);

        PolicyEvaluationResult validResult = evaluator.evaluate(identity, "db_query", validArgs);
        assertTrue(validResult.isAllowed());

        // Dangerous DROP query blocked
        ObjectNode attackArgs = mapper.createObjectNode();
        attackArgs.put("query", "DROP TABLE users; --");
        attackArgs.put("max_rows", 100);

        PolicyEvaluationResult attackResult = evaluator.evaluate(identity, "db_query", attackArgs);
        assertTrue(attackResult.isDenied());
        assertTrue(attackResult.argumentViolation());
        assertTrue(attackResult.reason().contains("violated constraint: MATCHES_REGEX"));
    }

    @Test
    @DisplayName("FEAT-002: Numeric max_rows constraint blocks query exceeding threshold")
    void testNumericConstraintBlocksRowLimitExceeded() {
        AgentIdentity identity = AgentIdentity.fromCredentials("spiffe://cluster.local/ns/agents/sa/support-bot", null);

        ObjectNode args = mapper.createObjectNode();
        args.put("query", "SELECT * FROM audit_logs");
        args.put("max_rows", 5000); // Max allowed is 1000

        PolicyEvaluationResult result = evaluator.evaluate(identity, "db_query", args);
        assertTrue(result.isDenied());
        assertTrue(result.argumentViolation());
        assertTrue(result.reason().contains("violated constraint: LESS_THAN_OR_EQUAL 1000"));
    }

    @Test
    @DisplayName("FEAT-002: Whitelist domain IN constraint allows approved and blocks unapproved domains")
    void testDomainInConstraint() {
        AgentIdentity identity = AgentIdentity.fromCredentials("spiffe://cluster.local/ns/agents/sa/support-bot", null);

        // Approved domain
        ObjectNode goodArgs = mapper.createObjectNode();
        goodArgs.put("domain", "api.internal.corp");
        assertTrue(evaluator.evaluate(identity, "http_fetch", goodArgs).isAllowed());

        // Unapproved domain
        ObjectNode badArgs = mapper.createObjectNode();
        badArgs.put("domain", "evil-exfiltration.com");
        PolicyEvaluationResult badResult = evaluator.evaluate(identity, "http_fetch", badArgs);
        assertTrue(badResult.isDenied());
        assertTrue(badResult.argumentViolation());
    }

    @Test
    @DisplayName("FEAT-002 / FEAT-006: Sensitive tool returns REQUIRE_APPROVAL verdict")
    void testSensitiveToolRequiresApproval() {
        AgentIdentity identity = AgentIdentity.fromCredentials("spiffe://cluster.local/ns/agents/sa/support-bot", null);

        ObjectNode args = mapper.createObjectNode();
        args.put("environment", "production");

        PolicyEvaluationResult result = evaluator.evaluate(identity, "deploy_application", args);
        assertTrue(result.isRequireApproval());
        assertEquals(PolicyVerdict.REQUIRE_APPROVAL, result.verdict());
        assertTrue(result.reason().contains("requires human-in-the-loop approval"));
    }

    @Test
    @DisplayName("FEAT-002: Explicit rule action DENY blocks tool call")
    void testExplicitDenyRule() {
        AgentIdentity identity = AgentIdentity.fromCredentials("spiffe://cluster.local/ns/agents/sa/support-bot", null);

        ObjectNode args = mapper.createObjectNode();
        args.put("table", "customers");

        PolicyEvaluationResult result = evaluator.evaluate(identity, "db_drop", args);
        assertTrue(result.isDenied());
        assertEquals(PolicyVerdict.DENY, result.verdict());
        assertTrue(result.reason().contains("denied by rule"));
    }

    @Test
    @DisplayName("FEAT-002: Fail-closed posture when no policy is assigned to agent")
    void testFailClosedOnUnmappedAgentIdentity() {
        AgentIdentity unknownAgent = AgentIdentity.fromCredentials("spiffe://cluster.local/ns/untrusted/sa/unknown-bot", null);

        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/workspace/file.txt");

        PolicyEvaluationResult result = evaluator.evaluate(unknownAgent, "filesystem_read", args);
        assertTrue(result.isDenied());
        assertEquals(PolicyVerdict.DENY, result.verdict());
        assertNull(result.policyId());
        assertTrue(result.reason().contains("Fail-closed: No active security policy assigned"));
    }
}
