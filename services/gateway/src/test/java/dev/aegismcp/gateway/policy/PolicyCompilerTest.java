package dev.aegismcp.gateway.policy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for YAML policy compilation into executable AST.
 * Anchors: FEAT-002, C-006, NFR-024.
 */
class PolicyCompilerTest {

    private final PolicyCompiler compiler = PolicyCompiler.getInstance();

    @Test
    @DisplayName("FEAT-002 / C-006: Compiles valid YAML policy with tool whitelist and argument constraints")
    void testCompileValidYamlPolicy() {
        String yaml = """
                id: pol_staging_db_v1
                name: Staging Database Access Policy
                version: 1.0.0
                targetAgents:
                  - "agent-*"
                  - "spiffe://cluster.local/ns/prod/sa/*"
                actionThreshold: 75.0
                rules:
                  - id: rule_fs_read
                    tool: filesystem_read
                    action: allow
                    constraints:
                      - argument: path
                        operator: starts_with
                        value: "/workspace"
                  - id: rule_db_query
                    tool: db_query
                    action: allow
                    constraints:
                      - argument: query
                        operator: matches_regex
                        value: "(?i)^\\\\s*SELECT.*"
                      - argument: max_rows
                        operator: lte
                        value: 1000
                  - id: rule_db_drop
                    tool: db_drop
                    action: require_approval
                    description: "Requires explicit operator sign-off before dropping DB"
                """;

        PolicyAst ast = compiler.compile(yaml);
        assertNotNull(ast);
        assertEquals("pol_staging_db_v1", ast.id());
        assertEquals("Staging Database Access Policy", ast.name());
        assertEquals("1.0.0", ast.version());
        assertEquals(2, ast.targetAgents().size());
        assertEquals(75.0, ast.actionThreshold());
        assertEquals(PolicyVerdict.DENY, ast.defaultAction()); // fail-closed default

        assertEquals(3, ast.rules().size());

        PolicyRule rule1 = ast.rules().get(0);
        assertEquals("rule_fs_read", rule1.id());
        assertEquals("filesystem_read", rule1.tool());
        assertEquals(PolicyVerdict.ALLOW, rule1.action());
        assertEquals(1, rule1.constraints().size());
        assertEquals("path", rule1.constraints().get(0).argument());
        assertEquals(ConstraintOperator.STARTS_WITH, rule1.constraints().get(0).operator());
        assertEquals("/workspace", rule1.constraints().get(0).value());

        PolicyRule rule2 = ast.rules().get(1);
        assertEquals("rule_db_query", rule2.id());
        assertEquals(2, rule2.constraints().size());
        assertEquals(ConstraintOperator.MATCHES_REGEX, rule2.constraints().get(0).operator());
        assertEquals(ConstraintOperator.LESS_THAN_OR_EQUAL, rule2.constraints().get(1).operator());

        PolicyRule rule3 = ast.rules().get(2);
        assertEquals("rule_db_drop", rule3.id());
        assertEquals(PolicyVerdict.REQUIRE_APPROVAL, rule3.action());
        assertTrue(rule3.isRequireApproval());
    }

    @Test
    @DisplayName("FEAT-002: Compiles policy with snake_case fields and boolean require_approval")
    void testCompileSnakeCaseAndApprovalFlag() {
        String yaml = """
                id: pol_k8s_ops
                name: Kubernetes Operator Policy
                version: 2.1.0
                target_agents:
                  - "ops-bot"
                action_threshold: 90.0
                rules:
                  - tool: "k8s_delete_pod"
                    require_approval: true
                    constraints:
                      - argument: namespace
                        operator: in
                        value: ["default", "staging"]
                """;

        PolicyAst ast = compiler.compile(yaml);
        assertNotNull(ast);
        assertEquals("pol_k8s_ops", ast.id());
        assertEquals(1, ast.targetAgents().size());
        assertEquals("ops-bot", ast.targetAgents().get(0));
        assertEquals(90.0, ast.actionThreshold());

        PolicyRule rule = ast.rules().get(0);
        assertEquals("k8s_delete_pod", rule.tool());
        assertEquals(PolicyVerdict.REQUIRE_APPROVAL, rule.action());
        assertTrue(rule.isRequireApproval());
        assertEquals(1, rule.constraints().size());
        assertEquals(ConstraintOperator.IN, rule.constraints().get(0).operator());
    }

    @Test
    @DisplayName("C-006: Rejects malformed YAML with PolicyCompilationException (HTTP 400)")
    void testRejectMalformedYaml() {
        String invalidYaml = """
                id: broken_policy
                name: [unclosed list
                version: 1.0
                  indentation: error: :
                """;

        PolicyCompilationException ex = assertThrows(PolicyCompilationException.class, () -> compiler.compile(invalidYaml));
        assertTrue(ex.getMessage().contains("Syntax error in YAML") || ex.getMessage().contains("Failed to compile"));
    }

    @Test
    @DisplayName("C-006: Rejects policy missing mandatory id, name, or version")
    void testRejectMissingRequiredFields() {
        String missingIdYaml = """
                name: Missing ID Policy
                version: 1.0.0
                rules: []
                """;
        PolicyCompilationException ex1 = assertThrows(PolicyCompilationException.class, () -> compiler.compile(missingIdYaml));
        assertTrue(ex1.getMessage().contains("Policy 'id' is required") || ex1.getMessage().contains("Invalid AST"));

        String missingVersionYaml = """
                id: pol_no_ver
                name: Missing Version Policy
                rules: []
                """;
        PolicyCompilationException ex2 = assertThrows(PolicyCompilationException.class, () -> compiler.compile(missingVersionYaml));
        assertTrue(ex2.getMessage().contains("Policy 'version' is required") || ex2.getMessage().contains("Invalid AST"));
    }

    @Test
    @DisplayName("FEAT-002: Rejects invalid regex pattern in constraint")
    void testRejectInvalidRegexConstraint() {
        String badRegexYaml = """
                id: pol_bad_regex
                name: Bad Regex Policy
                version: 1.0.0
                rules:
                  - tool: search
                    constraints:
                      - argument: query
                        operator: regex
                        value: "(unclosed group"
                """;

        PolicyCompilationException ex = assertThrows(PolicyCompilationException.class, () -> compiler.compile(badRegexYaml));
        assertTrue(ex.getMessage().contains("Invalid regex pattern") || ex.getMessage().contains("Invalid AST"));
    }

    @Test
    @DisplayName("FEAT-002: Rejects non-numeric value for numeric comparison operator")
    void testRejectNonNumericForLte() {
        String badNumberYaml = """
                id: pol_bad_num
                name: Bad Number Policy
                version: 1.0.0
                rules:
                  - tool: fetch
                    constraints:
                      - argument: limit
                        operator: lte
                        value: "not-a-number"
                """;

        PolicyCompilationException ex = assertThrows(PolicyCompilationException.class, () -> compiler.compile(badNumberYaml));
        assertTrue(ex.getMessage().contains("Numeric value required") || ex.getMessage().contains("Invalid AST"));
    }
}
