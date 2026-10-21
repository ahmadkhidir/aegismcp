package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying composite DynamicParameterValidator orchestrations and DB admin whitelisting.
 * Anchors: FEAT-012, NFR-024.
 */
class DynamicParameterValidatorTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private DynamicParameterValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        validator = new DynamicParameterValidator();

        // Register sample filesystem tool schema
        String fsSchemaJson = """
                {
                  "type": "object",
                  "properties": {
                    "path": { "type": "string" },
                    "encoding": { "type": "string", "enum": ["utf-8", "ascii"] }
                  },
                  "required": ["path"]
                }
                """;
        validator.getSchemaRegistry().registerSchema("read_file", mapper.readTree(fsSchemaJson), "/data/workspace");

        // Register database query tool schema
        String sqlSchemaJson = """
                {
                  "type": "object",
                  "properties": {
                    "query": { "type": "string" },
                    "max_rows": { "type": "integer" }
                  },
                  "required": ["query"]
                }
                """;
        validator.getSchemaRegistry().registerTool(
                ToolSchema.database("db_query", mapper.readTree(sqlSchemaJson))
        );
    }

    @Test
    @DisplayName("FEAT-012: Enforces JSON schema type check before checking path traversal")
    void testSchemaTypeMismatchTriggersViolation() {
        ObjectNode args = mapper.createObjectNode();
        args.put("path", 12345); // integer instead of string

        ValidationResult result = validator.validate("agent-1", "read_file", args);
        assertFalse(result.isValid());
        assertTrue(result.summaryMessage().contains("type mismatch"));
    }

    @Test
    @DisplayName("FEAT-012: Filesystem path traversal out of bounds is blocked")
    void testPathTraversalBlocked() {
        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/data/workspace/../../etc/passwd");

        ValidationResult result = validator.validate("agent-1", "read_file", args);
        assertFalse(result.isValid());
        assertEquals("path_traversal", result.primaryViolationType());
    }

    @Test
    @DisplayName("FEAT-012 AC 3 / AC 7: Untrusted agent SQL injection is blocked")
    void testUntrustedAgentSqlInjectionBlocked() {
        ObjectNode args = mapper.createObjectNode();
        args.put("query", "SELECT * FROM accounts WHERE id = 1 UNION SELECT password, secret FROM admin");

        ValidationResult result = validator.validate("regular-agent", "db_query", args);
        assertFalse(result.isValid());
        assertTrue(result.summaryMessage().contains("SQL injection pattern detected"));
    }

    @Test
    @DisplayName("FEAT-012 AC 7: Authorized DB administrator agent whitelist bypasses SQL injection check")
    void testWhitelistedDbAdminBypassesSqlCheck() {
        String adminAgentId = "dba-lead-agent";
        validator.whitelistDatabaseAdmin(adminAgentId);

        ObjectNode args = mapper.createObjectNode();
        // Complex administrative query containing UNION or DDL keywords
        args.put("query", "SELECT id, name FROM tables UNION SELECT id, name FROM archived_tables");

        ValidationResult result = validator.validate(adminAgentId, "db_query", args);
        assertTrue(result.isValid(), "Authorized DB admin agent should be permitted to execute complex SQL");
    }

    @Test
    @DisplayName("FEAT-012 AC 7: Agent with role database-admin is automatically recognized as DB admin")
    void testDbAdminAgentIdConvention() {
        ObjectNode args = mapper.createObjectNode();
        args.put("query", "SELECT * FROM orders; DROP TABLE temp_orders");

        ValidationResult result = validator.validate("agent-database-admin-worker", "db_query", args);
        assertTrue(result.isValid(), "Agent identified as database-admin by naming convention should be permitted");
    }

    @Test
    @DisplayName("FEAT-012: Compliant invocation passes cleanly")
    void testCompliantInvocationPasses() {
        ObjectNode args = mapper.createObjectNode();
        args.put("path", "/data/workspace/logs/app.log");
        args.put("encoding", "utf-8");

        ValidationResult result = validator.validate("agent-1", "read_file", args);
        assertTrue(result.isValid());
        assertEquals(0, result.violations().size());
    }
}
