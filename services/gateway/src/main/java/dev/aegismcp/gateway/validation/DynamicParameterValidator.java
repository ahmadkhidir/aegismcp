package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.gateway.proxy.AgentIdentity;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Pre-execution payload validation and injection sanitization engine for MCP tool invocations.
 * Combines strict JSON schema enforcement with path traversal, SQL injection, and command injection defenses.
 * Anchors: FEAT-012, NFR-024.
 */
public class DynamicParameterValidator {

    private final ToolSchemaRegistry schemaRegistry;
    private final JsonSchemaValidator jsonSchemaValidator;
    private final PathTraversalSanitizer pathTraversalSanitizer;
    private final SqlInjectionDetector sqlInjectionDetector;
    private final CommandInjectionDetector commandInjectionDetector;

    // Policy override / whitelist for authorized database administrator agents (FEAT-012 Edge Cases)
    private final Set<String> whitelistedDbAdmins = ConcurrentHashMap.newKeySet();

    public DynamicParameterValidator() {
        this(new ToolSchemaRegistry(), new JsonSchemaValidator(), new PathTraversalSanitizer(), new SqlInjectionDetector(), new CommandInjectionDetector());
    }

    public DynamicParameterValidator(ToolSchemaRegistry schemaRegistry) {
        this(schemaRegistry, new JsonSchemaValidator(), new PathTraversalSanitizer(), new SqlInjectionDetector(), new CommandInjectionDetector());
    }

    public DynamicParameterValidator(
            ToolSchemaRegistry schemaRegistry,
            JsonSchemaValidator jsonSchemaValidator,
            PathTraversalSanitizer pathTraversalSanitizer,
            SqlInjectionDetector sqlInjectionDetector,
            CommandInjectionDetector commandInjectionDetector
    ) {
        this.schemaRegistry = Objects.requireNonNull(schemaRegistry, "schemaRegistry must not be null");
        this.jsonSchemaValidator = Objects.requireNonNull(jsonSchemaValidator, "jsonSchemaValidator must not be null");
        this.pathTraversalSanitizer = Objects.requireNonNull(pathTraversalSanitizer, "pathTraversalSanitizer must not be null");
        this.sqlInjectionDetector = Objects.requireNonNull(sqlInjectionDetector, "sqlInjectionDetector must not be null");
        this.commandInjectionDetector = Objects.requireNonNull(commandInjectionDetector, "commandInjectionDetector must not be null");
    }

    /**
     * Authorizes a database administrator agent identity to bypass SQL injection heuristics.
     */
    public void whitelistDatabaseAdmin(String agentId) {
        if (agentId != null && !agentId.isBlank()) {
            whitelistedDbAdmins.add(agentId.trim());
        }
    }

    public void removeDatabaseAdmin(String agentId) {
        if (agentId != null) {
            whitelistedDbAdmins.remove(agentId.trim());
        }
    }

    public boolean isDatabaseAdmin(String agentId) {
        if (agentId == null) return false;
        if (whitelistedDbAdmins.contains(agentId) || whitelistedDbAdmins.contains("*")) {
            return true;
        }
        String lower = agentId.toLowerCase();
        return lower.contains("db-admin") || lower.contains("database-admin") || lower.contains("db_admin");
    }

    /**
     * Validates tool invocation arguments for an agent.
     */
    public ValidationResult validate(AgentIdentity identity, String toolName, JsonNode arguments) {
        String agentId = identity != null ? identity.agentId() : "anonymous";
        return validate(agentId, toolName, arguments);
    }

    /**
     * Validates tool invocation arguments for an agent ID and tool name.
     */
    public ValidationResult validate(String agentId, String toolName, JsonNode arguments) {
        List<ValidationViolation> violations = new ArrayList<>();

        ToolSchema toolSchema = schemaRegistry.getSchema(toolName);
        if (toolSchema == null) {
            // Infer basic schema metadata from tool name when missing from manifest (FEAT-012 edge cases)
            toolSchema = ToolSchema.of(toolName != null ? toolName : "unknown", null);
        }

        // 1. Strict JSON schema enforcement
        if (toolSchema.inputSchema() != null) {
            violations.addAll(jsonSchemaValidator.validate(toolSchema.inputSchema(), arguments));
        }

        // 2. Path traversal sanitization
        violations.addAll(pathTraversalSanitizer.sanitize(toolSchema, arguments));

        // 3. SQL injection detection (bypassed if agent is whitelisted DB admin)
        boolean isWhitelisted = isDatabaseAdmin(agentId);
        if (!isWhitelisted) {
            violations.addAll(sqlInjectionDetector.detect(toolSchema, arguments));
        }

        // 4. Command injection detection
        violations.addAll(commandInjectionDetector.detect(toolSchema, arguments));

        if (violations.isEmpty()) {
            return ValidationResult.valid();
        }
        return ValidationResult.invalid(violations);
    }

    public ToolSchemaRegistry getSchemaRegistry() {
        return schemaRegistry;
    }

    public JsonSchemaValidator getJsonSchemaValidator() {
        return jsonSchemaValidator;
    }

    public PathTraversalSanitizer getPathTraversalSanitizer() {
        return pathTraversalSanitizer;
    }

    public SqlInjectionDetector getSqlInjectionDetector() {
        return sqlInjectionDetector;
    }

    public CommandInjectionDetector getCommandInjectionDetector() {
        return commandInjectionDetector;
    }

    public Set<String> getWhitelistedDbAdmins() {
        return whitelistedDbAdmins;
    }
}
