package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Thread-safe registry storing published MCP tool schemas for pre-execution validation.
 * Anchors: FEAT-012, NFR-024.
 */
public class ToolSchemaRegistry {

    private final ConcurrentMap<String, ToolSchema> schemas = new ConcurrentHashMap<>();

    public void registerSchema(String toolName, JsonNode inputSchema) {
        Objects.requireNonNull(toolName, "toolName must not be null");
        schemas.put(toolName, ToolSchema.of(toolName, inputSchema));
    }

    public void registerSchema(String toolName, JsonNode inputSchema, String allowedBaseDir) {
        Objects.requireNonNull(toolName, "toolName must not be null");
        schemas.put(toolName, ToolSchema.filesystem(toolName, inputSchema, allowedBaseDir));
    }

    public void registerTool(ToolSchema toolSchema) {
        Objects.requireNonNull(toolSchema, "toolSchema must not be null");
        schemas.put(toolSchema.toolName(), toolSchema);
    }

    public ToolSchema getSchema(String toolName) {
        return toolName != null ? schemas.get(toolName) : null;
    }

    public boolean hasSchema(String toolName) {
        return toolName != null && schemas.containsKey(toolName);
    }

    public void removeSchema(String toolName) {
        if (toolName != null) {
            schemas.remove(toolName);
        }
    }

    public void clear() {
        schemas.clear();
    }
}
