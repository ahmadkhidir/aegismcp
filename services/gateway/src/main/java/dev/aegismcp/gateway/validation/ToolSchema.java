package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Objects;
import java.util.Set;

/**
 * Published JSON schema definition and security metadata for an MCP tool.
 * Anchors: FEAT-012, NFR-024.
 */
public record ToolSchema(
        String toolName,
        JsonNode inputSchema,
        String allowedBaseDir,
        Set<ToolCategory> categories
) {
    public enum ToolCategory {
        DATABASE,
        FILESYSTEM,
        COMMAND,
        GENERIC
    }

    public ToolSchema {
        Objects.requireNonNull(toolName, "toolName must not be null");
        categories = categories != null ? Set.copyOf(categories) : Set.of(ToolCategory.GENERIC);
    }

    public static ToolSchema of(String toolName, JsonNode inputSchema) {
        return new ToolSchema(toolName, inputSchema, null, Set.of(inferCategory(toolName)));
    }

    public static ToolSchema filesystem(String toolName, JsonNode inputSchema, String allowedBaseDir) {
        return new ToolSchema(toolName, inputSchema, allowedBaseDir, Set.of(ToolCategory.FILESYSTEM));
    }

    public static ToolSchema database(String toolName, JsonNode inputSchema) {
        return new ToolSchema(toolName, inputSchema, null, Set.of(ToolCategory.DATABASE));
    }

    public static ToolSchema command(String toolName, JsonNode inputSchema) {
        return new ToolSchema(toolName, inputSchema, null, Set.of(ToolCategory.COMMAND));
    }

    private static ToolCategory inferCategory(String toolName) {
        if (toolName == null) return ToolCategory.GENERIC;
        String lower = toolName.toLowerCase();
        if (lower.contains("sql") || lower.contains("query") || lower.contains("db") || lower.contains("database")) {
            return ToolCategory.DATABASE;
        }
        if (lower.contains("file") || lower.contains("path") || lower.contains("read") || lower.contains("write") || lower.contains("dir")) {
            return ToolCategory.FILESYSTEM;
        }
        if (lower.contains("exec") || lower.contains("bash") || lower.contains("sh") || lower.contains("shell") || lower.contains("cmd")) {
            return ToolCategory.COMMAND;
        }
        return ToolCategory.GENERIC;
    }

    public boolean isDatabaseTool() {
        if (categories.contains(ToolCategory.DATABASE)) return true;
        String lower = toolName.toLowerCase();
        return lower.contains("sql") || lower.contains("db") || lower.contains("database");
    }

    public boolean isFilesystemTool() {
        if (categories.contains(ToolCategory.FILESYSTEM)) return true;
        String lower = toolName.toLowerCase();
        return lower.contains("file") || lower.contains("path") || lower.contains("dir");
    }

    public boolean isCommandTool() {
        if (categories.contains(ToolCategory.COMMAND)) return true;
        String lower = toolName.toLowerCase();
        return lower.contains("exec") || lower.contains("bash") || lower.contains("sh") || lower.contains("shell") || lower.contains("cmd");
    }
}
