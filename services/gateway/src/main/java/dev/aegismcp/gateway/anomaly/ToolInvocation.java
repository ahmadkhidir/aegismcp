package dev.aegismcp.gateway.anomaly;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;
import java.util.Objects;

/**
 * Representation of a tool invocation event stored in an agent session sequence.
 * Anchors: FEAT-004.
 */
public record ToolInvocation(
        String toolName,
        JsonNode arguments,
        Instant timestamp
) {
    public ToolInvocation {
        Objects.requireNonNull(toolName, "toolName must not be null");
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }

    public static ToolInvocation of(String toolName) {
        return new ToolInvocation(toolName, null, Instant.now());
    }

    public static ToolInvocation of(String toolName, Instant timestamp) {
        return new ToolInvocation(toolName, null, timestamp);
    }

    public static ToolInvocation of(String toolName, JsonNode arguments) {
        return new ToolInvocation(toolName, arguments, Instant.now());
    }

    public static ToolInvocation of(String toolName, JsonNode arguments, Instant timestamp) {
        return new ToolInvocation(toolName, arguments, timestamp);
    }
}
