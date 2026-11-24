package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import dev.aegismcp.gateway.proxy.UpstreamClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests verifying the tool manifest the gateway reads to validate arguments against each tool's
 * published schema (FEAT-012, C-001 SCHEMA_VALIDATION_FAILED).
 */
class UpstreamToolSchemaSourceTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("FEAT-012: published tool schemas are registered from the upstream tools/list manifest")
    void registersPublishedSchemas() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        UpstreamClient upstream = (context, request) -> {
            calls.incrementAndGet();
            return CompletableFuture.completedFuture(manifest());
        };
        ToolSchemaRegistry registry = new ToolSchemaRegistry();

        int registered = new UpstreamToolSchemaSource(upstream).loadInto(registry);

        assertEquals(1, registered);
        assertEquals(1, calls.get());
        assertNotNull(registry.getSchema("typed_tool"));
        assertEquals("integer",
                registry.getSchema("typed_tool").inputSchema().path("properties").path("rows").path("type").asText());
        assertNull(registry.getSchema("not_published"));
    }

    @Test
    @DisplayName("FEAT-012: the manifest is read once and a loaded registry is never refetched")
    void readsManifestOnce() {
        AtomicInteger calls = new AtomicInteger();
        UpstreamClient upstream = (context, request) -> {
            calls.incrementAndGet();
            return CompletableFuture.completedFuture(manifest());
        };
        UpstreamToolSchemaSource source = new UpstreamToolSchemaSource(upstream);
        ToolSchemaRegistry registry = new ToolSchemaRegistry();

        source.loadInto(registry);
        source.loadInto(registry);

        assertEquals(1, calls.get());
    }

    @Test
    @DisplayName("FEAT-012 edge case: an unreachable manifest falls back instead of failing the call")
    void unreachableManifestFallsBack() {
        UpstreamClient upstream = (context, request) ->
                CompletableFuture.failedFuture(new IllegalStateException("upstream unavailable"));
        ToolSchemaRegistry registry = new ToolSchemaRegistry();

        int registered = new UpstreamToolSchemaSource(upstream).loadInto(registry);

        assertEquals(0, registered);
        assertNull(registry.getSchema("typed_tool"));
    }

    @Test
    @DisplayName("FEAT-012: a validated call rejects an argument that violates the published schema")
    void validationUsesThePublishedSchema() throws Exception {
        UpstreamClient upstream = (context, request) -> CompletableFuture.completedFuture(manifest());
        ToolSchemaRegistry registry = new ToolSchemaRegistry();
        UpstreamToolSchemaSource source = new UpstreamToolSchemaSource(upstream);
        DynamicParameterValidator validator = new DynamicParameterValidator(registry, source);

        ObjectNode arguments = mapper.createObjectNode();
        arguments.put("rows", "not-a-number");

        ValidationResult result = validator.validate("agent-1", "typed_tool", arguments);

        assertTrue(!result.isValid(), "A string passed for an integer must be rejected");
        assertEquals(ValidationViolation.Family.SCHEMA, result.primaryFamily());
    }

    private JsonRpcResponse manifest() {
        ObjectNode schema = mapper.createObjectNode();
        schema.put("type", "object");
        ObjectNode properties = schema.putObject("properties");
        properties.putObject("rows").put("type", "integer");
        ObjectNode tool = mapper.createObjectNode();
        tool.put("name", "typed_tool");
        tool.set("inputSchema", schema);
        ObjectNode result = mapper.createObjectNode();
        result.putArray("tools").add(tool);
        return JsonRpcResponse.success(JsonRpcId.of("manifest"), result);
    }

    /** Guards the fixture's shape against the request the source actually sends. */
    @Test
    @DisplayName("FEAT-012: the manifest request is a tools/list call with no agent payload")
    void manifestRequestShape() {
        AtomicInteger calls = new AtomicInteger();
        UpstreamClient upstream = (context, request) -> {
            calls.incrementAndGet();
            assertEquals(JsonRpcRequest.METHOD_TOOLS_LIST, request.method());
            assertNotNull(request.id());
            return CompletableFuture.completedFuture(manifest());
        };

        new UpstreamToolSchemaSource(upstream).loadInto(new ToolSchemaRegistry());

        assertEquals(1, calls.get());
    }
}
