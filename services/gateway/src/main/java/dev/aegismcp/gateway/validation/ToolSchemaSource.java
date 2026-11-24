package dev.aegismcp.gateway.validation;

/**
 * Source of the JSON schemas the target MCP server publishes for its tools.
 *
 * <p>FEAT-012 validates arguments against the tool's <em>published</em> schema and names the MCP
 * server manifest as that source, so the gateway learns the schemas from the server it proxies
 * rather than from a table maintained inside the gateway. A missing or unreadable manifest is the
 * FEAT-012 edge case: the validator falls back to its generic checks instead of refusing every call.
 *
 * <p>Anchors: FEAT-012, NFR-024.
 */
public interface ToolSchemaSource {

    /**
     * Registers every schema the source publishes into {@code registry}.
     *
     * @return the number of schemas registered, or {@code 0} when the source could not be read
     */
    int loadInto(ToolSchemaRegistry registry);

    /** A source that publishes nothing, for an assembly with no upstream to ask. */
    static ToolSchemaSource empty() {
        return registry -> 0;
    }
}
