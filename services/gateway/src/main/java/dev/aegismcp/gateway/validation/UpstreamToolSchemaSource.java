package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.SecurityContext;
import dev.aegismcp.gateway.proxy.UpstreamClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Reads the tool manifest the upstream MCP server publishes through {@code tools/list} and registers
 * each tool's {@code inputSchema} for pre-execution validation (FEAT-012).
 *
 * <p>The manifest is fetched once and cached in the registry. A fetch is attempted only when a tool
 * the registry does not know is validated, and only one fetch runs at a time: a caller that arrives
 * while a fetch is in flight proceeds with the generic checks instead of waiting, and a failed fetch
 * is retried after a cooldown rather than on every call. A failed or empty manifest is the FEAT-012
 * edge case, not a refusal.
 *
 * <p>The manifest request carries no agent credential and no request payload; the upstream sees only
 * the method, exactly as it does for a forwarded call (FEAT-009, NFR-027).
 *
 * <p>Anchors: FEAT-012, NFR-024, C-001.
 */
public final class UpstreamToolSchemaSource implements ToolSchemaSource {

    private static final Logger logger = LoggerFactory.getLogger(UpstreamToolSchemaSource.class);

    /** How long a failed or empty manifest read suppresses the next attempt. */
    static final Duration RETRY_COOLDOWN = Duration.ofSeconds(30);

    private static final String MANIFEST_REQUEST_ID = "aegis-tools-list";

    private final UpstreamClient upstreamClient;
    private final AtomicBoolean fetching = new AtomicBoolean(false);

    private volatile boolean loaded = false;
    private volatile Instant lastAttempt = Instant.EPOCH;

    public UpstreamToolSchemaSource(UpstreamClient upstreamClient) {
        this.upstreamClient = Objects.requireNonNull(upstreamClient, "upstreamClient must not be null");
    }

    @Override
    public int loadInto(ToolSchemaRegistry registry) {
        if (registry == null || loaded || !retryWindowElapsed()) {
            return 0;
        }
        if (!fetching.compareAndSet(false, true)) {
            // Another request is already reading the manifest; use the generic checks meanwhile.
            return 0;
        }
        try {
            lastAttempt = Instant.now();
            int registered = fetchAndRegister(registry);
            if (registered > 0) {
                loaded = true;
                logger.info("Loaded {} published tool schema(s) from the upstream MCP server", registered);
            } else {
                logger.warn("The upstream MCP server published no usable tool schema; "
                        + "falling back to generic parameter checks (FEAT-012)");
            }
            return registered;
        } catch (RuntimeException e) {
            logger.warn("The upstream MCP tool manifest could not be read; "
                    + "falling back to generic parameter checks (FEAT-012)", e);
            return 0;
        } finally {
            fetching.set(false);
        }
    }

    private boolean retryWindowElapsed() {
        return Instant.now().isAfter(lastAttempt.plus(RETRY_COOLDOWN));
    }

    private int fetchAndRegister(ToolSchemaRegistry registry) {
        JsonRpcRequest manifestRequest = new JsonRpcRequest(
                JsonRpcId.of(MANIFEST_REQUEST_ID),
                JsonRpcRequest.METHOD_TOOLS_LIST,
                JsonNodeFactory.instance.objectNode());
        JsonRpcResponse response;
        try {
            response = upstreamClient
                    .forward(SecurityContext.of(AgentIdentity.anonymous(), null), manifestRequest)
                    .join();
        } catch (CompletionException e) {
            throw e.getCause() instanceof RuntimeException runtime ? runtime : e;
        }

        if (response == null || response.isError() || response.result() == null) {
            return 0;
        }
        JsonNode tools = response.result().get("tools");
        if (tools == null || !tools.isArray()) {
            return 0;
        }

        int registered = 0;
        for (JsonNode tool : tools) {
            String name = tool.path("name").asText(null);
            if (name == null || name.isBlank()) {
                continue;
            }
            registry.registerSchema(name, tool.get("inputSchema"));
            registered++;
        }
        return registered;
    }
}
