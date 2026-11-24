package dev.aegismcp.gateway.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcRequest;

import java.util.Set;

/**
 * Classifies the MCP methods C-001 makes policy-bearing and expresses a non-{@code tools/call}
 * request in the shape the interceptor chain evaluates.
 *
 * <p>C-001 names exactly two policy-evaluated methods: {@code tools/call} and
 * {@code resources/read}. Every other method ({@code initialize}, {@code tools/list}, {@code ping})
 * passes through to the upstream server without a policy decision. The request path must therefore
 * route those two methods through the full identity, parameter-validation, policy, sequence-anomaly,
 * DLP, and audit chain and nothing else.
 *
 * <p>The chain's stages are written against {@code tools/call}: they read {@code params.name} as the
 * policy target and {@code params.arguments} as the constrained payload. A resource read is evaluated
 * by projecting it onto that contract — the policy target is the method name itself
 * ({@code resources/read}) and its {@code params} object (which carries {@code uri}) is the argument
 * set. The projection is used for the decision only; the upstream always receives the original
 * JSON-RPC request, so a resource read is forwarded as a resource read.
 *
 * <p>Anchors: FEAT-001, FEAT-002, FEAT-004, FEAT-012, C-001.
 */
public final class PolicyBearingMethods {

    /** The second policy-evaluated MCP method named by C-001. */
    public static final String METHOD_RESOURCES_READ = "resources/read";

    private static final Set<String> POLICY_BEARING =
            Set.of(JsonRpcRequest.METHOD_TOOLS_CALL, METHOD_RESOURCES_READ);

    private static final String CHAIN_NAME = "name";
    private static final String CHAIN_ARGUMENTS = "arguments";

    private PolicyBearingMethods() {
    }

    /**
     * Whether C-001 makes this request subject to a policy decision. A request with no method is not
     * policy-bearing; the codec refuses it before this point.
     */
    public static boolean isPolicyBearing(JsonRpcRequest request) {
        return request != null && request.method() != null && POLICY_BEARING.contains(request.method());
    }

    /**
     * The name the policy rule is matched against: the tool name for a {@code tools/call}, the method
     * for a {@code resources/read}. Used for logging and audit labels so an operator sees the target
     * the policy actually decided on.
     */
    public static String policyTarget(JsonRpcRequest request) {
        if (request == null) {
            return null;
        }
        if (request.isToolCall()) {
            return request.toolName();
        }
        return isPolicyBearing(request) ? request.method() : null;
    }

    /**
     * Projects a policy-bearing request onto the {@code tools/call} shape every chain stage
     * understands. A {@code tools/call} is returned unchanged; a {@code resources/read} is projected
     * with its method as the policy target and its params as the argument object. Any other method is
     * returned unchanged and is never sent to the chain by the proxy.
     */
    public static JsonRpcRequest toChainRequest(JsonRpcRequest request) {
        if (request == null || request.isToolCall() || !isPolicyBearing(request)) {
            return request;
        }

        JsonNode resourceParams = request.params();
        ObjectNode chainParams = JsonNodeFactory.instance.objectNode();
        chainParams.put(CHAIN_NAME, request.method());
        if (resourceParams == null || resourceParams.isNull()) {
            chainParams.set(CHAIN_ARGUMENTS, JsonNodeFactory.instance.objectNode());
        } else {
            chainParams.set(CHAIN_ARGUMENTS, resourceParams);
        }
        return new JsonRpcRequest(request.id(), JsonRpcRequest.METHOD_TOOLS_CALL, chainParams);
    }
}
