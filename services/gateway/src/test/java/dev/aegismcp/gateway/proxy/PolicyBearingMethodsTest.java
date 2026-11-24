package dev.aegismcp.gateway.proxy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * C-001 names exactly two policy-evaluated MCP methods. These tests pin the classification and the
 * projection the proxy uses to evaluate a resource read through the shared tool-call chain.
 *
 * <p>Anchors: FEAT-001, FEAT-002, C-001.
 */
class PolicyBearingMethodsTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private JsonRpcRequest request(String method, ObjectNode params) {
        return new JsonRpcRequest(JsonRpcId.of("req-1"), method, params);
    }

    @Test
    @DisplayName("C-001: only tools/call and resources/read are policy-bearing")
    void classifiesOnlyTheTwoContractMethods() {
        assertTrue(PolicyBearingMethods.isPolicyBearing(
                request(JsonRpcRequest.METHOD_TOOLS_CALL, mapper.createObjectNode())));
        assertTrue(PolicyBearingMethods.isPolicyBearing(
                request(PolicyBearingMethods.METHOD_RESOURCES_READ, mapper.createObjectNode())));

        assertFalse(PolicyBearingMethods.isPolicyBearing(request("initialize", mapper.createObjectNode())));
        assertFalse(PolicyBearingMethods.isPolicyBearing(request("tools/list", mapper.createObjectNode())));
        assertFalse(PolicyBearingMethods.isPolicyBearing(request("resources/list", mapper.createObjectNode())));
        assertFalse(PolicyBearingMethods.isPolicyBearing(request("ping", mapper.createObjectNode())));
        assertFalse(PolicyBearingMethods.isPolicyBearing(null));
    }

    @Test
    @DisplayName("C-001: a tools/call is handed to the chain unchanged")
    void toolCallIsNotProjected() {
        ObjectNode params = mapper.createObjectNode();
        params.put("name", "read_file");
        ObjectNode arguments = mapper.createObjectNode();
        arguments.put("path", "/workspace/a.txt");
        params.set("arguments", arguments);
        JsonRpcRequest toolCall = request(JsonRpcRequest.METHOD_TOOLS_CALL, params);

        assertSame(toolCall, PolicyBearingMethods.toChainRequest(toolCall));
        assertEquals("read_file", PolicyBearingMethods.policyTarget(toolCall));
    }

    @Test
    @DisplayName("C-001: a resources/read is projected with its method as target and its params as arguments")
    void resourceReadIsProjectedOntoTheToolCallContract() {
        ObjectNode params = mapper.createObjectNode();
        params.put("uri", "file:///workspace/report.txt");
        JsonRpcRequest resourceRead = request(PolicyBearingMethods.METHOD_RESOURCES_READ, params);

        JsonRpcRequest chainRequest = PolicyBearingMethods.toChainRequest(resourceRead);

        assertEquals(JsonRpcRequest.METHOD_TOOLS_CALL, chainRequest.method());
        assertEquals(resourceRead.id(), chainRequest.id(), "the request id is preserved for the answer");
        assertEquals(PolicyBearingMethods.METHOD_RESOURCES_READ, chainRequest.toolName());
        assertEquals("file:///workspace/report.txt", chainRequest.toolArguments().path("uri").asText());
        assertEquals(PolicyBearingMethods.METHOD_RESOURCES_READ, PolicyBearingMethods.policyTarget(resourceRead));
    }

    @Test
    @DisplayName("C-001: a resources/read without params is projected with an empty argument object")
    void resourceReadWithoutParamsStillHasAnArgumentObject() {
        JsonRpcRequest chainRequest = PolicyBearingMethods.toChainRequest(
                request(PolicyBearingMethods.METHOD_RESOURCES_READ, null));

        assertEquals(JsonRpcRequest.METHOD_TOOLS_CALL, chainRequest.method());
        assertTrue(chainRequest.toolArguments().isObject());
        assertTrue(chainRequest.toolArguments().isEmpty());
    }

    @Test
    @DisplayName("C-001: a non-policy-bearing method has no policy target and is not projected")
    void passThroughMethodHasNoPolicyTarget() {
        JsonRpcRequest toolsList = request("tools/list", mapper.createObjectNode());

        assertSame(toolsList, PolicyBearingMethods.toChainRequest(toolsList));
        assertNull(PolicyBearingMethods.policyTarget(toolsList));
    }
}
