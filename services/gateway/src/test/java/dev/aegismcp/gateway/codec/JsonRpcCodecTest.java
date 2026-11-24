package dev.aegismcp.gateway.codec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for JSON-RPC 2.0 streaming codec and Netty HTTP handlers.
 * Anchors: FEAT-001, C-001.
 */
class JsonRpcCodecTest {

    private JsonRpcCodec codec;

    @BeforeEach
    void setUp() {
        codec = new JsonRpcCodec();
    }

    @Test
    @DisplayName("FEAT-001 / C-001: Parse valid tools/call request with numeric ID")
    void testParseValidToolCallWithNumericId() {
        String json = """
                {
                  "jsonrpc": "2.0",
                  "id": 1001,
                  "method": "tools/call",
                  "params": {
                    "name": "read_file",
                    "arguments": {
                      "path": "/etc/hosts"
                    }
                  }
                }
                """;

        JsonRpcRequest request = codec.decodeRequest(json.getBytes(StandardCharsets.UTF_8));
        assertNotNull(request);
        assertEquals("2.0", request.jsonrpc());
        assertTrue(request.id() instanceof JsonRpcId.NumberId);
        assertEquals(1001L, ((JsonRpcId.NumberId) request.id()).numberValue());
        assertEquals("tools/call", request.method());
        assertTrue(request.isToolCall());
        assertEquals("read_file", request.toolName());
        assertNotNull(request.toolArguments());
        assertEquals("/etc/hosts", request.toolArguments().get("path").asText());
        assertFalse(request.isNotification());
    }

    @Test
    @DisplayName("FEAT-001 / C-001: Parse valid tools/call request with string ID")
    void testParseValidToolCallWithStringId() {
        String json = """
                {
                  "jsonrpc": "2.0",
                  "id": "req-xyz-42",
                  "method": "tools/call",
                  "params": {
                    "name": "execute_query",
                    "arguments": {
                      "sql": "SELECT 1"
                    }
                  }
                }
                """;

        JsonRpcRequest request = codec.decodeRequest(json.getBytes(StandardCharsets.UTF_8));
        assertNotNull(request);
        assertTrue(request.id() instanceof JsonRpcId.StringId);
        assertEquals("req-xyz-42", ((JsonRpcId.StringId) request.id()).stringValue());
        assertEquals("execute_query", request.toolName());
    }

    @Test
    @DisplayName("FEAT-001: Reject malformed JSON with -32700 Parse error")
    void testMalformedJsonReturnsParseError() {
        String malformedJson = "{ \"jsonrpc\": \"2.0\", \"id\": 1, \"method\": ";

        JsonRpcCodecException ex = assertThrows(JsonRpcCodecException.class, () ->
                codec.decodeRequest(malformedJson.getBytes(StandardCharsets.UTF_8))
        );

        assertEquals(JsonRpcError.PARSE_ERROR, ex.getError().code());
        assertEquals(HttpResponseStatus.BAD_REQUEST, ex.getHttpStatus());
    }

    @Test
    @DisplayName("FEAT-001: Reject missing jsonrpc version with -32600 Invalid Request")
    void testMissingJsonRpcVersion() {
        String json = """
                {
                  "id": 1,
                  "method": "tools/list"
                }
                """;

        JsonRpcCodecException ex = assertThrows(JsonRpcCodecException.class, () ->
                codec.decodeRequest(json.getBytes(StandardCharsets.UTF_8))
        );

        assertEquals(JsonRpcError.INVALID_REQUEST, ex.getError().code());
        assertTrue(ex.getError().message().contains("jsonrpc"));
    }

    @Test
    @DisplayName("C-001: a request without an id is -32600 INVALID_REQUEST and is never forwarded")
    void testMissingIdIsInvalidRequest() {
        String json = """
                {
                  "jsonrpc": "2.0",
                  "method": "ping"
                }
                """;

        JsonRpcCodecException ex = assertThrows(JsonRpcCodecException.class, () ->
                codec.decodeRequest(json.getBytes(StandardCharsets.UTF_8))
        );

        assertEquals(JsonRpcError.INVALID_REQUEST, ex.getError().code());
        assertEquals(JsonRpcError.MACHINE_INVALID_REQUEST, ex.getError().machineCode());
        assertTrue(ex.getError().message().contains("id"));
    }

    @Test
    @DisplayName("C-001: a null or structured id is -32600 INVALID_REQUEST")
    void testInvalidIdIsInvalidRequest() {
        for (String json : new String[]{
                "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}",
                "{\"jsonrpc\":\"2.0\",\"id\":{\"nested\":1},\"method\":\"ping\"}"}) {
            JsonRpcCodecException ex = assertThrows(JsonRpcCodecException.class, () ->
                    codec.decodeRequest(json.getBytes(StandardCharsets.UTF_8)));
            assertEquals(JsonRpcError.INVALID_REQUEST, ex.getError().code());
            assertEquals(JsonRpcError.MACHINE_INVALID_REQUEST, ex.getError().machineCode());
        }
    }

    @Test
    @DisplayName("FEAT-001: Reject missing method with -32600 Invalid Request")
    void testMissingMethod() {
        String json = """
                {
                  "jsonrpc": "2.0",
                  "id": 1
                }
                """;

        JsonRpcCodecException ex = assertThrows(JsonRpcCodecException.class, () ->
                codec.decodeRequest(json.getBytes(StandardCharsets.UTF_8))
        );

        assertEquals(JsonRpcError.INVALID_REQUEST, ex.getError().code());
        assertTrue(ex.getError().message().contains("method"));
    }

    @Test
    @DisplayName("FEAT-001 / C-001: Encode and decode JsonRpcResponse preserving exact ID")
    void testEncodeAndDecodeResponse() {
        ObjectNode result = codec.createObjectNode();
        result.put("status", "success");
        result.put("bytesRead", 1024);

        JsonRpcResponse response = JsonRpcResponse.success(JsonRpcId.of("client-req-99"), result);
        byte[] encoded = codec.encode(response);

        JsonRpcResponse decoded = codec.decodeResponse(encoded);
        assertEquals("2.0", decoded.jsonrpc());
        assertTrue(decoded.id() instanceof JsonRpcId.StringId);
        assertEquals("client-req-99", ((JsonRpcId.StringId) decoded.id()).stringValue());
        assertTrue(decoded.isSuccess());
        assertFalse(decoded.isError());
        assertEquals("success", decoded.result().get("status").asText());
    }

    @Test
    @DisplayName("C-001: Error status code mapping for all contract errors")
    void testContractErrorHttpStatusMapping() {
        assertEquals(HttpResponseStatus.UNAUTHORIZED, JsonRpcError.authenticationFailed("test").toHttpStatus());
        assertEquals(HttpResponseStatus.FORBIDDEN, JsonRpcError.policyViolation("test").toHttpStatus());
        assertEquals(HttpResponseStatus.REQUEST_TIMEOUT, JsonRpcError.approvalTimedOut("test").toHttpStatus());
        assertEquals(HttpResponseStatus.TOO_MANY_REQUESTS, JsonRpcError.rateLimited("test").toHttpStatus());
        assertEquals(HttpResponseStatus.BAD_GATEWAY, JsonRpcError.upstreamUnavailable("test").toHttpStatus());
        assertEquals(HttpResponseStatus.BAD_REQUEST, JsonRpcError.invalidRequest("test").toHttpStatus());
        assertEquals(HttpResponseStatus.BAD_REQUEST, JsonRpcError.parseError("test").toHttpStatus());
        assertEquals(HttpResponseStatus.INTERNAL_SERVER_ERROR, JsonRpcError.internalError("test").toHttpStatus());
    }

    @Test
    @DisplayName("C-001: a success response serializes exactly jsonrpc, id, and result")
    void testSuccessResponseCarriesNoExtraFields() throws Exception {
        ObjectNode result = codec.createObjectNode();
        result.put("content", "ok");
        JsonRpcResponse response = JsonRpcResponse.success(JsonRpcId.of(7), result);

        JsonNode encoded = codec.getMapper().readTree(codec.encode(response));

        assertEquals(java.util.Set.of("jsonrpc", "id", "result"), fieldNames(encoded));
        assertFalse(encoded.has("success"), "the response must not carry a success field");
        assertFalse(encoded.has("error"));
        assertEquals(7, encoded.get("id").asInt());
    }

    @Test
    @DisplayName("C-001: an upstream failure is -32603 with machine code UPSTREAM_UNAVAILABLE")
    void testUpstreamFailureUsesContractCodeAndMachineCode() throws Exception {
        JsonRpcError error = JsonRpcError.upstreamUnavailable("did not answer");

        assertEquals(JsonRpcError.INTERNAL_ERROR, error.code());
        assertEquals(JsonRpcError.MACHINE_UPSTREAM_UNAVAILABLE, error.machineCode());
        assertEquals(HttpResponseStatus.BAD_GATEWAY, error.toHttpStatus());

        JsonRpcResponse response = JsonRpcResponse.error(JsonRpcId.of("req-1"), error);
        JsonNode encoded = codec.getMapper().readTree(codec.encode(response));

        assertEquals(java.util.Set.of("jsonrpc", "id", "error"), fieldNames(encoded));
        assertEquals(JsonRpcError.INTERNAL_ERROR, encoded.get("error").get("code").asInt());
        assertEquals(JsonRpcError.MACHINE_UPSTREAM_UNAVAILABLE,
                encoded.get("error").get("data").get("code").asText());
    }

    @Test
    @DisplayName("C-001: a forwarded request serializes exactly jsonrpc, id, method, and params")
    void testRequestCarriesNoExtraFields() throws Exception {
        ObjectNode params = codec.createObjectNode();
        params.put("name", "read_file");
        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of(11), "tools/call", params);

        JsonNode encoded = codec.getMapper().readTree(codec.encode(request));

        assertEquals(java.util.Set.of("jsonrpc", "id", "method", "params"), fieldNames(encoded));
        assertFalse(encoded.has("toolCall"));
        assertFalse(encoded.has("notification"));
    }

    @Test
    @DisplayName("C-001: an error response serializes exactly code, message, and data")
    void testErrorObjectCarriesNoExtraFields() throws Exception {
        JsonRpcResponse response = JsonRpcResponse.error(JsonRpcId.of(3),
                JsonRpcError.policyViolation("denied"));

        JsonNode encoded = codec.getMapper().readTree(codec.encode(response));

        assertEquals(java.util.Set.of("jsonrpc", "id", "error"), fieldNames(encoded));
        assertEquals(java.util.Set.of("code", "message", "data"), fieldNames(encoded.get("error")));
    }

    private static java.util.Set<String> fieldNames(JsonNode node) {
        java.util.Set<String> names = new java.util.HashSet<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    @Test
    @DisplayName("FEAT-001 / C-001: HttpJsonRpcDecoder decodes valid POST /mcp/v1/rpc")
    void testHttpJsonRpcDecoderSuccess() {
        HttpJsonRpcDecoder decoder = new HttpJsonRpcDecoder();
        EmbeddedChannel channel = new EmbeddedChannel(decoder);

        String payload = """
                {
                  "jsonrpc": "2.0",
                  "id": 55,
                  "method": "tools/list"
                }
                """;
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "/mcp/v1/rpc",
                Unpooled.wrappedBuffer(payload.getBytes(StandardCharsets.UTF_8))
        );
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");

        assertTrue(channel.writeInbound(request));
        JsonRpcRequest decoded = channel.readInbound();
        assertNotNull(decoded);
        assertEquals(55L, ((JsonRpcId.NumberId) decoded.id()).numberValue());
        assertEquals("tools/list", decoded.method());
    }

    @Test
    @DisplayName("FEAT-001 / C-001: HttpJsonRpcDecoder intercepts malformed JSON and writes 400 error")
    void testHttpJsonRpcDecoderMalformedError() {
        HttpJsonRpcDecoder decoder = new HttpJsonRpcDecoder();
        EmbeddedChannel channel = new EmbeddedChannel(decoder);

        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "/mcp/v1/rpc",
                Unpooled.wrappedBuffer("not json".getBytes(StandardCharsets.UTF_8))
        );

        assertFalse(channel.writeInbound(request));
        FullHttpResponse response = channel.readOutbound();
        assertNotNull(response);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());

        byte[] body = new byte[response.content().readableBytes()];
        response.content().readBytes(body);
        JsonRpcResponse errResponse = codec.decodeResponse(body);
        assertTrue(errResponse.isError());
        assertEquals(JsonRpcError.PARSE_ERROR, errResponse.error().code());
    }

    @Test
    @DisplayName("FEAT-001: StreamingJsonRpcFrameDecoder parses newline-delimited frames")
    void testStreamingJsonRpcFrameDecoder() {
        StreamingJsonRpcFrameDecoder frameDecoder = new StreamingJsonRpcFrameDecoder();
        EmbeddedChannel channel = new EmbeddedChannel(frameDecoder);

        String line1 = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        String line2 = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\r\n";

        ByteBuf inBuf = Unpooled.wrappedBuffer((line1 + line2).getBytes(StandardCharsets.UTF_8));
        assertTrue(channel.writeInbound(inBuf));

        JsonRpcRequest req1 = channel.readInbound();
        assertNotNull(req1);
        assertEquals("ping", req1.method());
        assertEquals(1L, ((JsonRpcId.NumberId) req1.id()).numberValue());

        JsonRpcRequest req2 = channel.readInbound();
        assertNotNull(req2);
        assertEquals("tools/list", req2.method());
        assertEquals(2L, ((JsonRpcId.NumberId) req2.id()).numberValue());
    }
}
