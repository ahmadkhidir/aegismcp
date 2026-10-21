package dev.aegismcp.gateway.codec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import io.netty.buffer.ByteBufOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * High-performance JSON-RPC 2.0 codec supporting streaming Netty buffers and Jackson mapping.
 * Anchors: FEAT-001, C-001.
 */
public class JsonRpcCodec {

    private static final JsonRpcCodec DEFAULT_INSTANCE = new JsonRpcCodec();

    private final ObjectMapper mapper;

    public JsonRpcCodec() {
        this.mapper = new ObjectMapper();
        this.mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public static JsonRpcCodec getInstance() {
        return DEFAULT_INSTANCE;
    }

    public ObjectMapper getMapper() {
        return mapper;
    }

    /**
     * Decodes a JSON-RPC request from raw bytes, strictly enforcing C-001 and JSON-RPC 2.0.
     */
    public JsonRpcRequest decodeRequest(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new JsonRpcCodecException(JsonRpcError.invalidRequest("Request body is empty"));
        }
        try {
            JsonNode root = mapper.readTree(bytes);
            return parseRequestNode(root);
        } catch (JsonProcessingException e) {
            throw new JsonRpcCodecException(JsonRpcError.parseError(e.getOriginalMessage()));
        } catch (IOException e) {
            throw new JsonRpcCodecException(JsonRpcError.parseError(e.getMessage()));
        }
    }

    /**
     * Decodes a JSON-RPC request directly from a Netty ByteBuf without intermediate allocations.
     */
    public JsonRpcRequest decodeRequest(ByteBuf byteBuf) {
        if (byteBuf == null || !byteBuf.isReadable()) {
            throw new JsonRpcCodecException(JsonRpcError.invalidRequest("Request buffer is empty"));
        }
        try (InputStream in = new ByteBufInputStream(byteBuf)) {
            JsonNode root = mapper.readTree(in);
            return parseRequestNode(root);
        } catch (JsonProcessingException e) {
            throw new JsonRpcCodecException(JsonRpcError.parseError(e.getOriginalMessage()));
        } catch (IOException e) {
            throw new JsonRpcCodecException(JsonRpcError.parseError(e.getMessage()));
        }
    }

    /**
     * Decodes a JSON-RPC response from raw bytes.
     */
    public JsonRpcResponse decodeResponse(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new JsonRpcCodecException(JsonRpcError.invalidRequest("Response body is empty"));
        }
        try {
            JsonNode root = mapper.readTree(bytes);
            return parseResponseNode(root);
        } catch (JsonProcessingException e) {
            throw new JsonRpcCodecException(JsonRpcError.parseError(e.getOriginalMessage()));
        } catch (IOException e) {
            throw new JsonRpcCodecException(JsonRpcError.parseError(e.getMessage()));
        }
    }

    /**
     * Decodes a JSON-RPC response directly from a Netty ByteBuf.
     */
    public JsonRpcResponse decodeResponse(ByteBuf byteBuf) {
        if (byteBuf == null || !byteBuf.isReadable()) {
            throw new JsonRpcCodecException(JsonRpcError.invalidRequest("Response buffer is empty"));
        }
        try (InputStream in = new ByteBufInputStream(byteBuf)) {
            JsonNode root = mapper.readTree(in);
            return parseResponseNode(root);
        } catch (JsonProcessingException e) {
            throw new JsonRpcCodecException(JsonRpcError.parseError(e.getOriginalMessage()));
        } catch (IOException e) {
            throw new JsonRpcCodecException(JsonRpcError.parseError(e.getMessage()));
        }
    }

    /**
     * Encodes a JSON-RPC message into UTF-8 bytes.
     */
    public byte[] encode(JsonRpcMessage message) {
        try {
            return mapper.writeValueAsBytes(message);
        } catch (JsonProcessingException e) {
            throw new JsonRpcCodecException(message.id(), JsonRpcError.internalError("Serialization failure: " + e.getMessage()));
        }
    }

    /**
     * Encodes a JSON-RPC message directly into a destination Netty ByteBuf.
     */
    public void encode(JsonRpcMessage message, ByteBuf out) {
        try (ByteBufOutputStream os = new ByteBufOutputStream(out)) {
            mapper.writeValue((java.io.OutputStream) os, message);
        } catch (IOException e) {
            throw new JsonRpcCodecException(message.id(), JsonRpcError.internalError("Serialization failure: " + e.getMessage()));
        }
    }

    private JsonRpcRequest parseRequestNode(JsonNode root) {
        if (!root.isObject()) {
            throw new JsonRpcCodecException(JsonRpcError.invalidRequest("JSON-RPC request must be a JSON object"));
        }

        JsonRpcId id = extractId(root);

        JsonNode versionNode = root.get("jsonrpc");
        if (versionNode == null || !JsonRpcMessage.JSONRPC_VERSION.equals(versionNode.asText())) {
            throw new JsonRpcCodecException(id, JsonRpcError.invalidRequest("Missing or invalid 'jsonrpc' version; must be '2.0'"));
        }

        JsonNode methodNode = root.get("method");
        if (methodNode == null || !methodNode.isTextual() || methodNode.asText().isBlank()) {
            throw new JsonRpcCodecException(id, JsonRpcError.invalidRequest("Missing or invalid 'method' property"));
        }

        String method = methodNode.asText();
        JsonNode params = root.get("params");

        return new JsonRpcRequest(JsonRpcMessage.JSONRPC_VERSION, id, method, params);
    }

    private JsonRpcResponse parseResponseNode(JsonNode root) {
        if (!root.isObject()) {
            throw new JsonRpcCodecException(JsonRpcError.invalidRequest("JSON-RPC response must be a JSON object"));
        }

        JsonRpcId id = extractId(root);

        JsonNode versionNode = root.get("jsonrpc");
        if (versionNode == null || !JsonRpcMessage.JSONRPC_VERSION.equals(versionNode.asText())) {
            throw new JsonRpcCodecException(id, JsonRpcError.invalidRequest("Missing or invalid 'jsonrpc' version; must be '2.0'"));
        }

        JsonNode resultNode = root.get("result");
        JsonNode errorNode = root.get("error");

        JsonRpcError error = null;
        if (errorNode != null && !errorNode.isNull()) {
            int code = errorNode.has("code") ? errorNode.get("code").asInt() : JsonRpcError.INTERNAL_ERROR;
            String message = errorNode.has("message") ? errorNode.get("message").asText() : "Unknown error";
            JsonNode data = errorNode.get("data");
            error = new JsonRpcError(code, message, data);
        }

        return new JsonRpcResponse(JsonRpcMessage.JSONRPC_VERSION, id, resultNode, error);
    }

    private JsonRpcId extractId(JsonNode root) {
        if (!root.has("id")) {
            return JsonRpcId.nullId();
        }
        JsonNode idNode = root.get("id");
        if (idNode.isTextual()) {
            return JsonRpcId.of(idNode.asText());
        } else if (idNode.isNumber()) {
            return JsonRpcId.of(idNode.asLong());
        } else if (idNode.isNull()) {
            return JsonRpcId.nullId();
        } else {
            return JsonRpcId.nullId();
        }
    }

    public ObjectNode createObjectNode() {
        return mapper.createObjectNode();
    }
}
