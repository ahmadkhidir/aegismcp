package dev.aegismcp.gateway.dlp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Outbound DLP scrubber service that sanitizes secrets, private keys, database credentials,
 * and personal data from JSON-RPC responses and raw payloads.
 * Conforms to contract C-001 with sub-3ms latency overhead per NFR-002.
 * Anchors: FEAT-005, NFR-002, C-001.
 */
public class DlpScrubber {

    private static final Logger logger = LoggerFactory.getLogger(DlpScrubber.class);

    private static final class InstanceHolder {
        private static final DlpScrubber DEFAULT_INSTANCE = new DlpScrubber(DlpConfig.defaultConfig());
    }

    private final DlpConfig config;
    private final DlpPatternMatcher patternMatcher;
    private final ShannonEntropyScanner entropyScanner;
    private final DlpRedactionEngine redactionEngine;
    private final ObjectMapper objectMapper;

    public DlpScrubber() {
        this(DlpConfig.defaultConfig());
    }

    public DlpScrubber(DlpConfig config) {
        this(config, JsonRpcCodec.getInstance().getMapper());
    }

    public DlpScrubber(DlpConfig config, ObjectMapper objectMapper) {
        this.config = Objects.requireNonNull(config, "config must not be null");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.patternMatcher = new DlpPatternMatcher(this.config);
        this.entropyScanner = new ShannonEntropyScanner(this.config);
        this.redactionEngine = new DlpRedactionEngine();
    }

    public static DlpScrubber getInstance() {
        return InstanceHolder.DEFAULT_INSTANCE;
    }

    public DlpConfig getConfig() {
        return config;
    }

    /**
     * Scans input text and returns all non-overlapping detections.
     */
    public List<DlpDetection> scan(String text) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        List<DlpDetection> regexDetections = patternMatcher.scan(text);
        List<DlpDetection> entropyDetections = entropyScanner.scan(text);

        List<DlpDetection> combined = new ArrayList<>(regexDetections.size() + entropyDetections.size());
        combined.addAll(regexDetections);
        combined.addAll(entropyDetections);

        return redactionEngine.resolveNonOverlapping(combined);
    }

    /**
     * Redacts secrets and PII from a plain-text string.
     */
    public String scrubText(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        List<DlpDetection> detections = scan(input);
        if (detections.isEmpty()) {
            return input;
        }
        return redactionEngine.applyRedactions(input, detections);
    }

    /**
     * Recursively redacts secrets from a Jackson JsonNode tree while preserving structure,
     * numbers, booleans, arrays, and null nodes.
     */
    public JsonNode scrub(JsonNode node) {
        if (node == null || node.isNull()) {
            return node;
        }

        if (node.isTextual()) {
            String original = node.asText();
            String scrubbed = scrubText(original);
            return original.equals(scrubbed) ? node : TextNode.valueOf(scrubbed);
        }

        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            ObjectNode scrubbedObject = JsonNodeFactory.instance.objectNode();
            Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String fieldName = entry.getKey();
                JsonNode childNode = entry.getValue();
                scrubbedObject.set(fieldName, scrub(childNode));
            }
            return scrubbedObject;
        }

        if (node.isArray()) {
            ArrayNode arrayNode = (ArrayNode) node;
            ArrayNode scrubbedArray = JsonNodeFactory.instance.arrayNode(arrayNode.size());
            for (int i = 0; i < arrayNode.size(); i++) {
                scrubbedArray.add(scrub(arrayNode.get(i)));
            }
            return scrubbedArray;
        }

        // IntNode, LongNode, DoubleNode, BooleanNode, etc. remain unchanged
        return node;
    }

    /**
     * Sanitizes a JSON-RPC 2.0 response object, scrubbing result and error payloads
     * while strictly preserving response id. Conforms to C-001.
     */
    public JsonRpcResponse scrub(JsonRpcResponse response) {
        if (response == null) {
            return null;
        }

        if (response.isError()) {
            JsonRpcError err = response.error();
            String scrubbedMessage = scrubText(err.message());
            JsonNode scrubbedData = err.data() != null ? scrub(err.data()) : null;
            JsonRpcError scrubbedError = new JsonRpcError(err.code(), scrubbedMessage, scrubbedData);
            return JsonRpcResponse.error(response.id(), scrubbedError);
        }

        JsonNode scrubbedResult = response.result() != null ? scrub(response.result()) : null;
        return JsonRpcResponse.success(response.id(), scrubbedResult);
    }

    /**
     * Parses and redacts a JSON string. If JSON parsing fails, falls back to plain-text scrubbing.
     */
    public String scrubJson(String jsonString) {
        if (jsonString == null || jsonString.isEmpty()) {
            return jsonString;
        }
        try {
            JsonNode root = objectMapper.readTree(jsonString);
            JsonNode scrubbed = scrub(root);
            return objectMapper.writeValueAsString(scrubbed);
        } catch (JsonProcessingException e) {
            logger.debug("Failed parsing JSON payload for tree scrubbing, falling back to text scrubbing", e);
            return scrubText(jsonString);
        }
    }

    /**
     * Sanitizes a raw byte payload.
     */
    public byte[] scrub(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return payload;
        }

        // Check if starts with JSON object or array
        int firstNonWs = 0;
        while (firstNonWs < payload.length && Character.isWhitespace((char) payload[firstNonWs])) {
            firstNonWs++;
        }

        if (firstNonWs < payload.length && (payload[firstNonWs] == '{' || payload[firstNonWs] == '[')) {
            try {
                JsonNode root = objectMapper.readTree(payload);
                JsonNode scrubbed = scrub(root);
                return objectMapper.writeValueAsBytes(scrubbed);
            } catch (Exception e) {
                logger.debug("Could not parse byte payload as JSON tree, falling back to text bytes", e);
            }
        }

        String rawText = new String(payload, StandardCharsets.UTF_8);
        String scrubbedText = scrubText(rawText);
        return scrubbedText.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Sanitizes a Netty ByteBuf payload and returns a new ByteBuf.
     */
    public ByteBuf scrub(ByteBuf input, ByteBufAllocator alloc) {
        if (input == null || !input.isReadable()) {
            return input != null ? input.retainedSlice() : Unpooled.EMPTY_BUFFER;
        }

        byte[] bytes = ByteBufUtil.getBytes(input);
        byte[] scrubbedBytes = scrub(bytes);

        ByteBuf result = alloc.buffer(scrubbedBytes.length);
        result.writeBytes(scrubbedBytes);
        return result;
    }

    /**
     * Sanitizes a Netty FullHttpResponse before sending back to an MCP client.
     * Updates Content-Length and replaces payload buffer.
     */
    public FullHttpResponse scrubHttpResponse(FullHttpResponse response, ByteBufAllocator alloc) {
        if (response == null || !response.content().isReadable()) {
            return response;
        }

        ByteBuf scrubbedContent = scrub(response.content(), alloc);
        FullHttpResponse scrubbedResponse = response.replace(scrubbedContent);
        scrubbedResponse.headers().set(HttpHeaderNames.CONTENT_LENGTH, scrubbedContent.readableBytes());
        return scrubbedResponse;
    }
}
