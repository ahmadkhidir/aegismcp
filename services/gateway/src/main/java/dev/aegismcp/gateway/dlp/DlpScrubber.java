package dev.aegismcp.gateway.dlp;

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
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Outbound DLP scrubber service that sanitizes secrets, private keys, database credentials,
 * and personal data from JSON-RPC responses and raw payloads.
 *
 * <p>Raw payloads are parsed only for their JSON string boundaries, never into an object tree: a
 * tree round trip on a 1 MB response costs tens of milliseconds for no security benefit, while the
 * boundary walk keeps numeric values and document structure byte-identical outside the redacted
 * spans. Conforms to contract C-001 with sub-3ms latency overhead per NFR-002.
 *
 * <p>Every scrub has a reporting form that returns a {@link DlpScrubResult}: the sanitized payload
 * plus the detections it replaced. Callers that must account for what was masked — the audit trail
 * and the inspector summary — read the count from that result instead of rescanning.
 * Anchors: FEAT-005, NFR-002, C-001, C-002, C-013.
 */
public class DlpScrubber {

    private static final Logger logger = LoggerFactory.getLogger(DlpScrubber.class);

    /** Replacement emitted when the scanner itself fails; the payload is never forwarded raw. */
    public static final String SCAN_FAILURE_MASK = "[REDACTED_DLP_SCAN_FAILURE]";

    /** Nesting depth beyond which a JSON tree is masked instead of walked. */
    private static final int MAX_JSON_DEPTH = 512;

    private static final class InstanceHolder {
        private static final DlpScrubber DEFAULT_INSTANCE = new DlpScrubber(DlpConfig.defaultConfig());
    }

    private final DlpConfig config;
    private final DlpScanner scanner;
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
        this.scanner = new DlpScanner(this.config);
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
        return redactionEngine.resolveNonOverlapping(scanner.scanText(text));
    }

    /**
     * Redacts secrets and PII from a plain-text string.
     */
    public String scrubText(String input) {
        return scrubTextWithReport(input).payload();
    }

    /**
     * Redacts a plain-text string and reports how many spans were replaced.
     */
    public DlpScrubResult<String> scrubTextWithReport(String input) {
        if (input == null || input.isEmpty()) {
            return DlpScrubResult.unchanged(input);
        }
        List<DlpDetection> detections = redactionEngine.resolveNonOverlapping(scanner.scanText(input));
        if (detections.isEmpty()) {
            return DlpScrubResult.unchanged(input);
        }
        return new DlpScrubResult<>(redactionEngine.applyRedactions(input, detections), detections);
    }

    /**
     * Recursively redacts secrets from a Jackson JsonNode tree while preserving structure,
     * numbers, booleans, arrays, and null nodes.
     *
     * <p>Pathological nesting is masked rather than walked: an iterative overflow here would abort
     * the response after part of it had already been released upstream.
     * Anchors: FEAT-005.
     */
    public JsonNode scrub(JsonNode node) {
        return scrubWithReport(node).payload();
    }

    /**
     * Scrubs a Jackson JsonNode tree and reports every span replaced across its text nodes.
     */
    public DlpScrubResult<JsonNode> scrubWithReport(JsonNode node) {
        List<DlpDetection> detections = new ArrayList<>();
        JsonNode scrubbed = scrubNode(node, 0, detections);
        return new DlpScrubResult<>(scrubbed, detections);
    }

    private JsonNode scrubNode(JsonNode node, int depth, List<DlpDetection> detections) {
        if (node == null || node.isNull()) {
            return node;
        }
        if (depth > MAX_JSON_DEPTH) {
            logger.warn("JSON nesting exceeds {} levels during DLP scrubbing; masking subtree", MAX_JSON_DEPTH);
            return TextNode.valueOf(SCAN_FAILURE_MASK);
        }

        if (node.isTextual()) {
            DlpScrubResult<String> result = scrubTextWithReport(node.asText());
            if (!result.redacted()) {
                return node;
            }
            detections.addAll(result.detections());
            return TextNode.valueOf(result.payload());
        }

        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            ObjectNode scrubbedObject = JsonNodeFactory.instance.objectNode();
            for (Map.Entry<String, JsonNode> entry : objectNode.properties()) {
                scrubbedObject.set(entry.getKey(), scrubNode(entry.getValue(), depth + 1, detections));
            }
            return scrubbedObject;
        }

        if (node.isArray()) {
            ArrayNode arrayNode = (ArrayNode) node;
            ArrayNode scrubbedArray = JsonNodeFactory.instance.arrayNode(arrayNode.size());
            for (int i = 0; i < arrayNode.size(); i++) {
                scrubbedArray.add(scrubNode(arrayNode.get(i), depth + 1, detections));
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
        return scrubWithReport(response).payload();
    }

    /**
     * Scrubs a JSON-RPC 2.0 response and reports how many spans were replaced in its payload.
     */
    public DlpScrubResult<JsonRpcResponse> scrubWithReport(JsonRpcResponse response) {
        if (response == null) {
            return DlpScrubResult.unchanged(null);
        }

        List<DlpDetection> detections = new ArrayList<>();
        if (response.isError()) {
            JsonRpcError err = response.error();
            DlpScrubResult<String> scrubbedMessage = scrubTextWithReport(err.message());
            detections.addAll(scrubbedMessage.detections());
            JsonNode scrubbedData = err.data() != null ? scrubNode(err.data(), 0, detections) : null;
            JsonRpcError scrubbedError = new JsonRpcError(err.code(), scrubbedMessage.payload(), scrubbedData);
            return new DlpScrubResult<>(JsonRpcResponse.error(response.id(), scrubbedError), detections);
        }

        JsonNode scrubbedResult = response.result() != null ? scrubNode(response.result(), 0, detections) : null;
        return new DlpScrubResult<>(JsonRpcResponse.success(response.id(), scrubbedResult), detections);
    }

    /**
     * Redacts a JSON document held as a string, rewriting detected spans inside string values only.
     * A payload that cannot be walked falls back to plain-text scrubbing.
     */
    public String scrubJson(String jsonString) {
        return scrubJsonWithReport(jsonString).payload();
    }

    /**
     * Redacts a JSON document held as a string and reports how many spans were replaced.
     */
    public DlpScrubResult<String> scrubJsonWithReport(String jsonString) {
        if (jsonString == null || jsonString.isEmpty()) {
            return DlpScrubResult.unchanged(jsonString);
        }
        try {
            List<DlpDetection> detections =
                    redactionEngine.resolveNonOverlapping(scanner.scanJsonText(jsonString));
            if (detections.isEmpty()) {
                return DlpScrubResult.unchanged(jsonString);
            }
            return new DlpScrubResult<>(redactionEngine.applyRedactions(jsonString, detections), detections);
        } catch (RuntimeException e) {
            logger.debug("Failed scrubbing JSON payload, falling back to text scrubbing", e);
            return scrubTextWithReport(jsonString);
        }
    }

    /**
     * Sanitizes a raw byte payload. A JSON payload is scanned inside string values only, so numbers
     * keep their JSON type; any other payload is scanned as text.
     */
    public byte[] scrub(byte[] payload) {
        return scrubWithReport(payload).payload();
    }

    /**
     * Sanitizes a raw byte payload and reports how many spans were replaced.
     */
    public DlpScrubResult<byte[]> scrubWithReport(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return DlpScrubResult.unchanged(payload);
        }

        List<DlpDetection> detections;
        if (DlpScanner.looksLikeJson(payload)) {
            detections = scanner.scanJsonBytes(payload);
        } else {
            detections = scanner.scanBytes(payload);
        }

        List<DlpDetection> resolved = redactionEngine.resolveNonOverlapping(detections);
        if (resolved.isEmpty()) {
            return DlpScrubResult.unchanged(payload);
        }
        return new DlpScrubResult<>(redactBytes(payload, resolved), resolved);
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

    /**
     * Copies {@code payload} into a new array, replacing each detected span with its marker.
     */
    private static byte[] redactBytes(byte[] payload, List<DlpDetection> detections) {
        int size = payload.length;
        for (DlpDetection detection : detections) {
            size += detection.replacement().length() - (detection.end() - detection.start());
        }

        byte[] out = new byte[size];
        int read = 0;
        int write = 0;
        for (DlpDetection detection : detections) {
            int copy = detection.start() - read;
            System.arraycopy(payload, read, out, write, copy);
            write += copy;
            byte[] marker = detection.replacement().getBytes(StandardCharsets.ISO_8859_1);
            System.arraycopy(marker, 0, out, write, marker.length);
            write += marker.length;
            read = detection.end();
        }
        System.arraycopy(payload, read, out, write, payload.length - read);
        return out;
    }
}
