package dev.aegismcp.gateway.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying Contract C-007 Netty HTTP verification endpoint.
 * Anchors: C-007, FEAT-007.
 */
class AuditVerificationHandlerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private AuditLedger ledger;
    private AuditVerificationHandler handler;
    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        ledger = new AuditLedger(1);
        // Seed 5 blocks
        for (int i = 1; i <= 5; i++) {
            ledger.appendSync(AuditRecord.create("agent-" + i, "tool_" + i, "allow", 0, 1.0, "arg=" + i));
        }
        handler = new AuditVerificationHandler(ledger);
        channel = new EmbeddedChannel(handler);
    }

    @AfterEach
    void tearDown() {
        if (ledger != null) {
            ledger.close();
        }
        if (channel != null) {
            channel.close();
        }
    }

    private FullHttpResponse sendRequest(HttpMethod method, String uri, String authHeader) {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                method,
                uri,
                Unpooled.EMPTY_BUFFER
        );
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        request.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
        if (authHeader != null) {
            request.headers().set(HttpHeaderNames.AUTHORIZATION, authHeader);
        }

        channel.writeInbound(request);
        return channel.readOutbound();
    }

    private JsonNode parseBody(FullHttpResponse response) throws Exception {
        byte[] bytes = new byte[response.content().readableBytes()];
        response.content().readBytes(bytes);
        return mapper.readTree(bytes);
    }

    @Test
    @DisplayName("C-007: GET /api/v1/audit/verify without auth header returns 401 Unauthorized")
    void testVerifyWithoutAuthReturnsUnauthorized() throws Exception {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/audit/verify", null);

        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
        JsonNode body = parseBody(response);
        assertTrue(body.has("error"));
        assertTrue(body.get("error").asText().contains("Missing authentication credentials"));
    }

    @Test
    @DisplayName("C-007: GET /api/v1/audit/verify with viewer role token returns 403 Forbidden")
    void testVerifyWithViewerTokenReturnsForbidden() throws Exception {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/audit/verify", "Bearer viewer-token-xyz");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
        JsonNode body = parseBody(response);
        assertTrue(body.has("error"));
        assertTrue(body.get("error").asText().contains("Insufficient permissions"));
    }

    @Test
    @DisplayName("C-007: GET /api/v1/audit/verify with auditor token returns 200 OK and valid chain result")
    void testVerifyValidEntireChain() throws Exception {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/audit/verify", "Bearer auditor-token-123");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode body = parseBody(response);
        assertTrue(body.has("valid"));
        assertTrue(body.get("valid").asBoolean());
        assertTrue(body.has("checkedBlocks"));
        assertEquals(6, body.get("checkedBlocks").asLong()); // blocks 0 through 5
        assertTrue(body.has("merkleRoot"));
        assertFalse(body.get("merkleRoot").isNull());
        assertEquals(ledger.getLatestBlock().getPayloadHash(), body.get("merkleRoot").asText());
        assertTrue(body.has("latestBlockHash"));
        assertEquals(ledger.getLatestBlock().getBlockHash(), body.get("latestBlockHash").asText());
        assertTrue(body.has("brokenAtBlock"));
        assertTrue(body.get("brokenAtBlock").isNull());
    }

    @Test
    @DisplayName("C-007: GET /api/v1/audit/verify with query params ?fromBlock=2&toBlock=4 checks range")
    void testVerifySpecificBlockRange() throws Exception {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/audit/verify?fromBlock=2&toBlock=4", "Bearer auditor-token-123");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode body = parseBody(response);
        assertTrue(body.get("valid").asBoolean());
        assertEquals(3, body.get("checkedBlocks").asLong()); // 4 - 2 + 1
        assertEquals(ledger.getBlock(4).getPayloadHash(), body.get("merkleRoot").asText());
        assertEquals(ledger.getBlock(4).getBlockHash(), body.get("latestBlockHash").asText());
        assertTrue(body.get("brokenAtBlock").isNull());
    }

    @Test
    @DisplayName("C-007: GET /api/v1/audit/verify with invalid non-numeric query params returns 400 Bad Request")
    void testVerifyNonNumericParamsReturnsBadRequest() throws Exception {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/audit/verify?fromBlock=abc&toBlock=5", "Bearer auditor-token-123");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
        JsonNode body = parseBody(response);
        assertTrue(body.has("error"));
        assertTrue(body.get("error").asText().contains("must be a valid integer"));
    }

    @Test
    @DisplayName("C-007: GET /api/v1/audit/verify with invalid range returns 400 Bad Request")
    void testVerifyInvalidRangeReturnsBadRequest() throws Exception {
        // fromBlock > toBlock
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/audit/verify?fromBlock=4&toBlock=2", "Bearer auditor-token-123");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
        JsonNode body = parseBody(response);
        assertTrue(body.has("error"));
        assertTrue(body.get("error").asText().contains("Invalid block range"));
    }

    @Test
    @DisplayName("C-007: GET /api/v1/audit/verify against tampered block returns valid=false and brokenAtBlock")
    void testVerifyTamperedBlockReturnsBrokenAtBlock() throws Exception {
        // Tamper with block 3
        AuditBlock originalBlock = ledger.getBlock(3);
        AuditBlock tamperedBlock = new AuditBlock(
                3L,
                originalBlock.getTimestamp(),
                originalBlock.getPreviousHash(),
                originalBlock.getPayloadHash(),
                "badhash0000000000000000000000000000000000000000000000000000000000", // corrupted blockHash
                originalBlock.getRecords()
        );
        ledger.tamperWithBlock(3L, tamperedBlock);

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/audit/verify", "Bearer auditor-token-123");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode body = parseBody(response);
        assertFalse(body.get("valid").asBoolean());
        assertTrue(body.get("merkleRoot").isNull());
        assertTrue(body.get("latestBlockHash").isNull());
        assertEquals(3L, body.get("brokenAtBlock").asLong());
    }

    @Test
    @DisplayName("FEAT-007: Non-audit endpoint is passed through to next handler in Netty pipeline")
    void testUnmatchedPathPassesThrough() {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.GET,
                "/health"
        );

        assertTrue(channel.writeInbound(request));
        DefaultFullHttpRequest forwarded = channel.readInbound();
        assertNotNull(forwarded);
        assertEquals("/health", forwarded.uri());
    }

    @Test
    @DisplayName("C-007: Non-GET HTTP method returns 405 Method Not Allowed")
    void testNonGetMethodReturnsMethodNotAllowed() throws Exception {
        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/audit/verify", "Bearer auditor-token-123");

        assertNotNull(response);
        assertEquals(HttpResponseStatus.METHOD_NOT_ALLOWED, response.status());
    }
}
