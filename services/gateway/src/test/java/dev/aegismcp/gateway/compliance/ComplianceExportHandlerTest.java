package dev.aegismcp.gateway.compliance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.audit.AuditBlock;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.audit.AuditRecord;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests verifying contract C-011 Netty HTTP endpoint POST /api/v1/compliance/export.
 * Anchors: C-011, FEAT-011.
 */
class ComplianceExportHandlerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private AuditLedger ledger;
    private ComplianceReportEngine engine;
    private ComplianceExportHandler handler;
    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        ledger = new AuditLedger(1);
        for (int i = 1; i <= 3; i++) {
            ledger.appendSync(AuditRecord.create("agent-auditor", "read_metric", "allow", 0, 1.0, "p=" + i));
        }
        engine = new ComplianceReportEngine(ledger);
        handler = new ComplianceExportHandler(engine);
        channel = new EmbeddedChannel(handler);
    }

    @AfterEach
    void tearDown() {
        if (channel != null) {
            channel.close();
        }
        if (ledger != null) {
            ledger.close();
        }
    }

    private FullHttpResponse sendPost(String uri, String authHeader, String jsonBody) {
        ByteBuf content = jsonBody != null ? Unpooled.copiedBuffer(jsonBody, StandardCharsets.UTF_8) : Unpooled.EMPTY_BUFFER;
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                uri,
                content
        );
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        request.headers().set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        if (authHeader != null) {
            request.headers().set(HttpHeaderNames.AUTHORIZATION, authHeader);
        }
        channel.writeInbound(request);
        return channel.readOutbound();
    }

    @Test
    @DisplayName("C-011: POST /api/v1/compliance/export with valid Bearer token returns 200 OK and attestation response")
    void testExportSuccess() throws Exception {
        String body = """
                {
                  "framework": "EU_AI_ACT",
                  "format": "JSON",
                  "agentId": "agent-auditor"
                }
                """;

        FullHttpResponse response = sendPost("/api/v1/compliance/export", "Bearer auditor-token-123", body);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        String json = response.content().toString(StandardCharsets.UTF_8);
        JsonNode node = mapper.readTree(json);

        assertEquals("EU_AI_ACT", node.get("framework").asText());
        assertEquals("COMPLETED", node.get("status").asText());
        assertEquals(3, node.get("recordCount").asInt());
        assertNotNull(node.get("reportId").asText());
        assertNotNull(node.get("merkleRoot").asText());
        assertNotNull(node.get("signature").asText());
        assertNotNull(node.get("content").asText());

        response.release();
    }

    @Test
    @DisplayName("C-011: POST without Authorization Bearer token returns 401 Unauthorized")
    void testMissingAuthReturns401() {
        String body = "{\"framework\": \"EU_AI_ACT\", \"format\": \"JSON\"}";
        FullHttpResponse response = sendPost("/api/v1/compliance/export", null, body);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
        response.release();
    }

    @Test
    @DisplayName("C-011: POST with viewer/readonly Bearer token returns 403 Forbidden")
    void testInsufficientRoleReturns403() {
        String body = "{\"framework\": \"SOC2_TYPE2\", \"format\": \"JSON\"}";
        FullHttpResponse response = sendPost("/api/v1/compliance/export", "Bearer viewer-token", body);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
        response.release();
    }

    @Test
    @DisplayName("C-011: Invalid framework or missing body returns 400 Bad Request")
    void testInvalidRequestReturns400() {
        // Missing body
        FullHttpResponse resp1 = sendPost("/api/v1/compliance/export", "Bearer admin-token", "");
        assertNotNull(resp1);
        assertEquals(HttpResponseStatus.BAD_REQUEST, resp1.status());
        resp1.release();

        // Unsupported framework
        String badFramework = "{\"framework\": \"HIPAA\", \"format\": \"JSON\"}";
        FullHttpResponse resp2 = sendPost("/api/v1/compliance/export", "Bearer admin-token", badFramework);
        assertNotNull(resp2);
        assertEquals(HttpResponseStatus.BAD_REQUEST, resp2.status());
        resp2.release();

        // Invalid format
        String badFormat = "{\"framework\": \"EU_AI_ACT\", \"format\": \"XML\"}";
        FullHttpResponse resp3 = sendPost("/api/v1/compliance/export", "Bearer admin-token", badFormat);
        assertNotNull(resp3);
        assertEquals(HttpResponseStatus.BAD_REQUEST, resp3.status());
        resp3.release();
    }

    @Test
    @DisplayName("C-011: Cryptographic ledger discrepancy returns 409 Conflict")
    void testTamperedLedgerReturns409() {
        // Corrupt block 1 in ledger
        AuditBlock original = ledger.getBlock(1);
        AuditBlock tampered = new AuditBlock(
                1L,
                original.getTimestamp(),
                "0000000000000000000000000000000000000000000000000000000000000001",
                original.getPayloadHash(),
                original.getBlockHash(),
                original.getRecords()
        );
        ledger.tamperWithBlock(1L, tampered);

        String body = "{\"framework\": \"EU_AI_ACT\", \"format\": \"JSON\"}";
        FullHttpResponse response = sendPost("/api/v1/compliance/export", "Bearer admin-token", body);

        assertNotNull(response);
        assertEquals(HttpResponseStatus.CONFLICT, response.status());

        String json = response.content().toString(StandardCharsets.UTF_8);
        assertTrue(json.contains("Cryptographic hash chain broken or integrity compromised"));
        response.release();
    }

    @Test
    @DisplayName("C-011: Unsupported HTTP method returns 405 Method Not Allowed")
    void testUnsupportedMethodReturns405() {
        DefaultFullHttpRequest getReq = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.GET,
                "/api/v1/compliance/export",
                Unpooled.EMPTY_BUFFER
        );
        getReq.headers().set(HttpHeaderNames.AUTHORIZATION, "Bearer admin-token");

        channel.writeInbound(getReq);
        FullHttpResponse response = channel.readOutbound();

        assertNotNull(response);
        assertEquals(HttpResponseStatus.METHOD_NOT_ALLOWED, response.status());
        response.release();
    }

    @Test
    @DisplayName("FEAT-011: Non-compliance routes pass through down the Netty pipeline")
    void testPassThrough() {
        DefaultFullHttpRequest otherReq = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.GET,
                "/api/v1/other",
                Unpooled.EMPTY_BUFFER
        );

        channel.writeInbound(otherReq);
        // Handler should pass the request through; no outbound response generated by this handler
        Object passThrough = channel.readInbound();
        assertNotNull(passThrough, "Request should pass through down the pipeline");
        assertEquals(otherReq, passThrough);
        otherReq.release();
    }
}
