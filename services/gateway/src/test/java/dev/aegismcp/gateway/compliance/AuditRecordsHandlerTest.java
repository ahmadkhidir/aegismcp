package dev.aegismcp.gateway.compliance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.audit.AuditRecord;
import dev.aegismcp.gateway.audit.AuditRecordsHandler;
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
 * Unit tests verifying contract C-013 Netty HTTP query endpoint GET /api/v1/audit/records.
 * Anchors: C-013, FEAT-011, schema.md#AuditBlock.
 */
class AuditRecordsHandlerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private AuditLedger ledger;
    private AuditRecordsHandler handler;
    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        ledger = new AuditLedger(1);
        // Seed 4 records:
        // 1: agent-A, tool1, allow
        // 2: agent-A, tool2, block
        // 3: agent-B, tool1, allow
        // 4: agent-B, tool3, require_approval
        ledger.appendSync(AuditRecord.create("agent-A", "tool1", "allow", 0, 1.2, "summary1"));
        ledger.appendSync(AuditRecord.create("agent-A", "tool2", "block", 0, 0.4, "summary2"));
        ledger.appendSync(AuditRecord.create("agent-B", "tool1", "allow", 1, 2.0, "summary3"));
        ledger.appendSync(AuditRecord.create("agent-B", "tool3", "require_approval", 0, 3.1, "summary4"));
        ledger.flush();

        handler = new AuditRecordsHandler(ledger);
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

    private FullHttpResponse sendGet(String uri, String authHeader) {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.GET,
                uri,
                Unpooled.EMPTY_BUFFER
        );
        if (authHeader != null) {
            request.headers().set(HttpHeaderNames.AUTHORIZATION, authHeader);
        }
        channel.writeInbound(request);
        return channel.readOutbound();
    }

    @Test
    @DisplayName("C-013: GET /api/v1/audit/records with Bearer token returns 200 OK and record list")
    void testQueryRecordsSuccess() throws Exception {
        FullHttpResponse response = sendGet("/api/v1/audit/records", "Bearer auditor-token");
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        String json = response.content().toString(StandardCharsets.UTF_8);
        JsonNode node = mapper.readTree(json);

        assertTrue(node.has("records"));
        assertTrue(node.has("total"));
        // Genesis block (agentId=system, decision=allow) + 4 user records = 5 total
        assertEquals(5, node.get("total").asInt());
        assertEquals(5, node.get("records").size());

        JsonNode first = node.get("records").get(0);
        assertTrue(first.has("index"));
        assertTrue(first.has("blockHash"));
        assertTrue(first.has("parentHash"));
        assertTrue(first.has("agentId"));
        assertTrue(first.has("toolName"));
        assertTrue(first.has("decision"));
        assertTrue(first.has("redactionCount"));
        assertTrue(first.has("latencyMs"));
        assertTrue(first.has("timestamp"));

        response.release();
    }

    @Test
    @DisplayName("C-013: Filters audit records by agentId")
    void testFilterByAgentId() throws Exception {
        FullHttpResponse response = sendGet("/api/v1/audit/records?agentId=agent-A", "Bearer admin-token");
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        String json = response.content().toString(StandardCharsets.UTF_8);
        JsonNode node = mapper.readTree(json);

        assertEquals(2, node.get("total").asInt());
        assertEquals(2, node.get("records").size());
        assertEquals("agent-A", node.get("records").get(0).get("agentId").asText());
        assertEquals("agent-A", node.get("records").get(1).get("agentId").asText());

        response.release();
    }

    @Test
    @DisplayName("C-013: Filters audit records by decision and minSeverity")
    void testFilterByDecisionAndSeverity() throws Exception {
        // Filter by decision=block
        FullHttpResponse blockResp = sendGet("/api/v1/audit/records?decision=block", "Bearer admin-token");
        assertNotNull(blockResp);
        assertEquals(HttpResponseStatus.OK, blockResp.status());
        JsonNode blockNode = mapper.readTree(blockResp.content().toString(StandardCharsets.UTF_8));
        assertEquals(1, blockNode.get("total").asInt());
        assertEquals("block", blockNode.get("records").get(0).get("decision").asText());
        blockResp.release();

        // Filter by minSeverity=high (matches 'block')
        FullHttpResponse highResp = sendGet("/api/v1/audit/records?minSeverity=high", "Bearer admin-token");
        assertNotNull(highResp);
        assertEquals(HttpResponseStatus.OK, highResp.status());
        JsonNode highNode = mapper.readTree(highResp.content().toString(StandardCharsets.UTF_8));
        assertEquals(1, highNode.get("total").asInt());
        highResp.release();

        // Filter by minSeverity=medium (matches 'block' and 'require_approval')
        FullHttpResponse medResp = sendGet("/api/v1/audit/records?minSeverity=medium", "Bearer admin-token");
        assertNotNull(medResp);
        assertEquals(HttpResponseStatus.OK, medResp.status());
        JsonNode medNode = mapper.readTree(medResp.content().toString(StandardCharsets.UTF_8));
        assertEquals(2, medNode.get("total").asInt());
        medResp.release();
    }

    @Test
    @DisplayName("C-013: Paginates audit records via limit and offset")
    void testPagination() throws Exception {
        // limit=2, offset=0
        FullHttpResponse p1 = sendGet("/api/v1/audit/records?limit=2&offset=0", "Bearer auditor-token");
        JsonNode node1 = mapper.readTree(p1.content().toString(StandardCharsets.UTF_8));
        assertEquals(5, node1.get("total").asInt());
        assertEquals(2, node1.get("records").size());
        long firstIndex = node1.get("records").get(0).get("index").asLong();
        p1.release();

        // limit=2, offset=2
        FullHttpResponse p2 = sendGet("/api/v1/audit/records?limit=2&offset=2", "Bearer auditor-token");
        JsonNode node2 = mapper.readTree(p2.content().toString(StandardCharsets.UTF_8));
        assertEquals(5, node2.get("total").asInt());
        assertEquals(2, node2.get("records").size());
        long secondIndex = node2.get("records").get(0).get("index").asLong();
        assertTrue(secondIndex > firstIndex);
        p2.release();
    }

    @Test
    @DisplayName("C-013: Missing Bearer token returns 401 Unauthorized")
    void testMissingAuthReturns401() {
        FullHttpResponse response = sendGet("/api/v1/audit/records", null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
        response.release();
    }

    @Test
    @DisplayName("C-013: Readonly/viewer token returns 403 Forbidden")
    void testInsufficientRoleReturns403() {
        FullHttpResponse response = sendGet("/api/v1/audit/records", "Bearer readonly-token");
        assertNotNull(response);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
        response.release();
    }

    @Test
    @DisplayName("C-013: Non-GET method returns 405 Method Not Allowed")
    void testNonGetMethodReturns405() {
        DefaultFullHttpRequest postReq = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                "/api/v1/audit/records",
                Unpooled.EMPTY_BUFFER
        );
        postReq.headers().set(HttpHeaderNames.AUTHORIZATION, "Bearer admin-token");

        channel.writeInbound(postReq);
        FullHttpResponse response = channel.readOutbound();

        assertNotNull(response);
        assertEquals(HttpResponseStatus.METHOD_NOT_ALLOWED, response.status());
        response.release();
    }
}
