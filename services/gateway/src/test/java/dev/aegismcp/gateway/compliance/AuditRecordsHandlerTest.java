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
import static org.junit.jupiter.api.Assertions.assertFalse;
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
        // Seed 4 tool interactions:
        // 1: agent-A, tool1, allow
        // 2: agent-A, tool2, block
        // 3: agent-B, tool1, allow
        // 4: agent-B, tool3, require_approval
        ledger.appendSync(AuditRecord.create("agent-A", "tool1", "allow", 0, 1.2, "summary1"));
        ledger.appendSync(AuditRecord.create("agent-A", "tool2", "block", 0, 0.4, "summary2"));
        ledger.appendSync(AuditRecord.create("agent-B", "tool1", "allow", 1, 2.0, "summary3"));
        ledger.appendSync(AuditRecord.create("agent-B", "tool3", "require_approval", 0, 3.1, "summary4"));
        ledger.flush();

        handler = new AuditRecordsHandler(ledger, mapper,
                bearerToken -> {
                    if (bearerToken == null || bearerToken.isBlank()) {
                        return AuditRecordsHandler.AuditAuthorizer.AuthResult
                                .unauthenticated("Missing authentication credentials");
                    }
                    if (bearerToken.contains("viewer") || bearerToken.contains("readonly")) {
                        return AuditRecordsHandler.AuditAuthorizer.AuthResult
                                .forbidden("Insufficient permissions for this operation");
                    }
                    return AuditRecordsHandler.AuditAuthorizer.AuthResult.allow();
                },
                Runnable::run);
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

    private JsonNode body(FullHttpResponse response) throws Exception {
        byte[] bytes = new byte[response.content().readableBytes()];
        response.content().readBytes(bytes);
        return mapper.readTree(bytes);
    }

    @Test
    @DisplayName("C-013: GET /api/v1/audit/records returns tool-interaction records ordered by blockIndex descending")
    void testQueryRecordsSuccess() throws Exception {
        FullHttpResponse response = sendGet("/api/v1/audit/records", "Bearer auditor-token");
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode node = body(response);
        assertEquals(4, node.get("total").asInt());
        assertEquals(4, node.get("records").size());

        JsonNode first = node.get("records").get(0);
        assertEquals(4, first.get("blockIndex").asLong());
        assertTrue(first.has("blockHash"));
        assertTrue(first.has("parentHash"));
        assertTrue(first.has("agentId"));
        assertTrue(first.has("toolName"));
        assertTrue(first.has("argumentsHash"));
        assertTrue(first.has("decision"));
        assertTrue(first.has("redactionCount"));
        assertTrue(first.has("latencyMs"));
        assertTrue(first.has("timestamp"));
        assertTrue(first.has("reviewedBy"));
        assertFalse(first.get("argumentsHash").asText().contains("summary4"),
                "The arguments themselves must never be returned");

        long previous = Long.MAX_VALUE;
        for (JsonNode record : node.get("records")) {
            long blockIndex = record.get("blockIndex").asLong();
            assertTrue(blockIndex < previous, "Records must be ordered by blockIndex descending");
            previous = blockIndex;
        }

        response.release();
    }

    @Test
    @DisplayName("C-013: Filters audit records by agentId and toolName")
    void testFilterByAgentIdAndToolName() throws Exception {
        FullHttpResponse response = sendGet("/api/v1/audit/records?agentId=agent-A&toolName=tool1",
                "Bearer admin-token");
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode node = body(response);
        assertEquals(1, node.get("total").asInt());
        assertEquals("agent-A", node.get("records").get(0).get("agentId").asText());
        assertEquals("tool1", node.get("records").get(0).get("toolName").asText());

        response.release();
    }

    @Test
    @DisplayName("C-013: Filters audit records by decision")
    void testFilterByDecision() throws Exception {
        FullHttpResponse response = sendGet("/api/v1/audit/records?decision=block", "Bearer admin-token");
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode node = body(response);
        assertEquals(1, node.get("total").asInt());
        assertEquals("block", node.get("records").get(0).get("decision").asText());

        response.release();
    }

    @Test
    @DisplayName("C-013: Filters audit records by exact blockHash")
    void testFilterByBlockHash() throws Exception {
        String blockHash = ledger.getBlock(2).getBlockHash();
        FullHttpResponse response = sendGet("/api/v1/audit/records?blockHash=" + blockHash,
                "Bearer admin-token");
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode node = body(response);
        assertEquals(1, node.get("total").asInt());
        assertEquals(blockHash, node.get("records").get(0).get("blockHash").asText());

        response.release();
    }

    @Test
    @DisplayName("C-013: Paginates audit records via limit and offset")
    void testPagination() throws Exception {
        FullHttpResponse p1 = sendGet("/api/v1/audit/records?limit=2&offset=0", "Bearer auditor-token");
        JsonNode node1 = body(p1);
        assertEquals(4, node1.get("total").asInt());
        assertEquals(2, node1.get("records").size());
        long firstIndex = node1.get("records").get(0).get("blockIndex").asLong();
        assertEquals(4, firstIndex);
        p1.release();

        FullHttpResponse p2 = sendGet("/api/v1/audit/records?limit=2&offset=2", "Bearer auditor-token");
        JsonNode node2 = body(p2);
        assertEquals(4, node2.get("total").asInt());
        assertEquals(2, node2.get("records").size());
        long secondIndex = node2.get("records").get(0).get("blockIndex").asLong();
        assertTrue(secondIndex < firstIndex, "Pagination continues into older blocks");
        p2.release();
    }

    @Test
    @DisplayName("C-013: An out-of-range limit, negative offset, or undeclared decision returns 400")
    void testInvalidQueryParametersReturn400() {
        FullHttpResponse badLimit = sendGet("/api/v1/audit/records?limit=501", "Bearer auditor-token");
        assertEquals(HttpResponseStatus.BAD_REQUEST, badLimit.status());
        badLimit.release();

        FullHttpResponse badOffset = sendGet("/api/v1/audit/records?offset=-1", "Bearer auditor-token");
        assertEquals(HttpResponseStatus.BAD_REQUEST, badOffset.status());
        badOffset.release();

        FullHttpResponse badDecision = sendGet("/api/v1/audit/records?decision=BLOCKED",
                "Bearer auditor-token");
        assertEquals(HttpResponseStatus.BAD_REQUEST, badDecision.status());
        badDecision.release();

        FullHttpResponse badDate = sendGet("/api/v1/audit/records?from=yesterday", "Bearer auditor-token");
        assertEquals(HttpResponseStatus.BAD_REQUEST, badDate.status());
        badDate.release();
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
