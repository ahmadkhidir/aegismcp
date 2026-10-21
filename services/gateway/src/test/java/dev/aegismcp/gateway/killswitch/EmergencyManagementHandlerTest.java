package dev.aegismcp.gateway.killswitch;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying Netty HTTP endpoints conforming to contracts C-008, C-009, and C-010.
 * Anchors: C-008, C-009, C-010, FEAT-010.
 */
class EmergencyManagementHandlerTest {

    private final ObjectMapper mapper = JsonRpcCodec.getInstance().getMapper();
    private KillSwitchManager killSwitchManager;
    private GatewayMetrics metrics;
    private EmergencyManagementHandler handler;
    private EmbeddedChannel channel;

    private static final String ADMIN_TOKEN = "Bearer admin-token-secret-999";
    private static final String READONLY_TOKEN = "Bearer readonly-viewer-token";

    @BeforeEach
    void setUp() {
        killSwitchManager = new KillSwitchManager();
        metrics = new GatewayMetrics();
        handler = new EmergencyManagementHandler(killSwitchManager, metrics);
        channel = new EmbeddedChannel(handler);
    }

    @AfterEach
    void tearDown() {
        if (channel != null) {
            channel.close();
        }
    }

    private FullHttpResponse sendRequest(HttpMethod method, String uri, String payload, String authHeader, String cookieHeader) {
        ByteBuf content = (payload != null)
                ? Unpooled.wrappedBuffer(payload.getBytes(StandardCharsets.UTF_8))
                : Unpooled.EMPTY_BUFFER;

        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                method,
                uri,
                content
        );
        request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
        request.headers().set(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
        if (authHeader != null) {
            request.headers().set(HttpHeaderNames.AUTHORIZATION, authHeader);
        }
        if (cookieHeader != null) {
            request.headers().set(HttpHeaderNames.COOKIE, cookieHeader);
        }

        channel.writeInbound(request);
        return channel.readOutbound();
    }

    private JsonNode parseBody(FullHttpResponse response) throws Exception {
        byte[] bytes = new byte[response.content().readableBytes()];
        response.content().readBytes(bytes);
        return mapper.readTree(bytes);
    }

    // ==========================================
    // C-008: POST /api/v1/emergency/kill
    // ==========================================

    @Test
    @DisplayName("C-008: POST /api/v1/emergency/kill with targetType 'global' returns 200 OK with ACTIVE status")
    void testPostEmergencyKillGlobal() throws Exception {
        String body = """
                {
                  "targetType": "global",
                  "targetId": "global",
                  "reason": "Cluster isolation initiated"
                }
                """;

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("ACTIVE", json.get("status").asText());
        assertEquals(0, json.get("affectedSessions").asInt());
        assertNotNull(json.get("timestamp"));
        assertTrue(killSwitchManager.isGlobalLockdown());
    }

    @Test
    @DisplayName("C-008: POST /api/v1/emergency/kill with targetType 'agent' returns 200 OK with QUARANTINED status")
    void testPostEmergencyKillAgent() throws Exception {
        String body = """
                {
                  "targetType": "agent",
                  "targetId": "rogue-agent-77",
                  "reason": "Data exfiltration detected"
                }
                """;

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("QUARANTINED", json.get("status").asText());
        assertEquals(0, json.get("affectedSessions").asInt());
        assertNotNull(json.get("timestamp"));
        assertTrue(killSwitchManager.isAgentQuarantined("rogue-agent-77"));
    }

    @Test
    @DisplayName("C-008: POST /api/v1/emergency/kill with targetType 'tool' returns 200 OK with QUARANTINED status")
    void testPostEmergencyKillTool() throws Exception {
        String body = """
                {
                  "targetType": "tool",
                  "targetId": "shell:exec",
                  "reason": "Vulnerability CVE-2026-0001"
                }
                """;

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("QUARANTINED", json.get("status").asText());
        assertTrue(killSwitchManager.isToolQuarantined("shell:exec"));
    }

    @Test
    @DisplayName("C-008: POST /api/v1/emergency/kill with targetType 'server' returns 200 OK with SEVERED status")
    void testPostEmergencyKillServer() throws Exception {
        String body = """
                {
                  "targetType": "server",
                  "targetId": "upstream-mcp-db",
                  "reason": "Compromised credential"
                }
                """;

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("SEVERED", json.get("status").asText());
        assertTrue(killSwitchManager.isServerQuarantined("upstream-mcp-db"));
    }

    @Test
    @DisplayName("C-008: POST /api/v1/emergency/kill without token returns 401 Unauthorized")
    void testPostEmergencyKillUnauthorized() throws Exception {
        String body = "{\"targetType\": \"global\", \"targetId\": \"global\"}";

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, null, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());

        JsonNode json = parseBody(response);
        assertTrue(json.has("error"));
    }

    @Test
    @DisplayName("C-008: POST /api/v1/emergency/kill with readonly token returns 403 Forbidden")
    void testPostEmergencyKillForbidden() throws Exception {
        String body = "{\"targetType\": \"agent\", \"targetId\": \"bot-1\"}";

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, READONLY_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());

        JsonNode json = parseBody(response);
        assertTrue(json.has("error"));
        assertTrue(json.get("error").asText().contains("Insufficient permissions"));
    }

    @Test
    @DisplayName("C-008: POST /api/v1/emergency/kill with invalid targetType returns 400 Bad Request")
    void testPostEmergencyKillInvalidTargetType() throws Exception {
        String body = "{\"targetType\": \"unknown_type\", \"targetId\": \"id-1\"}";

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());

        JsonNode json = parseBody(response);
        assertTrue(json.get("error").asText().contains("Invalid target type"));
    }

    @Test
    @DisplayName("C-008: POST /api/v1/emergency/kill with missing targetId for agent returns 400 Bad Request")
    void testPostEmergencyKillMissingTargetId() throws Exception {
        String body = "{\"targetType\": \"agent\"}";

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());

        JsonNode json = parseBody(response);
        assertTrue(json.get("error").asText().contains("targetId is required"));
    }

    @Test
    @DisplayName("C-008: POST /api/v1/emergency/kill with empty body returns 400 Bad Request")
    void testPostEmergencyKillEmptyBody() {
        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", "", ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
    }

    @Test
    @DisplayName("C-008: Non-POST method on /api/v1/emergency/kill returns 405 Method Not Allowed")
    void testEmergencyKillMethodNotAllowed() {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/emergency/kill", null, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.METHOD_NOT_ALLOWED, response.status());
    }

    // ==========================================
    // C-009: GET /api/v1/system/status
    // ==========================================

    @Test
    @DisplayName("C-009: GET /api/v1/system/status returns 200 OK with NORMAL status under default state")
    void testGetSystemStatusNormal() throws Exception {
        metrics.setActiveConnections(12);
        metrics.recordRequest();

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/system/status", null, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("NORMAL", json.get("status").asText());
        assertEquals(12, json.get("activeConnections").asInt());
        assertEquals(1, json.get("totalRequests24h").asLong());
        assertEquals(0, json.get("blockedViolations24h").asLong());
        assertEquals(0, json.get("pendingApprovals").asInt());
    }

    @Test
    @DisplayName("C-009: GET /api/v1/system/status returns ELEVATED status when quarantines exist")
    void testGetSystemStatusElevated() throws Exception {
        killSwitchManager.quarantineAgent("suspicious-bot", "High rate of failure");

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/system/status", null, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("ELEVATED", json.get("status").asText());
    }

    @Test
    @DisplayName("C-009: GET /api/v1/system/status returns LOCKDOWN status when global lockdown active")
    void testGetSystemStatusLockdown() throws Exception {
        killSwitchManager.activateGlobalLockdown("Incident containment");

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/system/status", null, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("LOCKDOWN", json.get("status").asText());
    }

    @Test
    @DisplayName("C-009: GET /api/v1/system/status with session cookie returns 200 OK")
    void testGetSystemStatusWithCookie() throws Exception {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/system/status", null, null, "aegis_session=valid-session-123");
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertTrue(json.has("status"));
    }

    @Test
    @DisplayName("C-009: GET /api/v1/system/status without auth returns 401 Unauthorized")
    void testGetSystemStatusUnauthorized() {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/system/status", null, null, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
    }

    // ==========================================
    // C-010: GET /api/v1/metrics/summary
    // ==========================================

    @Test
    @DisplayName("C-010: GET /api/v1/metrics/summary returns 200 OK with aggregated dashboard metrics")
    void testGetMetricsSummary() throws Exception {
        metrics.setActiveAgents(8);
        metrics.recordToolCall();
        metrics.recordBlockedViolation();
        metrics.setPendingApprovals(3);

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/metrics/summary", null, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals(8, json.get("activeAgents").asInt());
        assertEquals(1, json.get("toolCalls24h").asLong());
        assertEquals(1, json.get("blockedViolations24h").asLong());
        assertEquals(3, json.get("pendingApprovals").asInt());
        assertTrue(json.has("uptimeSeconds"));
        assertTrue(json.get("uptimeSeconds").asLong() >= 0);
    }

    @Test
    @DisplayName("C-010: GET /api/v1/metrics/summary without auth returns 401 Unauthorized")
    void testGetMetricsSummaryUnauthorized() {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/metrics/summary", null, null, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
    }

    // ==========================================
    // Passthrough to next pipeline handler
    // ==========================================

    @Test
    @DisplayName("FEAT-010: Non-emergency endpoints pass through to downstream handlers")
    void testPassThrough() {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.GET,
                "/health",
                Unpooled.EMPTY_BUFFER
        );

        channel.writeInbound(request);
        // Handler should not produce an outbound response, but pass inbound object through
        Object passed = channel.readInbound();
        assertNotNull(passed);
        assertSame(request, passed);
    }
}
