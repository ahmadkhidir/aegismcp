package dev.aegismcp.gateway.killswitch;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.audit.AuditBlock;
import dev.aegismcp.gateway.audit.AuditLedger;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
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
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests verifying the Netty HTTP endpoints conforming to contracts C-008, C-009, C-010, and
 * C-020. Authentication is delegated to a test double that models the verified-token outcome.
 *
 * <p>Anchors: FEAT-010, C-008, C-009, C-010, C-020.
 */
class EmergencyManagementHandlerTest {

    private final ObjectMapper mapper = JsonRpcCodec.getInstance().getMapper();
    private KillSwitchManager killSwitchManager;
    private GatewayMetrics metrics;
    private AuditLedger auditLedger;
    private EmergencyManagementHandler handler;
    private EmbeddedChannel channel;

    private static final String ADMIN_TOKEN = "Bearer admin-token-secret-999";
    private static final String STALE_MFA_TOKEN = "Bearer stale-mfa-token";
    private static final String READONLY_TOKEN = "Bearer readonly-viewer-token";
    private static final String OPERATOR_SUBJECT = "marcus.vance@example.com";

    /** A channel registered so the target-existence check sees a live session. */
    private EmbeddedChannel agentSession;
    private EmbeddedChannel serverSession;
    private EmbeddedChannel namedSession;

    @BeforeEach
    void setUp() {
        killSwitchManager = new KillSwitchManager();
        metrics = new GatewayMetrics();
        auditLedger = new AuditLedger(1);

        agentSession = new EmbeddedChannel();
        serverSession = new EmbeddedChannel();
        namedSession = new EmbeddedChannel();
        killSwitchManager.registerSession("rogue-agent-77", agentSession);
        killSwitchManager.registerSession(null, "upstream-mcp-db", serverSession);
        killSwitchManager.registerSession("sess-42", "agent-42", null, namedSession);

        handler = new EmergencyManagementHandler(killSwitchManager, metrics, auditLedger, mapper,
                (path, method, bearerToken, cookieHeader) -> {
                    if (bearerToken == null || bearerToken.isBlank()) {
                        if (cookieHeader != null && !cookieHeader.isBlank()) {
                            return EmergencyManagementHandler.EmergencyAuthorizer.AuthResult
                                    .verified("viewer@example.com", Map.of());
                        }
                        return EmergencyManagementHandler.EmergencyAuthorizer.AuthResult
                                .unauthenticated("Missing authentication credentials");
                    }
                    if (bearerToken.contains("readonly") || bearerToken.contains("viewer")) {
                        return EmergencyManagementHandler.EmergencyAuthorizer.AuthResult
                                .forbidden("Insufficient permissions for this operation");
                    }
                    long authTime = bearerToken.contains("stale-mfa")
                            ? Instant.now().minusSeconds(600).getEpochSecond()
                            : Instant.now().minusSeconds(30).getEpochSecond();
                    return EmergencyManagementHandler.EmergencyAuthorizer.AuthResult.verified(
                            OPERATOR_SUBJECT,
                            Map.of("auth_time", authTime, "amr", List.of("pwd", "mfa")));
                },
                Runnable::run);
        channel = new EmbeddedChannel(handler);
    }

    @AfterEach
    void tearDown() {
        if (channel != null) {
            channel.close();
        }
        agentSession.finishAndReleaseAll();
        serverSession.finishAndReleaseAll();
        namedSession.finishAndReleaseAll();
        if (auditLedger != null) {
            auditLedger.close();
        }
    }

    private FullHttpResponse sendRequest(HttpMethod method, String uri, String payload, String authHeader,
                                         String cookieHeader) {
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
    @DisplayName("C-008: a global kill with a fresh MFA re-confirmation returns 200 with LOCKDOWN")
    void testPostEmergencyKillGlobal() throws Exception {
        String body = """
                {
                  "targetType": "global",
                  "reason": "Cluster isolation initiated"
                }
                """;

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("LOCKDOWN", json.get("status").asText());
        assertEquals(3, json.get("affectedSessions").asInt());
        assertNotNull(json.get("timestamp"));
        assertTrue(killSwitchManager.isGlobalLockdown());
    }

    @Test
    @DisplayName("C-008: a global kill without a fresh MFA re-confirmation returns 403 and applies nothing")
    void testGlobalKillRequiresFreshMfa() {
        String body = "{\"targetType\": \"global\", \"reason\": \"No MFA\"}";

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body,
                STALE_MFA_TOKEN, null);
        assertEquals(HttpResponseStatus.FORBIDDEN, response.status());
        assertEquals(false, killSwitchManager.isGlobalLockdown());
        response.release();
    }

    @Test
    @DisplayName("C-008: an agent kill returns 200 with QUARANTINED and closes the matching stream")
    void testPostEmergencyKillAgent() throws Exception {
        String body = """
                {
                  "targetType": "agent",
                  "targetId": "rogue-agent-77",
                  "reason": "Data exfiltration detected"
                }
                """;

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("QUARANTINED", json.get("status").asText());
        assertEquals(1, json.get("affectedSessions").asInt());
        assertTrue(killSwitchManager.isAgentQuarantined("rogue-agent-77"));
        response.release();
    }

    @Test
    @DisplayName("C-008: a session kill returns 200 with QUARANTINED")
    void testPostEmergencyKillSession() throws Exception {
        String body = "{\"targetType\": \"session\", \"targetId\": \"sess-42\"}";

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("QUARANTINED", json.get("status").asText());
        assertTrue(killSwitchManager.isSessionQuarantined("sess-42"));
        response.release();
    }

    @Test
    @DisplayName("C-008: a server kill returns 200 with SEVERED")
    void testPostEmergencyKillServer() throws Exception {
        String body = """
                {
                  "targetType": "server",
                  "targetId": "upstream-mcp-db",
                  "reason": "Compromised credential"
                }
                """;

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("SEVERED", json.get("status").asText());
        assertTrue(killSwitchManager.isServerQuarantined("upstream-mcp-db"));
        response.release();
    }

    @Test
    @DisplayName("C-008: an undeclared target type is answered 400, including the internal tool target")
    void testPostEmergencyKillToolIsNotAContractTarget() {
        String body = "{\"targetType\": \"tool\", \"targetId\": \"shell:exec\"}";

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
        assertEquals(false, killSwitchManager.isToolQuarantined("shell:exec"));
        response.release();
    }

    @Test
    @DisplayName("C-008: an unknown target is answered 404 and no quarantine is applied")
    void testPostEmergencyKillUnknownTargetReturns404() {
        String body = "{\"targetType\": \"agent\", \"targetId\": \"ghost-agent\"}";

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.NOT_FOUND, response.status());
        assertEquals(false, killSwitchManager.isAgentQuarantined("ghost-agent"));
        response.release();
    }

    @Test
    @DisplayName("C-008: a targetId supplied with global is answered 400")
    void testGlobalWithTargetIdReturns400() {
        String body = "{\"targetType\": \"global\", \"targetId\": \"global\"}";

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
        assertEquals(false, killSwitchManager.isGlobalLockdown());
        response.release();
    }

    @Test
    @DisplayName("C-008: a misplaced secondApprover is answered 400")
    void testSecondApproverOutsideEnterpriseGlobalReturns400() {
        String body = "{\"targetType\": \"agent\", \"targetId\": \"rogue-agent-77\", "
                + "\"secondApprover\": \"other@example.com\"}";

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.BAD_REQUEST, response.status());
        response.release();
    }

    @Test
    @DisplayName("C-008: missing token is 401 and a verified non-operator is 403")
    void testKillAuthFailures() {
        FullHttpResponse missing = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill",
                "{\"targetType\": \"agent\", \"targetId\": \"rogue-agent-77\"}", null, null);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, missing.status());
        missing.release();

        FullHttpResponse forbidden = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill",
                "{\"targetType\": \"agent\", \"targetId\": \"rogue-agent-77\"}", READONLY_TOKEN, null);
        assertEquals(HttpResponseStatus.FORBIDDEN, forbidden.status());
        forbidden.release();
    }

    @Test
    @DisplayName("C-008: missing targetId for a scoped target and an empty body are answered 400")
    void testKillPayloadValidation() {
        FullHttpResponse noTarget = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill",
                "{\"targetType\": \"agent\"}", ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.BAD_REQUEST, noTarget.status());
        noTarget.release();

        FullHttpResponse empty = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", "", ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.BAD_REQUEST, empty.status());
        empty.release();
    }

    @Test
    @DisplayName("C-008: the accepted kill is sealed in the ledger as an administrative entry")
    void testKillSealsAdministrativeEntry() {
        String body = "{\"targetType\": \"agent\", \"targetId\": \"rogue-agent-77\", \"reason\": \"incident\"}";

        FullHttpResponse response = sendRequest(HttpMethod.POST, "/api/v1/emergency/kill", body, ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.OK, response.status());
        response.release();

        auditLedger.flush();
        boolean sealed = false;
        long deadline = System.currentTimeMillis() + 2000;
        while (!sealed && System.currentTimeMillis() < deadline) {
            for (long i = 0; i <= auditLedger.getLatestBlockIndex(); i++) {
                AuditBlock block = auditLedger.getBlock(i);
                if (block == null) {
                    continue;
                }
                sealed = block.getRecords().stream().anyMatch(record ->
                        "KILL".equals(record.getDecision())
                                && OPERATOR_SUBJECT.equals(record.getAgentId()));
                if (sealed) {
                    break;
                }
            }
            if (!sealed) {
                try {
                    Thread.sleep(20);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        assertTrue(sealed, "The kill action must be sealed with the initiating operator");
    }

    @Test
    @DisplayName("C-008: a non-POST method on the kill path returns 405")
    void testEmergencyKillMethodNotAllowed() {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/emergency/kill", null, ADMIN_TOKEN, null);
        assertNotNull(response);
        assertEquals(HttpResponseStatus.METHOD_NOT_ALLOWED, response.status());
        response.release();
    }

    // ==========================================
    // C-009: GET /api/v1/system/status
    // ==========================================

    @Test
    @DisplayName("C-009: GET /api/v1/system/status returns 200 with NORMAL status under default state")
    void testGetSystemStatusNormal() throws Exception {
        metrics.setActiveConnections(12);
        metrics.recordRequest();

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/system/status", null, ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("NORMAL", json.get("status").asText());
        assertEquals(12, json.get("activeConnections").asInt());
        assertEquals(1, json.get("connectedNodes").asInt());
        assertEquals(1, json.get("totalRequests24h").asLong());
        assertEquals(0, json.get("blockedViolations24h").asLong());
        assertEquals(0, json.get("pendingApprovals").asInt());
        response.release();
    }

    @Test
    @DisplayName("C-009: status reports ELEVATED with quarantines and LOCKDOWN in a lockdown")
    void testGetSystemStatusElevatedAndLockdown() throws Exception {
        killSwitchManager.quarantineAgent("suspicious-bot", "High rate of failure");
        FullHttpResponse elevated = sendRequest(HttpMethod.GET, "/api/v1/system/status", null, ADMIN_TOKEN, null);
        assertEquals("ELEVATED", parseBody(elevated).get("status").asText());
        elevated.release();

        killSwitchManager.activateGlobalLockdown("Incident containment");
        FullHttpResponse lockdown = sendRequest(HttpMethod.GET, "/api/v1/system/status", null, ADMIN_TOKEN, null);
        assertEquals("LOCKDOWN", parseBody(lockdown).get("status").asText());
        lockdown.release();
    }

    @Test
    @DisplayName("C-009: the fleet status is readable with the console session cookie")
    void testGetSystemStatusWithCookie() throws Exception {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/system/status", null, null,
                "aegis_session=valid-session-123");
        assertEquals(HttpResponseStatus.OK, response.status());
        assertTrue(parseBody(response).has("status"));
        response.release();
    }

    @Test
    @DisplayName("C-009: the fleet status without credentials returns 401")
    void testGetSystemStatusUnauthorized() {
        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/system/status", null, null, null);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());
        response.release();
    }

    // ==========================================
    // C-010 and C-020: metrics
    // ==========================================

    @Test
    @DisplayName("C-010: GET /api/v1/metrics/summary returns the aggregated dashboard metrics")
    void testGetMetricsSummary() throws Exception {
        metrics.setActiveAgents(8);
        metrics.recordToolCall();
        metrics.recordBlockedViolation();
        metrics.setPendingApprovals(3);

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/metrics/summary", null, ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals(8, json.get("activeAgents").asInt());
        assertEquals(1, json.get("toolCalls24h").asLong());
        assertEquals(1, json.get("blockedViolations24h").asLong());
        assertEquals(3, json.get("pendingApprovals").asInt());
        assertTrue(json.get("uptimeSeconds").asLong() >= 0);
        response.release();
    }

    @Test
    @DisplayName("C-010: the metrics summary without credentials returns 401")
    void testGetMetricsSummaryUnauthorized() {
        FullHttpResponse metricsSummary = sendRequest(HttpMethod.GET, "/api/v1/metrics/summary", null, null, null);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, metricsSummary.status());
        metricsSummary.release();

        FullHttpResponse timeseries = sendRequest(HttpMethod.GET, "/api/v1/metrics/timeseries", null, null, null);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, timeseries.status());
        timeseries.release();
    }

    @Test
    @DisplayName("C-020: the timeseries reports 24 hourly buckets oldest first")
    void testGetMetricsTimeseries() throws Exception {
        metrics.recordToolCall();
        metrics.recordBlockedViolation();

        FullHttpResponse response = sendRequest(HttpMethod.GET, "/api/v1/metrics/timeseries", null,
                ADMIN_TOKEN, null);
        assertEquals(HttpResponseStatus.OK, response.status());

        JsonNode json = parseBody(response);
        assertEquals("HOUR", json.get("interval").asText());
        JsonNode buckets = json.get("buckets");
        assertEquals(24, buckets.size());

        JsonNode last = buckets.get(23);
        assertEquals(1, last.get("toolCalls").asLong());
        assertEquals(1, last.get("blockedViolations").asLong());
        assertTrue(last.get("bucketStart").asText().compareTo(
                buckets.get(0).get("bucketStart").asText()) > 0);
        response.release();
    }

    // ==========================================
    // Passthrough to next pipeline handler
    // ==========================================

    @Test
    @DisplayName("FEAT-010: non-management endpoints pass through to downstream handlers")
    void testPassThrough() {
        DefaultFullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.GET,
                "/health",
                Unpooled.EMPTY_BUFFER
        );

        channel.writeInbound(request);
        Object passed = channel.readInbound();
        assertNotNull(passed);
        assertSame(request, passed);
        ((FullHttpRequest) passed).release();
    }
}
