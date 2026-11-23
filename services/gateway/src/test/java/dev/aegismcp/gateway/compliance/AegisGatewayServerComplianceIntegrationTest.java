package dev.aegismcp.gateway.compliance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aegismcp.gateway.AegisGatewayServer;
import dev.aegismcp.gateway.audit.AuditRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end integration test verifying that AegisGatewayServer routes compliance and audit requests
 * through the Netty pipeline over actual HTTP.
 * Anchors: FEAT-011, C-011, C-013.
 */
class AegisGatewayServerComplianceIntegrationTest {

    private AegisGatewayServer server;
    private HttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void setUp() throws InterruptedException {
        server = new AegisGatewayServer("127.0.0.1", 0);
        server.start();

        // Seed some audit records into the server's ledger
        server.getAuditLedger().appendSync(AuditRecord.create("agent-e2e", "tool-alpha", "allow", 0, 1.5, "e2e-payload"));
        server.getAuditLedger().flush();

        httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
    }

    @AfterEach
    void tearDown() {
        if (server != null && server.isRunning()) {
            server.stop();
        }
    }

    @Test
    @DisplayName("FEAT-011 / C-011 & C-013: management routes fail closed with 401 when no verified identity provider is configured")
    void testEndToEndComplianceAndAuditRoutes() throws IOException, InterruptedException {
        int port = server.getPort();
        assertTrue(port > 0, "Server must be bound to active port");

        // 1. Verify health check still responds
        HttpRequest healthReq = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/health"))
                .GET()
                .timeout(Duration.ofSeconds(2))
                .build();
        HttpResponse<String> healthResp = httpClient.send(healthReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, healthResp.statusCode());
        assertEquals("{\"status\":\"UP\"}", healthResp.body());

        // 2. Query GET /api/v1/audit/records. The in-process seam configures no identity
        // provider, so the verified authorizer cannot accept any token and the endpoint fails
        // closed rather than trusting the token text.
        HttpRequest auditReq = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/v1/audit/records?agentId=agent-e2e"))
                .header("Authorization", "Bearer auditor-token")
                .GET()
                .timeout(Duration.ofSeconds(2))
                .build();
        HttpResponse<String> auditResp = httpClient.send(auditReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, auditResp.statusCode());

        // 3. Export POST /api/v1/compliance/export is likewise refused without a verified token.
        String exportJson = """
                {
                  "framework": "EU_AI_ACT",
                  "format": "JSON",
                  "agentId": "agent-e2e",
                  "from": "2020-01-01T00:00:00Z",
                  "to": "2030-01-01T00:00:00Z"
                }
                """;
        HttpRequest exportReq = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/api/v1/compliance/export"))
                .header("Authorization", "Bearer auditor-token")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(exportJson))
                .timeout(Duration.ofSeconds(2))
                .build();
        HttpResponse<String> exportResp = httpClient.send(exportReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, exportResp.statusCode());
    }
}
