package dev.aegismcp.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit and integration tests for the 'aegis-cli kill' command.
 * Anchors: FEAT-010, FEAT-003, C-008.
 */
class KillCommandTest {

    private static final String AWS_KEY = TestCredential.awsAccessKey();

    private HttpServer mockServer;
    private int mockPort;
    private final ObjectMapper mapper = new ObjectMapper();

    private final AtomicReference<String> lastReceivedPath = new AtomicReference<>();
    private final AtomicReference<String> lastReceivedMethod = new AtomicReference<>();
    private final AtomicReference<String> lastReceivedAuth = new AtomicReference<>();
    private final AtomicReference<String> lastReceivedBody = new AtomicReference<>();
    private final AtomicInteger requestCount = new AtomicInteger();
    private final AtomicInteger responseStatusCode = new AtomicInteger(200);
    private final AtomicReference<String> responsePayload = new AtomicReference<>();

    @BeforeEach
    void setUp() throws IOException {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        mockPort = mockServer.getAddress().getPort();

        mockServer.createContext("/api/v1/emergency/kill", exchange -> {
            requestCount.incrementAndGet();
            lastReceivedPath.set(exchange.getRequestURI().getPath());
            lastReceivedMethod.set(exchange.getRequestMethod());
            lastReceivedAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));

            byte[] bodyBytes = exchange.getRequestBody().readAllBytes();
            lastReceivedBody.set(new String(bodyBytes, StandardCharsets.UTF_8));

            int status = responseStatusCode.get();
            byte[] responseBytes = (responsePayload.get() != null ? responsePayload.get() : "{}")
                    .getBytes(StandardCharsets.UTF_8);

            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, responseBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        });

        mockServer.start();
    }

    @AfterEach
    void tearDown() {
        if (mockServer != null) {
            mockServer.stop(0);
        }
    }

    @Test
    @DisplayName("FEAT-010 AC 1 / C-008: Quarantines a rogue agent through the emergency endpoint")
    void testAgentKillSuccess() {
        responseStatusCode.set(200);
        responsePayload.set("""
                {
                  "status": "QUARANTINED",
                  "affectedSessions": 4,
                  "timestamp": "2026-10-21T10:15:30Z"
                }
                """);

        Captured result = execute(
                "--agent", "support-bot-04",
                "--gateway", "http://localhost:" + mockPort,
                "--reason", "Infinite loop detected",
                "--token", "test-admin-token");

        assertEquals(ExitCode.SUCCESS, result.exitCode());
        assertEquals("/api/v1/emergency/kill", lastReceivedPath.get());
        assertEquals("POST", lastReceivedMethod.get());
        assertEquals("Bearer test-admin-token", lastReceivedAuth.get());

        JsonNode bodyJson = readBody();
        assertEquals("agent", bodyJson.get("targetType").asText());
        assertEquals("support-bot-04", bodyJson.get("targetId").asText());
        assertEquals("Infinite loop detected", bodyJson.get("reason").asText());
        assertFalse(bodyJson.has("secondApprover"), "an agent target must not carry a second approver");

        assertTrue(result.out().contains("Emergency kill-switch invoked successfully (HTTP 200)"));
        assertTrue(result.out().contains("Result Status:     QUARANTINED"));
        assertTrue(result.out().contains("Affected Sessions: 4"));
        assertTrue(result.out().contains("Timestamp:         2026-10-21T10:15:30Z"));
        assertFalse(result.out().contains("test-admin-token"), "the bearer token must never be printed");
        assertFalse(result.err().contains("test-admin-token"), "the bearer token must never be printed");
    }

    @Test
    @DisplayName("FEAT-003 AC: A global target without --confirm-lockdown exits 2 and sends nothing")
    void testGlobalKillRequiresConfirmation() {
        Captured result = execute(
                "--target-type", "global",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.USAGE, result.exitCode());
        assertEquals(0, requestCount.get(), "no request may be sent without the confirmation flag");
        assertTrue(result.err().contains("requires the explicit --confirm-lockdown flag"));
    }

    @Test
    @DisplayName("FEAT-003 AC / C-008: A global target with --confirm-lockdown sends no targetId")
    void testGlobalKillWithConfirmation() {
        responseStatusCode.set(200);
        responsePayload.set("""
                {
                  "status": "LOCKDOWN",
                  "affectedSessions": 42,
                  "timestamp": "2026-10-21T10:16:00Z"
                }
                """);

        Captured result = execute(
                "--target-type", "global",
                "--confirm-lockdown",
                "--gateway", "http://localhost:" + mockPort,
                "--reason", "Compromised cluster state");

        assertEquals(ExitCode.SUCCESS, result.exitCode());
        JsonNode bodyJson = readBody();
        assertEquals("global", bodyJson.get("targetType").asText());
        assertFalse(bodyJson.has("targetId"), "C-008 forbids targetId on a global target");
        assertTrue(result.out().contains("Result Status:     LOCKDOWN"));
    }

    @Test
    @DisplayName("C-008: --second-approver is forwarded on a global target")
    void testGlobalKillSendsSecondApprover() {
        responseStatusCode.set(200);
        responsePayload.set("""
                {
                  "status": "LOCKDOWN",
                  "affectedSessions": 42,
                  "timestamp": "2026-10-21T10:16:00Z"
                }
                """);

        Captured result = execute(
                "--target-type", "global",
                "--confirm-lockdown",
                "--second-approver", "operator-two",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.SUCCESS, result.exitCode());
        JsonNode bodyJson = readBody();
        assertEquals("operator-two", bodyJson.get("secondApprover").asText());
    }

    @Test
    @DisplayName("C-008: --second-approver on a scoped target is a usage error and sends nothing")
    void testScopedSecondApproverIsRefused() {
        Captured result = execute(
                "--target-type", "server",
                "--target-id", "upstream-1",
                "--second-approver", "operator-two",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.USAGE, result.exitCode());
        assertEquals(0, requestCount.get());
        assertTrue(result.err().contains("permitted only on a global target"));
    }

    @Test
    @DisplayName("C-008: A global target rejects --target-id and sends nothing")
    void testGlobalTargetRejectsTargetId() {
        Captured result = execute(
                "--target-type", "global",
                "--target-id", "anything",
                "--confirm-lockdown",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.USAGE, result.exitCode());
        assertEquals(0, requestCount.get());
        assertTrue(result.err().contains("global target sends no target identifier"));
    }

    @Test
    @DisplayName("C-008: The undefined 'tool' target is a usage error and sends nothing")
    void testToolTargetIsRefused() {
        Captured result = execute(
                "--target-type", "tool",
                "--target-id", "read_file",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.USAGE, result.exitCode());
        assertEquals(0, requestCount.get());
        assertTrue(result.err().contains("expected session, agent, server, or global"));
    }

    @Test
    @DisplayName("FEAT-003: A scoped target with no identifier is a usage error")
    void testMissingTargetIdIsUsageError() {
        Captured result = execute(
                "--target-type", "session",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.USAGE, result.exitCode());
        assertEquals(0, requestCount.get());
    }

    @Test
    @DisplayName("FEAT-003: HTTP 400 is a usage error (exit 2)")
    void testBadRequestResponse() {
        responseStatusCode.set(400);
        responsePayload.set("{\"error\":\"Invalid target type\"}");

        Captured result = execute(
                "--agent", "rogue-agent",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.USAGE, result.exitCode());
        assertTrue(result.err().contains("Bad Request (HTTP 400)"));
    }

    @Test
    @DisplayName("FEAT-003: HTTP 401 exits 1 and never echoes the token")
    void testUnauthorizedResponse() {
        responseStatusCode.set(401);
        responsePayload.set("{\"error\":\"Unauthorized\"}");

        Captured result = execute(
                "--agent", "rogue-agent",
                "--token", "secret-admin-token",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.FAILURE, result.exitCode());
        assertTrue(result.err().contains("Unauthorized (HTTP 401)"));
        assertFalse(result.out().contains("secret-admin-token"));
        assertFalse(result.err().contains("secret-admin-token"));
    }

    @Test
    @DisplayName("FEAT-003: HTTP 403 exits 1")
    void testForbiddenResponse() {
        responseStatusCode.set(403);
        responsePayload.set("{\"error\":\"Forbidden\"}");

        Captured result = execute(
                "--agent", "rogue-agent",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.FAILURE, result.exitCode());
        assertTrue(result.err().contains("Forbidden (HTTP 403)"));
    }

    @Test
    @DisplayName("C-008: HTTP 404 exits 1")
    void testNotFoundResponse() {
        responseStatusCode.set(404);
        responsePayload.set("{\"error\":\"No agent matches the supplied targetId\"}");

        Captured result = execute(
                "--agent", "missing-agent",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.FAILURE, result.exitCode());
        assertTrue(result.err().contains("Not Found (HTTP 404)"));
    }

    @Test
    @DisplayName("C-008: HTTP 503 exits 1 and reports the partial propagation")
    void testServiceUnavailableResponse() {
        responseStatusCode.set(503);
        responsePayload.set("{\"error\":\"Peer propagation timed out\"}");

        Captured result = execute(
                "--target-type", "global",
                "--confirm-lockdown",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.FAILURE, result.exitCode());
        assertTrue(result.err().contains("Service Unavailable (HTTP 503)"));
        assertTrue(result.err().contains("remain in force"));
    }

    @Test
    @DisplayName("FEAT-010: Connection failure to the gateway exits 1")
    void testConnectionFailure() {
        Captured result = execute(
                "--agent", "rogue-agent",
                "--gateway", "http://localhost:65530");

        assertEquals(ExitCode.FAILURE, result.exitCode());
        assertTrue(result.err().contains("Failed to connect to AegisMCP Gateway"));
    }

    @Test
    @DisplayName("C-008: A 200 without a valid response body exits 1 instead of inventing values")
    void testMalformedSuccessResponse() {
        responseStatusCode.set(200);
        responsePayload.set("{\"status\":\"EXECUTED\"}");

        Captured result = execute(
                "--agent", "rogue-agent",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.FAILURE, result.exitCode());
        assertTrue(result.err().contains("without a valid C-008 response body"));
    }

    @Test
    @DisplayName("C-008: A status that contradicts the target type exits 1")
    void testContradictorySuccessStatus() {
        responseStatusCode.set(200);
        responsePayload.set("""
                {"status":"SEVERED","affectedSessions":1,"timestamp":"2026-10-21T10:16:00Z"}
                """);

        Captured result = execute(
                "--agent", "rogue-agent",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.FAILURE, result.exitCode());
        assertTrue(result.err().contains("expected 'QUARANTINED'"));
    }

    @Test
    @DisplayName("C-008 / FEAT-005: A gateway error body is redacted, never echoed verbatim")
    void testGatewayErrorBodyIsRedacted() {
        responseStatusCode.set(400);
        responsePayload.set("{\"error\":\"refused credential " + AWS_KEY + "\"}");

        Captured result = execute(
                "--agent", "rogue-agent",
                "--gateway", "http://localhost:" + mockPort);

        assertEquals(ExitCode.USAGE, result.exitCode());
        assertFalse(result.err().contains(AWS_KEY), "a credential-shaped value must be redacted");
        assertTrue(result.err().contains("[REDACTED_SECRET:AWS_KEY]"));
    }

    @Test
    @DisplayName("C-008: An invalid gateway URL is a usage error")
    void testInvalidGatewayUrl() {
        Captured result = execute(
                "--agent", "rogue-agent",
                "--gateway", "not a url");

        assertEquals(ExitCode.USAGE, result.exitCode());
    }

    @Test
    @DisplayName("C-008: The kill help advertises exactly the contract target vocabulary")
    void testKillHelpMatchesContract() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();
        int exitCode = AegisCliMain.execute(new PrintWriter(out), new PrintWriter(err), "kill", "--help");

        assertEquals(ExitCode.SUCCESS, exitCode);
        String help = out.toString();
        assertTrue(help.contains("session, agent, server, or global"));
        assertTrue(help.contains("--second-approver"));
        assertFalse(help.matches("(?s).*\\btool\\b.*"), "the internal 'tool' target must not be advertised");
    }

    private JsonNode readBody() {
        assertNotNull(lastReceivedBody.get());
        try {
            return mapper.readTree(lastReceivedBody.get());
        } catch (Exception e) {
            throw new AssertionError("Gateway request body was not JSON", e);
        }
    }

    private Captured execute(String... args) {
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origOut = System.out;
        PrintStream origErr = System.err;

        try {
            System.setOut(new PrintStream(outContent, true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(errContent, true, StandardCharsets.UTF_8));

            int exitCode = new CommandLine(new KillCommand()).execute(args);
            return new Captured(exitCode,
                    outContent.toString(StandardCharsets.UTF_8),
                    errContent.toString(StandardCharsets.UTF_8));
        } finally {
            System.setOut(origOut);
            System.setErr(origErr);
        }
    }

    private record Captured(int exitCode, String out, String err) {
    }
}
