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
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit and integration tests for the 'aegis-cli kill' command.
 * Anchors: FEAT-010, C-008.
 */
class KillCommandTest {

    private HttpServer mockServer;
    private int mockPort;
    private final ObjectMapper mapper = new ObjectMapper();

    private final AtomicReference<String> lastReceivedPath = new AtomicReference<>();
    private final AtomicReference<String> lastReceivedMethod = new AtomicReference<>();
    private final AtomicReference<String> lastReceivedAuth = new AtomicReference<>();
    private final AtomicReference<String> lastReceivedBody = new AtomicReference<>();
    private final AtomicInteger responseStatusCode = new AtomicInteger(200);
    private final AtomicReference<String> responsePayload = new AtomicReference<>();

    @BeforeEach
    void setUp() throws IOException {
        mockServer = HttpServer.create(new InetSocketAddress(0), 0);
        mockPort = mockServer.getAddress().getPort();

        mockServer.createContext("/api/v1/emergency/kill", exchange -> {
            lastReceivedPath.set(exchange.getRequestURI().getPath());
            lastReceivedMethod.set(exchange.getRequestMethod());
            lastReceivedAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));

            byte[] bodyBytes = exchange.getRequestBody().readAllBytes();
            lastReceivedBody.set(new String(bodyBytes, StandardCharsets.UTF_8));

            int status = responseStatusCode.get();
            byte[] responseBytes = (responsePayload.get() != null ? responsePayload.get() : "{}").getBytes(StandardCharsets.UTF_8);

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
    @DisplayName("FEAT-010 AC 1 / C-008: Quarantines rogue agent via C-008 emergency management endpoint")
    void testAgentKillSuccess() throws Exception {
        responseStatusCode.set(200);
        responsePayload.set("""
                {
                  "status": "QUARANTINED",
                  "affectedSessions": 4,
                  "timestamp": "2026-10-21T10:15:30Z"
                }
                """);

        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        PrintStream origOut = System.out;

        try {
            System.setOut(new PrintStream(outContent));

            CommandLine cmd = new CommandLine(new KillCommand());
            int exitCode = cmd.execute(
                    "--agent", "support-bot-04",
                    "--gateway", "http://localhost:" + mockPort,
                    "--reason", "Infinite loop detected",
                    "--token", "test-admin-token"
            );

            assertEquals(0, exitCode, "Kill command must exit with 0 on HTTP 200");
            assertEquals("/api/v1/emergency/kill", lastReceivedPath.get());
            assertEquals("POST", lastReceivedMethod.get());
            assertEquals("Bearer test-admin-token", lastReceivedAuth.get());

            // Validate C-008 JSON payload structure
            assertNotNull(lastReceivedBody.get());
            JsonNode bodyJson = mapper.readTree(lastReceivedBody.get());
            assertEquals("agent", bodyJson.get("targetType").asText());
            assertEquals("support-bot-04", bodyJson.get("targetId").asText());
            assertEquals("Infinite loop detected", bodyJson.get("reason").asText());

            String output = outContent.toString();
            assertTrue(output.contains("Emergency kill-switch invoked successfully (HTTP 200)"));
            assertTrue(output.contains("Result Status:     QUARANTINED"));
            assertTrue(output.contains("Affected Sessions: 4"));
        } finally {
            System.setOut(origOut);
        }
    }

    @Test
    @DisplayName("FEAT-010: Global kill-switch requires --confirm-lockdown flag")
    void testGlobalKillRequiresConfirmation() {
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new KillCommand());
            int exitCode = cmd.execute(
                    "--target-type", "global",
                    "--gateway", "http://localhost:" + mockPort
            );

            assertEquals(1, exitCode, "Global kill without confirmation must fail");
            assertTrue(errContent.toString().contains("Global kill-switch lockdown requires explicit '--confirm-lockdown' flag"));
        } finally {
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("FEAT-010 / C-008: Global kill-switch with --confirm-lockdown succeeds")
    void testGlobalKillWithConfirmation() throws Exception {
        responseStatusCode.set(200);
        responsePayload.set("""
                {
                  "status": "SEVERED",
                  "affectedSessions": 42,
                  "timestamp": "2026-10-21T10:16:00Z"
                }
                """);

        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        PrintStream origOut = System.out;

        try {
            System.setOut(new PrintStream(outContent));

            CommandLine cmd = new CommandLine(new KillCommand());
            int exitCode = cmd.execute(
                    "--target-type", "global",
                    "--confirm-lockdown",
                    "--gateway", "http://localhost:" + mockPort,
                    "--reason", "Compromised cluster state"
            );

            assertEquals(0, exitCode);
            JsonNode bodyJson = mapper.readTree(lastReceivedBody.get());
            assertEquals("global", bodyJson.get("targetType").asText());
            assertEquals("global", bodyJson.get("targetId").asText());
            assertTrue(outContent.toString().contains("Result Status:     SEVERED"));
        } finally {
            System.setOut(origOut);
        }
    }

    @Test
    @DisplayName("C-008: HTTP 400 Bad Request error returns exit code 1")
    void testBadRequestResponse() {
        responseStatusCode.set(400);
        responsePayload.set("{\"error\":\"Invalid target type\"}");

        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new KillCommand());
            int exitCode = cmd.execute(
                    "--agent", "rogue-agent",
                    "--gateway", "http://localhost:" + mockPort
            );

            assertEquals(1, exitCode);
            assertTrue(errContent.toString().contains("Bad Request (HTTP 400)"));
        } finally {
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("C-008: HTTP 401 Unauthorized returns exit code 1 and prompts for admin token")
    void testUnauthorizedResponse() {
        responseStatusCode.set(401);
        responsePayload.set("{\"error\":\"Unauthorized\"}");

        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new KillCommand());
            int exitCode = cmd.execute(
                    "--agent", "rogue-agent",
                    "--gateway", "http://localhost:" + mockPort
            );

            assertEquals(1, exitCode);
            assertTrue(errContent.toString().contains("Unauthorized (HTTP 401)"));
        } finally {
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("C-008: HTTP 403 Forbidden returns exit code 1")
    void testForbiddenResponse() {
        responseStatusCode.set(403);
        responsePayload.set("{\"error\":\"Forbidden\"}");

        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new KillCommand());
            int exitCode = cmd.execute(
                    "--agent", "rogue-agent",
                    "--gateway", "http://localhost:" + mockPort
            );

            assertEquals(1, exitCode);
            assertTrue(errContent.toString().contains("Forbidden (HTTP 403)"));
        } finally {
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("FEAT-010: Connection failure to gateway prints clear error and exits with 1")
    void testConnectionFailure() {
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            // Use an unallocated port to trigger connection failure
            CommandLine cmd = new CommandLine(new KillCommand());
            int exitCode = cmd.execute(
                    "--agent", "rogue-agent",
                    "--gateway", "http://localhost:65530"
            );

            assertEquals(1, exitCode);
            assertTrue(errContent.toString().contains("Failed to connect to AegisMCP Gateway"));
        } finally {
            System.setErr(origErr);
        }
    }
}
