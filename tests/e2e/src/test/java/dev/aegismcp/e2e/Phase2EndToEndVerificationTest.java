package dev.aegismcp.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.e2e.fixtures.ArtifactTest;
import dev.aegismcp.e2e.fixtures.ContractAssertions;
import dev.aegismcp.e2e.fixtures.GatewayHarness;
import dev.aegismcp.e2e.fixtures.GatewayProcess;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 2 gate journey: verified identity, the kill switch, fleet telemetry, and the packaged CLI
 * against the launched gateway. Anchors: FEAT-003, FEAT-009, FEAT-010.
 */
class Phase2EndToEndVerificationTest extends ArtifactTest {

    @Test
    @DisplayName("Phase 2: a SPIFFE SVID authenticates the agent over mutual TLS")
    void spiffeSvidAuthenticatesOverMutualTls() throws Exception {
        GatewayHarness harness = gateway();
        HttpResponse<String> response = harness.exchange(harness.mtlsClient(),
                harness.request("/mcp/v1/rpc", null)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                GatewayHarness.toolCall("svid-1", "echo", "{}")))
                        .build());
        ContractAssertions.assertStatus(200, response);
        assertEquals("svid-1", GatewayHarness.json(response).path("id").asText());
    }

    @Test
    @DisplayName("Phase 2: an expired OIDC token and an untrusted SVID are refused")
    void refusesExpiredAndUntrustedCredentials() throws Exception {
        GatewayHarness harness = gateway();
        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", harness.expiredToken("agent-expired"),
                GatewayHarness.toolCall("expired-1", "echo", "{}")), 401, -32000, "AUTHENTICATION_FAILED");
        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", harness.tamperedToken("agent-tampered"),
                GatewayHarness.toolCall("tampered-1", "echo", "{}")), 401, -32000, "AUTHENTICATION_FAILED");
    }

    @Test
    @DisplayName("Phase 2: the kill switch quarantines an agent and the fleet reports it")
    void killSwitchJourney() throws Exception {
        GatewayHarness harness = gateway();
        String agent = "phase2-rogue";
        harness.createPendingCall(agent, "deploy_prod", "{}");

        HttpResponse<String> kill = harness.postJson("/api/v1/emergency/kill", harness.adminToken(),
                "{\"targetType\":\"agent\",\"targetId\":\"" + agent + "\",\"reason\":\"phase 2\"}");
        ContractAssertions.assertStatus(200, kill);
        assertEquals("QUARANTINED", GatewayHarness.json(kill).path("status").asText());

        ContractAssertions.assertRpcError(harness.postJson("/mcp/v1/rpc", harness.agentToken(agent),
                GatewayHarness.toolCall("post-kill", "ping", "{}")), 403, -32001);

        JsonNode status = GatewayHarness.json(harness.get("/api/v1/system/status", harness.viewerToken()));
        assertEquals("ELEVATED", status.path("status").asText());
        JsonNode metrics = GatewayHarness.json(harness.get("/api/v1/metrics/summary", harness.viewerToken()));
        assertTrue(metrics.path("blockedViolations24h").asLong() >= 1);
    }

    @Test
    @DisplayName("Phase 2: the packaged CLI lints a policy and dispatches a kill")
    void packagedCliJourney() throws Exception {
        GatewayHarness harness = gateway();
        Path launcher = GatewayProcess.cliLauncher();
        Path policy = harness.workDirectory().resolve("policy.yaml");

        CommandResult lint = runCli(launcher, List.of("lint", policy.toString()), List.of());
        assertEquals(0, lint.exitCode, () -> "aegis-cli lint failed:\n" + lint.output);
        assertTrue(lint.output.contains("is valid"), () -> "Unexpected lint output:\n" + lint.output);

        String agent = "phase2-cli-rogue";
        harness.createPendingCall(agent, "deploy_prod", "{}");
        List<String> trustOptions = List.of(
                "-Djavax.net.ssl.trustStore=" + harness.tls().clientTruststore,
                "-Djavax.net.ssl.trustStorePassword=changeit",
                "-Djavax.net.ssl.trustStoreType=PKCS12");
        CommandResult kill = runCli(launcher, List.of(
                "kill", "--gateway", harness.baseUri().toString(), "--agent", agent,
                "--token", harness.adminToken(), "--reason", "cli journey"), trustOptions);
        assertEquals(0, kill.exitCode, () -> "aegis-cli kill failed:\n" + kill.output);
        assertTrue(kill.output.contains("QUARANTINED"), () -> "Unexpected kill output:\n" + kill.output);
    }

    @Test
    @DisplayName("Phase 2: the web console suite and production build pass")
    void webConsoleSuiteAndBuild() throws Exception {
        Path console = GatewayProcess.repositoryRoot().resolve("apps/console");
        CommandResult test = runCommand(console, npmCommand(List.of("test")));
        assertEquals(0, test.exitCode, () -> "Console tests failed:\n" + test.output);
        CommandResult build = runCommand(console, npmCommand(List.of("run", "build")));
        assertEquals(0, build.exitCode, () -> "Console build failed:\n" + build.output);
    }

    private record CommandResult(int exitCode, String output) {
    }

    private static CommandResult runCli(Path launcher, List<String> arguments, List<String> jvmOptions)
            throws Exception {
        // Launch the distribution's main class directly: the .bat shim mangles quoted arguments
        // under cmd.exe, while the java executable is portable and keeps argument boundaries.
        Path installDirectory = launcher.getParent().getParent();
        Path lib = installDirectory.resolve("lib");
        Path javaExecutable = Path.of(System.getProperty("java.home"), "bin",
                GatewayProcess.isWindows() ? "java.exe" : "java");
        List<String> command = new ArrayList<>();
        command.add(javaExecutable.toAbsolutePath().toString());
        command.addAll(jvmOptions);
        command.add("-cp");
        command.add(lib.toAbsolutePath() + java.io.File.separator + "*");
        command.add("dev.aegismcp.cli.AegisCliMain");
        command.addAll(arguments);
        ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
        return execute(builder);
    }

    private static CommandResult runCommand(Path directory, List<String> command) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(command).directory(directory.toFile()).redirectErrorStream(true);
        return execute(builder);
    }

    private static CommandResult execute(ProcessBuilder builder) throws Exception {
        Process process = builder.start();
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append('\n');
            }
        }
        if (!process.waitFor(10, TimeUnit.MINUTES)) {
            process.destroyForcibly();
            throw new IllegalStateException("The command timed out:\n" + output);
        }
        return new CommandResult(process.exitValue(), output.toString());
    }

    private static List<String> npmCommand(List<String> arguments) {
        List<String> command = new ArrayList<>();
        if (GatewayProcess.isWindows()) {
            command.add(System.getenv().getOrDefault("ComSpec", "cmd.exe"));
            command.add("/d");
            command.add("/s");
            command.add("/c");
            command.add("npm");
        } else {
            command.add("npm");
        }
        command.addAll(arguments);
        return command;
    }
}
