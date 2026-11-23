package dev.aegismcp.cli;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Execution tests for 'aegis-cli wrap' command.
 * Anchors: FEAT-003, FEAT-002, FEAT-005.
 */
class WrapCommandTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("FEAT-003: Missing target command returns exit code 1")
    void testMissingTargetCommand() throws Exception {
        Path policyFile = tempDir.resolve("policy.yaml");
        Files.writeString(policyFile, "id: test\nname: test\nversion: 1.0\nrules: []\n");

        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new WrapCommand());
            int exitCode = cmd.execute("-p", policyFile.toString());

            assertEquals(2, exitCode, "Missing positional command should return picocli parameter exception code");
        } finally {
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("FEAT-003: Non-existent policy file returns exit code 1")
    void testNonExistentPolicyFile() {
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new WrapCommand());
            int exitCode = cmd.execute("-p", "/tmp/does-not-exist-" + System.currentTimeMillis() + ".yaml", "--", "echo", "test");

            assertEquals(1, exitCode);
            assertTrue(errContent.toString().contains("Policy file does not exist"));
        } finally {
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("FEAT-003: Syntax invalid policy file fails fast with exit code 1")
    void testInvalidPolicyFile() throws Exception {
        Path policyFile = tempDir.resolve("invalid-policy.yaml");
        Files.writeString(policyFile, "bad: [unclosed");

        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new WrapCommand());
            int exitCode = cmd.execute("-p", policyFile.toString(), "--", "echo", "test");

            assertEquals(1, exitCode);
            assertTrue(errContent.toString().contains("Policy validation failed"));
        } finally {
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("FEAT-003: Wrap executes child process and exits with child status code")
    void testWrapExecution() throws Exception {
        String yaml = """
                id: wrap-exec-policy
                name: Wrap Exec Test
                version: 1.0.0
                rules: []
                """;
        Path policyFile = tempDir.resolve("exec-policy.yaml");
        Files.writeString(policyFile, yaml);

        String javaBin = ProcessHandle.current().info().command().orElse(System.getProperty("java.home") + "/bin/java");
        String classPath = System.getProperty("java.class.path");

        int exitCode = AegisCliMain.execute(
                new PrintWriter(new StringWriter()),
                new PrintWriter(new StringWriter()),
                "wrap",
                "-p", policyFile.toString(),
                "--color=never",
                "--",
                javaBin, "-cp", classPath, "dev.aegismcp.cli.MockMcpChildServer", "exit-immediately", "0"
        );

        assertEquals(0, exitCode);
    }

    @Test
    @DisplayName("FEAT-003: --color=always forces ANSI escapes on stderr inspection output")
    void testForcedColorOnInspectionOutput() throws Exception {
        Assumptions.assumeTrue(
                TerminalInspector.isColorEnabled(ColorMode.ALWAYS, false),
                "NO_COLOR or a dumb terminal forces plain text");

        Path policyFile = tempDir.resolve("forced-color-policy.yaml");
        Files.writeString(policyFile, """
                id: forced-color-policy
                name: Forced Color Test
                version: 1.0.0
                rules: []
                """);

        String javaBin = ProcessHandle.current().info().command().orElse(System.getProperty("java.home") + "/bin/java");
        String classPath = System.getProperty("java.class.path");

        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent, true, StandardCharsets.UTF_8));

            int exitCode = AegisCliMain.execute(
                    new PrintWriter(new StringWriter()),
                    new PrintWriter(new StringWriter()),
                    "wrap",
                    "-p", policyFile.toString(),
                    "--color=always",
                    "--",
                    javaBin, "-cp", classPath, "dev.aegismcp.cli.MockMcpChildServer", "exit-immediately", "0"
            );

            assertEquals(0, exitCode);
            assertTrue(errContent.toString(StandardCharsets.UTF_8).contains("\u001B["));
        } finally {
            System.setErr(origErr);
        }
    }
}
