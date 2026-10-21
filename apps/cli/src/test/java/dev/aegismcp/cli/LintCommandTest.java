package dev.aegismcp.cli;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit and execution tests for the 'aegis-cli lint' command.
 * Anchors: FEAT-003, FEAT-002, NFR-027.
 */
class LintCommandTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("FEAT-003 AC 3: Valid policy YAML passes linting with exit code 0")
    void testValidPolicyLinting() throws Exception {
        String validYaml = """
                id: test-dev-policy
                name: Test Developer Policy
                version: 1.0.0
                target_agents:
                  - local-dev-agent
                  - support-bot-*
                default_action: DENY
                rules:
                  - id: allow-read
                    tool: read_file
                    action: ALLOW
                    constraints:
                      - argument: path
                        operator: STARTS_WITH
                        value: /tmp/
                  - id: allow-list
                    tool: list_directory
                    action: ALLOW
                """;

        Path policyFile = tempDir.resolve("valid-policy.yaml");
        Files.writeString(policyFile, validYaml);

        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origOut = System.out;
        PrintStream origErr = System.err;

        try {
            System.setOut(new PrintStream(outContent));
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new LintCommand());
            int exitCode = cmd.execute(policyFile.toString());

            assertEquals(0, exitCode, "Linting valid policy must exit with code 0");
            assertTrue(outContent.toString().contains("Policy 'test-dev-policy' (version: 1.0.0) is valid"));
            assertTrue(outContent.toString().contains("Total Rules:    2"));
        } finally {
            System.setOut(origOut);
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("FEAT-003 AC 3: Syntax error in YAML fails linting with exit code 1")
    void testInvalidYamlSyntaxFails() throws Exception {
        String badYaml = """
                id: bad-yaml-policy
                name: Invalid
                version: [unclosed list
                rules:
                  - tool: "foo"
                """;

        Path policyFile = tempDir.resolve("bad-syntax.yaml");
        Files.writeString(policyFile, badYaml);

        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new LintCommand());
            int exitCode = cmd.execute(policyFile.toString());

            assertEquals(1, exitCode, "Linting syntax error must exit with code 1");
            assertTrue(errContent.toString().contains("Validation Failed: Syntax or schema error"));
        } finally {
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("FEAT-003: Missing policy file fails with exit code 1")
    void testMissingFileFails() {
        Path missing = tempDir.resolve("does-not-exist.yaml");

        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new LintCommand());
            int exitCode = cmd.execute(missing.toString());

            assertEquals(1, exitCode);
            assertTrue(errContent.toString().contains("Policy file not found"));
        } finally {
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("FEAT-003: Empty policy file fails with exit code 1")
    void testEmptyFileFails() throws Exception {
        Path empty = tempDir.resolve("empty.yaml");
        Files.writeString(empty, "   \n\n  ");

        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new LintCommand());
            int exitCode = cmd.execute(empty.toString());

            assertEquals(1, exitCode);
            assertTrue(errContent.toString().contains("Policy file is empty"));
        } finally {
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("FEAT-003: Missing required policy schema properties (e.g. id) fails with exit code 1")
    void testMissingRequiredFieldsFails() throws Exception {
        String missingIdYaml = """
                name: Missing ID Policy
                version: 1.0.0
                rules:
                  - tool: test_tool
                    action: ALLOW
                """;

        Path policyFile = tempDir.resolve("missing-id.yaml");
        Files.writeString(policyFile, missingIdYaml);

        ByteArrayOutputStream errContent = new ByteArrayOutputStream();
        PrintStream origErr = System.err;

        try {
            System.setErr(new PrintStream(errContent));

            CommandLine cmd = new CommandLine(new LintCommand());
            int exitCode = cmd.execute(policyFile.toString());

            assertEquals(1, exitCode);
            assertTrue(errContent.toString().contains("Validation Failed"));
        } finally {
            System.setErr(origErr);
        }
    }

    @Test
    @DisplayName("FEAT-003 / NFR-027: Detects unreachable and shadowed rules in policy")
    void testDetectUnreachableRules() throws Exception {
        String shadowedYaml = """
                id: shadowed-policy
                name: Shadowed Rules Test
                version: 1.0.0
                rules:
                  - id: wildcard-allow-all
                    tool: "*"
                    action: ALLOW
                  - id: never-reached-read
                    tool: read_file
                    action: DENY
                """;

        Path policyFile = tempDir.resolve("shadowed.yaml");
        Files.writeString(policyFile, shadowedYaml);

        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        PrintStream origOut = System.out;

        try {
            System.setOut(new PrintStream(outContent));

            CommandLine cmd = new CommandLine(new LintCommand());
            int exitCode = cmd.execute(policyFile.toString());

            assertEquals(0, exitCode);
            String output = outContent.toString();
            assertTrue(output.contains("Warnings:"));
            assertTrue(output.contains("Rule 'never-reached-read' for tool 'read_file' is unreachable"));
        } finally {
            System.setOut(origOut);
        }
    }
}
