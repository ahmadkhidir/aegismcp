package dev.aegismcp.cli;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the root {@link AegisCliMain} entrypoint.
 * Anchors: FEAT-003, FEAT-010.
 */
class AegisCliMainTest {

    private static final String ANSI_ESCAPE = "\u001B[";

    @Test
    @DisplayName("FEAT-003: aegis-cli --help prints usage instructions with subcommands")
    void testHelpOption() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(new PrintWriter(out), new PrintWriter(err), "--help");

        assertEquals(0, exitCode);
        String output = out.toString();
        assertTrue(output.contains("aegis-cli"));
        assertTrue(output.contains("wrap"));
        assertTrue(output.contains("lint"));
        assertTrue(output.contains("kill"));
    }

    @Test
    @DisplayName("FEAT-003: aegis-cli with no arguments prints usage and exits with 0")
    void testNoArgumentsPrintsUsage() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(new PrintWriter(out), new PrintWriter(err));

        assertEquals(0, exitCode);
        String output = out.toString();
        assertTrue(output.contains("Usage: aegis-cli"));
    }

    @Test
    @DisplayName("FEAT-003: aegis-cli --version prints version information")
    void testVersionOption() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(new PrintWriter(out), new PrintWriter(err), "--version");

        assertEquals(0, exitCode);
        assertTrue(out.toString().contains("1.0.0"));
    }

    @Test
    @DisplayName("FEAT-003: captured (non-terminal) usage output carries no ANSI escapes")
    void testCapturedUsageIsPlain() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(new PrintWriter(out), new PrintWriter(err));

        assertEquals(0, exitCode);
        String output = out.toString();
        assertTrue(output.contains("Usage: aegis-cli"));
        assertFalse(output.contains(ANSI_ESCAPE), "auto mode must not color a non-terminal stream");
    }

    @Test
    @DisplayName("FEAT-003: --color=never keeps help output plain")
    void testColorNeverKeepsHelpPlain() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(
                new PrintWriter(out), new PrintWriter(err), "--color=never", "--help");

        assertEquals(0, exitCode);
        assertFalse(out.toString().contains(ANSI_ESCAPE));
    }

    @Test
    @DisplayName("FEAT-003: --color=always forces ANSI escapes on help output")
    void testColorAlwaysForcesAnsi() {
        Assumptions.assumeTrue(
                TerminalInspector.isColorEnabled(ColorMode.ALWAYS, false),
                "NO_COLOR or a dumb terminal forces plain text");

        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(
                new PrintWriter(out), new PrintWriter(err), "--color=always", "--help");

        assertEquals(0, exitCode);
        assertTrue(out.toString().contains(ANSI_ESCAPE));
    }

    @Test
    @DisplayName("FEAT-003: the color mode accepts upper case values")
    void testColorModeIsCaseInsensitive() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(
                new PrintWriter(out), new PrintWriter(err), "--color=NEVER", "--help");

        assertEquals(0, exitCode);
        assertFalse(out.toString().contains(ANSI_ESCAPE));
    }

    @Test
    @DisplayName("FEAT-003: the hidden --no-color alias forces plain text over --color")
    void testNoColorAliasWins() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(
                new PrintWriter(out), new PrintWriter(err), "--no-color", "--color=always", "--help");

        assertEquals(0, exitCode);
        assertFalse(out.toString().contains(ANSI_ESCAPE));
    }

    @Test
    @DisplayName("FEAT-003: --color accepts a separated value")
    void testColorAcceptsSeparatedValue() {
        Assumptions.assumeTrue(
                TerminalInspector.isColorEnabled(ColorMode.ALWAYS, false),
                "NO_COLOR or a dumb terminal forces plain text");

        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(
                new PrintWriter(out), new PrintWriter(err), "--color", "always", "--help");

        assertEquals(0, exitCode);
        assertTrue(out.toString().contains(ANSI_ESCAPE));
    }

    @Test
    @DisplayName("FEAT-003: an invalid color mode fails with the picocli usage-error exit code")
    void testInvalidColorModeIsRejected() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(
                new PrintWriter(out), new PrintWriter(err), "--color=sometimes", "--help");

        assertEquals(2, exitCode);
        assertTrue(err.toString().contains("--color"));
    }
}
