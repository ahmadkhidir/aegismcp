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

        assertEquals(ExitCode.USAGE, exitCode);
        assertTrue(err.toString().contains("--color"));
    }

    @Test
    @DisplayName("FEAT-003: --help documents every exit code the CLI returns")
    void testHelpDocumentsExitCodes() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(new PrintWriter(out), new PrintWriter(err), "--help");

        assertEquals(ExitCode.SUCCESS, exitCode);
        String help = out.toString();
        assertTrue(help.contains("Exit codes:"));
        assertTrue(help.contains("130  interrupted"));
        assertTrue(help.contains("143  terminated"));
    }

    @Test
    @DisplayName("FEAT-003 AC: an unknown option exits 2, writes usage to stderr, and leaves stdout empty")
    void testUnknownOptionIsAUsageError() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(new PrintWriter(out), new PrintWriter(err), "--bogus");

        assertEquals(ExitCode.USAGE, exitCode);
        assertEquals("", out.toString(), "a usage error must not write to standard output");
        assertTrue(err.toString().contains("Unknown option"));
        assertTrue(err.toString().contains("Usage: aegis-cli"));
    }

    @Test
    @DisplayName("FEAT-003 AC: a missing required option exits 2 and writes nothing to stdout")
    void testMissingRequiredOptionIsAUsageError() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(new PrintWriter(out), new PrintWriter(err), "wrap");

        assertEquals(ExitCode.USAGE, exitCode);
        assertEquals("", out.toString());
        assertTrue(err.toString().contains("Missing required option"));
    }

    @Test
    @DisplayName("FEAT-003: wrap help does not advertise the removed --upstream transport switch")
    void testWrapHelpHasNoUpstreamSwitch() {
        StringWriter out = new StringWriter();
        StringWriter err = new StringWriter();

        int exitCode = AegisCliMain.execute(new PrintWriter(out), new PrintWriter(err), "wrap", "--help");

        assertEquals(ExitCode.SUCCESS, exitCode);
        assertFalse(out.toString().contains("--upstream"));
        assertFalse(out.toString().contains("sse"));
    }
}
