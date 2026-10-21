package dev.aegismcp.cli;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the root {@link AegisCliMain} entrypoint.
 * Anchors: FEAT-003, FEAT-010.
 */
class AegisCliMainTest {

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
}
