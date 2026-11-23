package dev.aegismcp.cli;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Color-resolution tests for {@link TerminalInspector}.
 * Anchors: FEAT-003, NFR-006.
 */
class TerminalInspectorTest {

    private static final String ANSI_ESCAPE = "\u001B[";

    @Test
    @DisplayName("FEAT-003: auto mode is plain when the destination is not an interactive terminal")
    void testAutoModeIsPlainWhenPiped() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        TerminalInspector inspector = new TerminalInspector(stream(buffer), ColorMode.AUTO);

        renderAll(inspector);

        String output = buffer.toString(StandardCharsets.UTF_8);
        assertTrue(output.contains("[ALLOWED]"));
        assertFalse(output.contains(ANSI_ESCAPE));
    }

    @Test
    @DisplayName("FEAT-003: never mode is plain even when the destination is a terminal")
    void testNeverModeIsPlainOnTerminal() {
        assertFalse(TerminalInspector.isColorEnabled(ColorMode.NEVER, true));

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        renderAll(new TerminalInspector(stream(buffer), ColorMode.NEVER));

        assertFalse(buffer.toString(StandardCharsets.UTF_8).contains(ANSI_ESCAPE));
    }

    @Test
    @DisplayName("FEAT-003: always mode forces ANSI escapes on a piped destination")
    void testAlwaysModeForcesColor() {
        Assumptions.assumeTrue(
                TerminalInspector.isColorEnabled(ColorMode.ALWAYS, false),
                "NO_COLOR or a dumb terminal forces plain text");

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        renderAll(new TerminalInspector(stream(buffer), ColorMode.ALWAYS));

        assertTrue(buffer.toString(StandardCharsets.UTF_8).contains(ANSI_ESCAPE));
    }

    @Test
    @DisplayName("FEAT-003: auto mode colors an interactive terminal")
    void testAutoModeColorsTerminal() {
        Assumptions.assumeTrue(
                TerminalInspector.isColorEnabled(ColorMode.AUTO, true),
                "NO_COLOR or a dumb terminal forces plain text");

        assertTrue(TerminalInspector.isColorEnabled(ColorMode.AUTO, true));
    }

    @Test
    @DisplayName("FEAT-003: captured streams are never treated as interactive terminals")
    void testCapturedStreamIsNotInteractive() {
        assertFalse(TerminalInspector.isInteractiveTerminal(stream(new ByteArrayOutputStream())));
    }

    private static PrintStream stream(ByteArrayOutputStream buffer) {
        return new PrintStream(buffer, true, StandardCharsets.UTF_8);
    }

    private static void renderAll(TerminalInspector inspector) {
        inspector.printBanner("policy-1", "1.0.0", "npx server");
        inspector.logToolCall("read_file", null, 1.25, true, null);
        inspector.logToolCall("write_file", null, 2.5, false, "path denied");
        inspector.logMessage("operational message");
        inspector.logError("failure message");
    }
}
