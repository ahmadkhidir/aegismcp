package dev.aegismcp.cli;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the reflective signal bridge end to end: the helper process installs the real handlers,
 * raises the signal against itself, and halts from the handler with the documented status.
 *
 * <p>This runs on Windows too, where POSIX delivery to another process is unavailable; the helper
 * raises the signal in its own process so the test runner's handlers are never touched.
 *
 * <p>Anchors: FEAT-003, NFR-006.
 */
class SignalBridgeTest {

    @Test
    @Timeout(30)
    @DisplayName("FEAT-003: the INT handler runs and halts with 130")
    void testIntHandler() throws Exception {
        assertProbe("INT", ExitCode.INTERRUPTED);
    }

    @Test
    @Timeout(30)
    @DisplayName("FEAT-003: the TERM handler runs and halts with 143")
    void testTermHandler() throws Exception {
        assertProbe("TERM", ExitCode.TERMINATED);
    }

    private void assertProbe(String signal, int expectedExitCode) throws Exception {
        String javaBin = ProcessHandle.current().info().command()
                .orElse(System.getProperty("java.home") + "/bin/java");
        String classPath = System.getProperty("java.class.path");

        Process probe = new ProcessBuilder(
                javaBin, "-cp", classPath, "dev.aegismcp.cli.SignalBridgeProbe", signal)
                .redirectErrorStream(true)
                .start();

        String output;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(probe.getInputStream(), StandardCharsets.UTF_8))) {
            output = reader.lines().reduce("", (left, right) -> left + right + "\n");
        }
        boolean finished = probe.waitFor(10, TimeUnit.SECONDS);
        if (!finished) {
            probe.destroyForcibly();
        }

        Assumptions.assumeFalse(output.contains("UNSUPPORTED"),
                "this platform's JDK does not expose a " + signal + " handler");
        assertTrue(finished, "the probe must exit");
        assertTrue(output.contains("HANDLED " + signal + " " + expectedExitCode),
                "the " + signal + " handler must run. Output: " + output);
        assertEquals(expectedExitCode, probe.exitValue(),
                "the handler must halt with the documented status. OS: "
                        + System.getProperty("os.name").toLowerCase(Locale.ROOT));
    }
}
