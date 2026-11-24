package dev.aegismcp.e2e.fixtures;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the artifact boot wait's failure paths with deliberately failing launchers.
 *
 * <p>The wait must be bounded, tolerate a launcher that is still making progress, report the
 * captured startup output when the budget expires, and surface a startup failure as its own
 * diagnosable condition rather than a contract assertion result. Every launch here is a throwaway
 * script, so the timeout path is exercised without a production defect and without building the
 * gateway distribution (NFR-005).
 */
class GatewayProcessStartupTest {

    @TempDir
    Path workDirectory;

    @Test
    void aLauncherThatNeverBindsFailsAtTheReadinessBudgetWithItsCapturedLog() throws Exception {
        Path marker = workDirectory.resolve("launched-lines.txt");
        List<String> command = launcher("""
                printf 'launched\\n' >> "%MARKER%"
                echo "[boot] deliberate launcher that never announces a bound port"
                sleep 60
                """.replace("%MARKER%", marker.toAbsolutePath().toString()));

        long startedAt = System.nanoTime();
        GatewayStartupException failure = assertThrows(GatewayStartupException.class,
                () -> GatewayProcess.start(command, "deliberately silent launcher", Map.of(),
                        Duration.ofSeconds(8), Duration.ofSeconds(15)));
        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);

        assertEquals(GatewayStartupException.Failure.READINESS_TIMEOUT, failure.failure(),
                "a live child that never binds must be reported as a readiness timeout");
        assertTrue(failure.getMessage().contains("readiness timeout"),
                "the failure message names the cause: " + failure.getMessage());
        assertTrue(failure.getMessage().contains("not a contract assertion result"),
                "the failure message separates startup failure from assertion failure");
        assertTrue(failure.getMessage().contains("[boot] deliberate launcher"),
                "the captured startup log is part of the failure: " + failure.getMessage());
        assertTrue(failure.capturedOutput().contains("[boot] deliberate launcher"),
                "the captured output is available programmatically");
        assertTrue(elapsedMillis >= 7_000 && elapsedMillis < 30_000,
                "progress extends the budget while the wait stays bounded; it took "
                        + elapsedMillis + "ms");
        assertEquals(1, Files.readAllLines(marker).size(),
                "the harness must never relaunch a failed startup");
    }

    @Test
    void aLauncherThatKeepsLoggingStillFailsAtTheHardCeiling() throws Exception {
        List<String> command = launcher("""
                while true; do
                    echo "[boot] still starting"
                    sleep 0.2
                done
                """);

        long startedAt = System.nanoTime();
        GatewayStartupException failure = assertThrows(GatewayStartupException.class,
                () -> GatewayProcess.start(command, "deliberately chatty launcher", Map.of(),
                        Duration.ofSeconds(5), Duration.ofSeconds(10)));
        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);

        assertEquals(GatewayStartupException.Failure.READINESS_TIMEOUT, failure.failure(),
                "a launcher that never binds must still time out");
        assertTrue(elapsedMillis >= 8_000 && elapsedMillis < 35_000,
                "progress extends the budget but the hard ceiling bounds it; it took "
                        + elapsedMillis + "ms");
    }

    @Test
    void anExitedLauncherIsReportedImmediatelyWithItsStatusAndOutput() throws Exception {
        Path marker = workDirectory.resolve("exited-lines.txt");
        List<String> command = launcher("""
                printf 'launched\\n' >> "%MARKER%"
                echo "[boot] refusing to start with an invalid configuration"
                echo "[boot] configuration is invalid" 1>&2
                exit 7
                """.replace("%MARKER%", marker.toAbsolutePath().toString()));

        long startedAt = System.nanoTime();
        GatewayStartupException failure = assertThrows(GatewayStartupException.class,
                () -> GatewayProcess.start(command, "deliberately failing launcher", Map.of(),
                        Duration.ofSeconds(30), Duration.ofSeconds(60)));
        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);

        assertEquals(GatewayStartupException.Failure.PROCESS_EXITED, failure.failure(),
                "an early exit is distinct from a readiness timeout");
        assertTrue(failure.getMessage().contains("exited with status 7"),
                "the failure names the exit status: " + failure.getMessage());
        assertTrue(failure.capturedOutput().contains("[boot] configuration is invalid"),
                "stderr is part of the captured startup log: " + failure.capturedOutput());
        assertTrue(elapsedMillis < 15_000,
                "an exited launcher must not wait out its budget; it took " + elapsedMillis + "ms");
        assertEquals(1, Files.readAllLines(marker).size(),
                "the harness must never relaunch a failed startup");
    }

    @Test
    void anUnstartableLauncherIsReportedAsALaunchFailure() {
        Path missing = workDirectory.resolve("missing-launcher");

        GatewayStartupException failure = assertThrows(GatewayStartupException.class,
                () -> GatewayProcess.start(List.of(missing.toAbsolutePath().toString()),
                        "missing launcher", Map.of(), Duration.ofSeconds(1), Duration.ofSeconds(2)));

        assertEquals(GatewayStartupException.Failure.LAUNCH_FAILED, failure.failure());
        assertTrue(failure.getMessage().contains("could not be started"),
                "the failure names the cause: " + failure.getMessage());
    }

    /**
     * Writes a deliberately failing launcher into the test's temporary directory and returns the
     * platform command that runs it. The body is POSIX shell; Windows receives a batch translation
     * of the same steps so both platforms exercise the same wait.
     */
    private List<String> launcher(String posixBody) throws Exception {
        boolean windows = GatewayProcess.isWindows();
        Path script = workDirectory.resolve(
                windows ? "deliberate-launcher.bat" : "deliberate-launcher.sh");
        if (windows) {
            Files.writeString(script, windowsBatch(posixBody));
            return List.of(System.getenv().getOrDefault("ComSpec", "cmd.exe"),
                    "/d", "/s", "/c", "\"" + script.toAbsolutePath() + "\"");
        }
        Files.writeString(script, "#!/bin/sh\n" + posixBody);
        script.toFile().setExecutable(true);
        return List.of("/bin/sh", script.toAbsolutePath().toString());
    }

    /** Translates the small launcher bodies above into the equivalent batch commands. */
    private static String windowsBatch(String posixBody) {
        StringBuilder batch = new StringBuilder("@echo off\r\n");
        for (String line : posixBody.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (trimmed.startsWith("printf 'launched")) {
                String path = trimmed.substring(trimmed.indexOf('"') + 1, trimmed.lastIndexOf('"'));
                batch.append("echo launched>>\"").append(path).append("\"\r\n");
            } else if (trimmed.startsWith("echo ")) {
                boolean stderr = trimmed.endsWith("1>&2");
                String text = trimmed.substring("echo ".length(), trimmed.length() - (stderr ? 5 : 0));
                batch.append("echo ").append(text).append(stderr ? " 1>&2" : "").append("\r\n");
            } else if (trimmed.startsWith("while true;")) {
                batch.append(":progress\r\n")
                        .append("echo [boot] still starting\r\n")
                        .append("ping -n 2 127.0.0.1 >nul\r\n")
                        .append("goto progress\r\n");
                return batch.toString();
            } else if (trimmed.equals("sleep 60")) {
                batch.append("ping -n 61 127.0.0.1 >nul\r\n");
            } else if (trimmed.equals("exit 7")) {
                batch.append("exit /b 7\r\n");
            }
        }
        return batch.toString();
    }
}
