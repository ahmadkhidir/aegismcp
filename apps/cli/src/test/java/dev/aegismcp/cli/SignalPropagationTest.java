package dev.aegismcp.cli;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end signal tests against the real {@code aegis-cli} entrypoint. The CLI is started as its
 * own process, wrapping a child that itself spawns a grandchild; the test then sends the POSIX signal
 * to the CLI and asserts the documented exit status and that no grandchild survives.
 *
 * <p>Skipped on Windows, which has no POSIX signal delivery for a child JVM through a Java process
 * handle; the tree-reaping behaviour itself is covered on every platform by
 * {@link StdioProxyTest#testTerminationReapsGrandchildren()}.
 *
 * <p>Anchors: FEAT-003, NFR-006.
 */
class SignalPropagationTest {

    @TempDir
    Path tempDir;

    @Test
    @Timeout(90)
    @DisplayName("FEAT-003: SIGTERM is forwarded and the CLI exits 143 with no orphan")
    void testSigtermPropagates() throws Exception {
        assertSignal("TERM", ExitCode.TERMINATED);
    }

    @Test
    @Timeout(90)
    @DisplayName("FEAT-003: SIGINT is forwarded and the CLI exits 130 with no orphan")
    void testSigintPropagates() throws Exception {
        assertSignal("INT", ExitCode.INTERRUPTED);
    }

    private void assertSignal(String signal, int expectedExitCode) throws Exception {
        Assumptions.assumeFalse(
                System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win"),
                "POSIX signal delivery is not available on Windows");

        Path policyFile = tempDir.resolve("signal-policy.yaml");
        Files.writeString(policyFile, """
                id: signal-policy
                name: Signal Propagation Test
                version: 1.0.0
                rules: []
                """);

        String javaBin = ProcessHandle.current().info().command()
                .orElse(System.getProperty("java.home") + "/bin/java");
        String classPath = System.getProperty("java.class.path");

        Process cli = new ProcessBuilder(
                javaBin, "-cp", classPath, "dev.aegismcp.cli.AegisCliMain",
                "wrap", "-p", policyFile.toString(), "--color=never", "--",
                javaBin, "-cp", classPath, "dev.aegismcp.cli.MockMcpChildServer", "spawn-grandchild")
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();

        try {
            long grandchildPid = awaitGrandchildPid(cli);
            assertTrue(grandchildPid > 0, "the wrapped child must announce its grandchild");

            Process kill = new ProcessBuilder("/bin/sh", "-c", "kill -" + signal + " " + cli.pid()).start();
            assertTrue(kill.waitFor(10, TimeUnit.SECONDS), "the signal command must finish");

            assertTrue(cli.waitFor(30, TimeUnit.SECONDS), "the CLI must exit after the signal");
            assertEquals(expectedExitCode, cli.exitValue(),
                    "the CLI must report the documented signal exit status");
            assertTrue(awaitGone(grandchildPid, 10_000L),
                    "the grandchild must not survive the terminated CLI");
        } finally {
            cli.destroyForcibly();
        }
    }

    private long awaitGrandchildPid(Process cli) throws Exception {
        try (ExecutorService executor = Executors.newSingleThreadExecutor();
             BufferedReader reader = new BufferedReader(
                     new InputStreamReader(cli.getInputStream(), StandardCharsets.UTF_8))) {
            Future<Long> pid = executor.submit(() -> {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("GRANDCHILD_PID=")) {
                        return Long.parseLong(line.substring("GRANDCHILD_PID=".length()).trim());
                    }
                }
                return -1L;
            });
            return pid.get(30, TimeUnit.SECONDS);
        }
    }

    private static boolean awaitGone(long pid, long timeoutMillis) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (System.currentTimeMillis() < deadline) {
            boolean alive = ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false);
            if (!alive) {
                return true;
            }
            Thread.sleep(50);
        }
        return ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false) == false;
    }
}
