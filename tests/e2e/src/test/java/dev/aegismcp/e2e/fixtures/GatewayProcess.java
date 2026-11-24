package dev.aegismcp.e2e.fixtures;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Launches the packaged gateway distribution in a child process and discovers the port it binds
 * from its own startup line.
 *
 * <p>The test JVM never constructs a server, handler, interceptor, or Netty pipeline. The child is
 * the installed launcher produced by {@code :services:gateway:installDist}; when the distribution is
 * absent (a clean checkout) it is built once with the repository's wrapper, then launched. stdout and
 * stderr are drained concurrently into a bounded tail so a full pipe cannot deadlock the child, and
 * every wait is bounded and fails with the captured output.
 */
public final class GatewayProcess implements AutoCloseable {

    private static final Duration STARTUP_TIMEOUT = Duration.ofSeconds(45);
    private static final Pattern BOUND_PORT =
            Pattern.compile("started successfully on [^:]+:(\\d+)");

    private static final ReentrantLock INSTALL_LOCK = new ReentrantLock();
    private static volatile Path installedLauncher;

    private final Process process;
    private final int port;
    private final Deque<String> outputTail;
    private final Thread stdoutDrainer;
    private final Thread stderrDrainer;
    private final Path temporaryDirectory;

    private GatewayProcess(Process process, int port, Path temporaryDirectory, Deque<String> outputTail,
                           Thread stdoutDrainer, Thread stderrDrainer) {
        this.process = process;
        this.port = port;
        this.temporaryDirectory = temporaryDirectory;
        this.outputTail = outputTail;
        this.stdoutDrainer = stdoutDrainer;
        this.stderrDrainer = stderrDrainer;
    }

    /**
     * Starts the artifact with the supplied environment overrides. The process inherits nothing
     * from the test JVM's {@code AEGIS_*} namespace, so parallel suites cannot contaminate it.
     */
    public static GatewayProcess start(Map<String, String> overrides) throws Exception {
        Path repositoryRoot = repositoryRoot();
        Path launcher = ensureInstalled(repositoryRoot);
        Path workDirectory = Files.createTempDirectory("aegis-e2e-gateway-");

        List<String> command = new ArrayList<>();
        boolean windows = isWindows();
        if (windows) {
            command.add(System.getenv().getOrDefault("ComSpec", "cmd.exe"));
            command.add("/d");
            command.add("/s");
            command.add("/c");
            command.add("\"" + launcher.toAbsolutePath() + "\"");
        } else {
            command.add(launcher.toAbsolutePath().toString());
        }

        ProcessBuilder builder = new ProcessBuilder(command)
                .directory(workDirectory.toFile());
        Map<String, String> environment = builder.environment();
        environment.keySet().removeIf(key -> key.toUpperCase(Locale.ROOT).startsWith("AEGIS_"));
        environment.putAll(overrides);
        builder.redirectErrorStream(false);

        Process process = builder.start();
        Deque<String> tail = new ArrayDeque<>();
        Thread stdout = drain("gateway-stdout", process.getInputStream(), tail, true);
        Thread stderr = drain("gateway-stderr", process.getErrorStream(), tail, false);

        long deadline = System.nanoTime() + STARTUP_TIMEOUT.toNanos();
        Matcher matcher;
        while (true) {
            matcher = BOUND_PORT.matcher(snapshot(tail));
            if (matcher.find()) {
                break;
            }
            if (!process.isAlive()) {
                String captured = snapshot(tail);
                stop(process);
                deleteRecursively(workDirectory);
                throw new IllegalStateException(
                        "The packaged gateway exited before reporting a bound port.\n" + captured);
            }
            if (System.nanoTime() > deadline) {
                String captured = snapshot(tail);
                stop(process);
                deleteRecursively(workDirectory);
                throw new IllegalStateException(
                        "The packaged gateway did not report a bound port within "
                                + STARTUP_TIMEOUT.toSeconds() + "s.\n" + captured);
            }
            Thread.sleep(100);
        }

        int port = Integer.parseInt(matcher.group(1));
        return new GatewayProcess(process, port, workDirectory, tail, stdout, stderr);
    }

    public int port() {
        return port;
    }

    public boolean isAlive() {
        return process.isAlive();
    }

    /** The captured stdout and stderr tail, used in failure messages. */
    public String output() {
        return snapshot(outputTail);
    }

    private static synchronized String snapshot(Deque<String> tail) {
        return String.join("\n", tail);
    }

    private static Thread drain(String name, java.io.InputStream stream, Deque<String> tail, boolean stdout) {
        Thread thread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    synchronized (tail) {
                        tail.addLast((stdout ? "[out] " : "[err] ") + line);
                        while (tail.size() > 300) {
                            tail.removeFirst();
                        }
                    }
                }
            } catch (IOException ignored) {
                // The stream closes when the child exits; the tail already holds its output.
            }
        }, name);
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static Path ensureInstalled(Path repositoryRoot) throws Exception {
        Path launcher = repositoryRoot.resolve("services/gateway/build/install/gateway/bin")
                .resolve(isWindows() ? "gateway.bat" : "gateway");
        Path installDirectory = repositoryRoot.resolve("services/gateway/build/install/gateway");

        Path cached = installedLauncher;
        if (cached != null && Files.isRegularFile(cached) && !isStale(installDirectory,
                repositoryRoot.resolve("services/gateway"))) {
            return cached;
        }
        INSTALL_LOCK.lock();
        try {
            if (Files.isRegularFile(launcher) && !isStale(installDirectory,
                    repositoryRoot.resolve("services/gateway"))) {
                installedLauncher = launcher;
                return launcher;
            }
            buildDistribution(repositoryRoot);
            if (!Files.isRegularFile(launcher)) {
                throw new IllegalStateException("The gateway distribution launcher is missing: " + launcher);
            }
            installedLauncher = launcher;
            return launcher;
        } finally {
            INSTALL_LOCK.unlock();
        }
    }

    /**
     * True when a source file under the module is newer than the installed distribution, so a run
     * never evaluates a stale artifact built from older sources.
     */
    private static boolean isStale(Path installDirectory, Path moduleDirectory) {
        if (!Files.isDirectory(installDirectory)) {
            return true;
        }
        long installedAt;
        try {
            installedAt = Files.getLastModifiedTime(installDirectory).toMillis();
        } catch (IOException e) {
            return true;
        }
        long newestSource = newestSourceMillis(moduleDirectory.resolve("src/main"));
        long buildFile = newestSourceMillis(moduleDirectory.resolve("build.gradle.kts"));
        return Math.max(newestSource, buildFile) > installedAt;
    }

    private static long newestSourceMillis(Path root) {
        if (!Files.exists(root)) {
            return 0L;
        }
        try (var paths = Files.walk(root)) {
            return paths.filter(Files::isRegularFile)
                    .mapToLong(path -> {
                        try {
                            return Files.getLastModifiedTime(path).toMillis();
                        } catch (IOException e) {
                            return 0L;
                        }
                    })
                    .max()
                    .orElse(0L);
        } catch (IOException e) {
            return 0L;
        }
    }

    private static void buildDistribution(Path repositoryRoot) throws Exception {
        Path wrapper = repositoryRoot.resolve(isWindows() ? "gradlew.bat" : "gradlew");
        if (!Files.isRegularFile(wrapper)) {
            throw new IllegalStateException("The Gradle wrapper is missing: " + wrapper);
        }
        List<String> command = new ArrayList<>();
        if (isWindows()) {
            command.add(System.getenv().getOrDefault("ComSpec", "cmd.exe"));
            command.add("/d");
            command.add("/s");
            command.add("/c");
            command.add("\"" + wrapper.toAbsolutePath() + "\"");
        } else {
            command.add(wrapper.toAbsolutePath().toString());
        }
        command.add(":services:gateway:installDist");
        command.add("--console=plain");

        ProcessBuilder builder = new ProcessBuilder(command).directory(repositoryRoot.toFile());
        builder.redirectErrorStream(true);
        Process build = builder.start();
        StringBuilder log = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(build.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                log.append(line).append('\n');
            }
        }
        if (!build.waitFor(10, TimeUnit.MINUTES)) {
            build.destroyForcibly();
            throw new IllegalStateException("Building the gateway distribution timed out");
        }
        if (build.exitValue() != 0) {
            throw new IllegalStateException(
                    "Building the gateway distribution failed with exit status " + build.exitValue()
                            + ":\n" + log);
        }
    }

    /** The repository root, found by walking up from the test working directory. */
    public static Path repositoryRoot() {
        Path current = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (current != null) {
            if (Files.isRegularFile(current.resolve("settings.gradle.kts"))) {
                return current;
            }
            current = current.getParent();
        }
        throw new IllegalStateException("Could not locate the repository root from "
                + System.getProperty("user.dir"));
    }

    /** Builds the CLI distribution once and returns its launcher. */
    public static Path cliLauncher() throws Exception {
        Path repositoryRoot = repositoryRoot();
        Path installDirectory = repositoryRoot.resolve("apps/cli/build/install/aegis-cli");
        Path launcher = repositoryRoot.resolve("apps/cli/build/install/aegis-cli/bin")
                .resolve(isWindows() ? "aegis-cli.bat" : "aegis-cli");
        if (Files.isRegularFile(launcher)
                && !isStale(installDirectory, repositoryRoot.resolve("apps/cli"))) {
            return launcher;
        }
        Path wrapper = repositoryRoot.resolve(isWindows() ? "gradlew.bat" : "gradlew");
        List<String> command = new ArrayList<>();
        if (isWindows()) {
            command.add(System.getenv().getOrDefault("ComSpec", "cmd.exe"));
            command.add("/d");
            command.add("/s");
            command.add("/c");
            command.add("\"" + wrapper.toAbsolutePath() + "\"");
        } else {
            command.add(wrapper.toAbsolutePath().toString());
        }
        command.add(":apps:cli:installDist");
        command.add("--console=plain");
        ProcessBuilder builder = new ProcessBuilder(command).directory(repositoryRoot.toFile());
        builder.redirectErrorStream(true);
        Process build = builder.start();
        StringBuilder log = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(build.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                log.append(line).append('\n');
            }
        }
        build.waitFor(10, TimeUnit.MINUTES);
        if (build.exitValue() != 0) {
            throw new IllegalStateException("Building the CLI distribution failed:\n" + log);
        }
        return launcher;
    }

    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    @Override
    public void close() {
        stop(process);
        try {
            stdoutDrainer.join(2_000);
            stderrDrainer.join(2_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        deleteRecursively(temporaryDirectory);
    }

    private static void stop(Process process) {
        if (process == null) {
            return;
        }
        if (isWindows() && process.isAlive()) {
            // The batch launcher spawns the JVM as a child; taskkill /T is the platform-owned way
            // to terminate the whole tree, so no gateway JVM survives its test.
            try {
                Process killer = new ProcessBuilder("taskkill", "/PID",
                        String.valueOf(process.pid()), "/T", "/F")
                        .redirectErrorStream(true)
                        .start();
                killer.getInputStream().readAllBytes();
                killer.waitFor(10, TimeUnit.SECONDS);
            } catch (Exception ignored) {
                // Fall through to the generic destroy path.
            }
        }
        List<ProcessHandle> descendants = process.descendants().toList();
        process.destroy();
        try {
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
        for (ProcessHandle descendant : descendants) {
            if (descendant.isAlive()) {
                descendant.destroyForcibly();
            }
        }
        try {
            process.waitFor(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void deleteRecursively(Path directory) {
        if (directory == null || !Files.exists(directory)) {
            return;
        }
        try (var paths = Files.walk(directory)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // Best-effort cleanup; the operating system reclaims the temporary directory.
                }
            });
        } catch (IOException ignored) {
            // Best-effort cleanup.
        }
    }
}
