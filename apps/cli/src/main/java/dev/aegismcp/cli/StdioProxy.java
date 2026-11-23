package dev.aegismcp.cli;

import com.fasterxml.jackson.databind.JsonNode;
import dev.aegismcp.gateway.codec.JsonRpcCodec;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.codec.JsonRpcResponse;
import dev.aegismcp.gateway.dlp.DlpScrubber;
import dev.aegismcp.gateway.policy.PolicyEvaluationResult;
import dev.aegismcp.gateway.policy.PolicyEvaluator;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * High-performance Stdio proxy intercepting JSON-RPC MCP messages between parent client and child
 * server. Evaluates tool calls against declarative policies, scrubs responses via the DLP engine,
 * and logs inspections.
 *
 * <p>Child lifecycle is hermetic (FEAT-003): the child is spawned only after the command has
 * validated its inputs; standard output and standard error are drained on their own virtual threads
 * from the first byte; the child's input is closed on parent EOF; the child and every descendant are
 * terminated on interruption, signal, or exit so no orphan outlives the CLI. A non-zero child status
 * is reported and mapped onto {@link ExitCode#FAILURE}, because a raw status could collide with a
 * code the CLI documents for a different outcome.
 *
 * <p>Anchors: FEAT-003, FEAT-005, NFR-001, NFR-002, C-001.
 */
public class StdioProxy {

    private static final Logger logger = LoggerFactory.getLogger(StdioProxy.class);

    /** Upper bound on a graceful child shutdown before the tree is killed. FEAT-003. */
    private static final long SHUTDOWN_GRACE_MILLIS = 5_000L;

    /** Upper bound on waiting for the drain threads after the child exits. */
    private static final long DRAIN_JOIN_MILLIS = 5_000L;

    private final List<String> command;
    private final PolicyEvaluator policyEvaluator;
    private final DlpScrubber dlpScrubber;
    private final TerminalInspector inspector;
    private final AgentIdentity localAgentIdentity;
    private final JsonRpcCodec codec;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Object terminationLock = new Object();

    /**
     * Descendants seen while the child was alive. A child that exits after spawning a helper would
     * otherwise be invisible to {@link Process#descendants()} by the time shutdown runs, leaving the
     * helper orphaned. ProcessHandle identity is safe against PID reuse because the JDK compares the
     * process start time before reporting one alive.
     */
    private final Set<ProcessHandle> observedDescendants = ConcurrentHashMap.newKeySet();

    private volatile Process childProcess;
    private volatile int shutdownExitCode;

    public StdioProxy(List<String> command, PolicyEvaluator policyEvaluator) {
        this(command, policyEvaluator, DlpScrubber.getInstance(), new TerminalInspector());
    }

    public StdioProxy(List<String> command, PolicyEvaluator policyEvaluator, DlpScrubber dlpScrubber,
                      TerminalInspector inspector) {
        this.command = List.copyOf(Objects.requireNonNull(command, "command must not be null"));
        this.policyEvaluator = Objects.requireNonNull(policyEvaluator, "policyEvaluator must not be null");
        this.dlpScrubber = Objects.requireNonNull(dlpScrubber, "dlpScrubber must not be null");
        this.inspector = Objects.requireNonNull(inspector, "inspector must not be null");
        this.codec = JsonRpcCodec.getInstance();
        this.localAgentIdentity = new AgentIdentity("local-dev-agent", "spiffe://aegismcp.dev/agent/local", null, true);
    }

    /**
     * Starts the managed child process and runs stdio interception until streams close or the
     * process terminates.
     *
     * @return {@link ExitCode#SUCCESS} when the child exits 0, {@link ExitCode#FAILURE} when it
     *         exits non-zero or cannot start, and {@link ExitCode#INTERRUPTED} when the proxy thread
     *         is interrupted
     */
    public int start(InputStream parentIn, PrintStream parentOut, PrintStream parentErr) {
        if (command.isEmpty()) {
            inspector.logError("No target MCP server command provided.");
            return ExitCode.FAILURE;
        }

        Process process;
        try {
            process = new ProcessBuilder(command).start();
        } catch (IOException e) {
            inspector.logError("Failed to launch target MCP server: " + e.getMessage());
            return ExitCode.FAILURE;
        }
        childProcess = process;
        running.set(true);

        Thread shutdownHook = new Thread(this::terminateChildProcess, "aegis-cli-shutdown-hook");
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        Thread stdoutDrain = Thread.ofVirtual()
                .name("aegis-cli-child-stdout")
                .start(() -> drainStdout(process, parentOut));
        Thread stderrDrain = Thread.ofVirtual()
                .name("aegis-cli-child-stderr")
                .start(() -> drainStderr(process, parentErr));

        Thread descendantWatch = Thread.ofVirtual()
                .name("aegis-cli-descendant-watch")
                .start(() -> watchDescendants(process));

        // When the child exits first, closing the parent channel unblocks a parent read that would
        // otherwise keep the CLI alive after its upstream disappeared.
        Thread exitWatcher = Thread.ofVirtual()
                .name("aegis-cli-child-exit-watch")
                .start(() -> {
                    try {
                        process.waitFor();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        running.set(false);
                        closeQuietly(parentIn);
                    }
                });

        int exitCode;
        try {
            pumpParentInput(parentIn, process, parentOut);
            exitCode = awaitChild(process);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            shutdownExitCode = ExitCode.INTERRUPTED;
            exitCode = ExitCode.INTERRUPTED;
        } finally {
            running.set(false);
            terminateChildProcess();
            joinQuietly(stdoutDrain);
            joinQuietly(stderrDrain);
            joinQuietly(descendantWatch);
            joinQuietly(exitWatcher);
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);
            } catch (IllegalStateException ignored) {
                // The JVM is already shutting down; the hook is running.
            }
        }

        if (shutdownExitCode != ExitCode.SUCCESS) {
            return shutdownExitCode;
        }
        if (exitCode != ExitCode.SUCCESS) {
            inspector.logError("Target MCP server exited with code " + exitCode + ".");
        }
        return ExitCode.fromChildExit(exitCode);
    }

    /**
     * Forwards a signal to the managed child tree and records the exit status the CLI must report.
     * Production signal handlers call this and then halt the process with the returned code.
     *
     * @param code {@link ExitCode#INTERRUPTED} or {@link ExitCode#TERMINATED}
     * @return the same code, for the caller's convenience
     */
    int forwardShutdownSignal(int code) {
        shutdownExitCode = code;
        running.set(false);
        terminateChildProcess();
        return code;
    }

    private void pumpParentInput(InputStream parentIn, Process process, PrintStream parentOut) {
        try (BufferedReader parentReader =
                     new BufferedReader(new InputStreamReader(parentIn, StandardCharsets.UTF_8));
             BufferedWriter childWriter =
                     new BufferedWriter(new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8))) {

            String line;
            while (running.get() && (line = parentReader.readLine()) != null) {
                if (!running.get()) {
                    break;
                }
                if (line.isBlank()) {
                    childWriter.write(line);
                    childWriter.newLine();
                    childWriter.flush();
                    continue;
                }

                JsonRpcRequest request = tryParseJsonRpc(line);
                if (request != null && request.isToolCall()) {
                    handleToolCall(request, line, childWriter, parentOut);
                } else {
                    writeToChild(childWriter, line);
                }
            }
        } catch (IOException e) {
            logger.debug("Parent input stream closed or failed: {}", e.getMessage());
        }
    }

    private void handleToolCall(JsonRpcRequest request, String line, BufferedWriter childWriter,
                                PrintStream parentOut) throws IOException {
        String toolName = request.toolName();
        JsonNode toolArgs = request.toolArguments();

        long startNs = System.nanoTime();
        PolicyEvaluationResult evalResult = policyEvaluator.evaluate(localAgentIdentity, toolName, toolArgs);
        double latencyMs = (System.nanoTime() - startNs) / 1_000_000.0;

        if (evalResult.isAllowed()) {
            inspector.logToolCall(toolName, toolArgs, latencyMs, true, null);
            writeToChild(childWriter, line);
        } else {
            String reason = evalResult.reason() != null ? evalResult.reason() : "Tool call rejected by policy";
            inspector.logToolCall(toolName, toolArgs, latencyMs, false, reason);

            // Answer the caller directly; the rejected call never reaches the upstream child.
            JsonRpcError error = JsonRpcError.policyViolation(reason);
            JsonRpcResponse errorResponse = JsonRpcResponse.error(request.id(), error);
            writeProtocolFrame(parentOut, codec.encode(errorResponse));
        }
    }

    private static void writeProtocolFrame(PrintStream out, byte[] frame) {
        out.println(new String(frame, StandardCharsets.UTF_8));
        out.flush();
    }

    private static void writeToChild(BufferedWriter childWriter, String line) throws IOException {
        childWriter.write(line);
        childWriter.newLine();
        childWriter.flush();
    }

    private void drainStdout(Process process, PrintStream parentOut) {
        try (BufferedReader reader =
                     new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    parentOut.println(line);
                    parentOut.flush();
                    continue;
                }
                String scrubbed = dlpScrubber.scrubJson(line);
                parentOut.println(scrubbed != null ? scrubbed : line);
                parentOut.flush();
            }
        } catch (IOException e) {
            logger.debug("Child stdout drain ended: {}", e.getMessage());
        }
    }

    /**
     * Records descendants while the child runs, so a grandchild that outlives its parent is still
     * known when the CLI shuts down.
     */
    private void watchDescendants(Process process) {
        while (running.get() && process.isAlive()) {
            process.descendants().forEach(observedDescendants::add);
            try {
                Thread.sleep(100L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void drainStderr(Process process, PrintStream parentErr) {
        try (BufferedReader reader =
                     new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                parentErr.println(line);
                parentErr.flush();
            }
        } catch (IOException e) {
            logger.debug("Child stderr drain ended: {}", e.getMessage());
        }
    }

    private int awaitChild(Process process) throws InterruptedException {
        // A signal handler may have recorded its code and halted the process; the wait stays
        // interruptible so an in-process interrupt unwinds the same way.
        return process.waitFor();
    }

    private JsonRpcRequest tryParseJsonRpc(String line) {
        try {
            return codec.decodeRequest(line.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Terminates the managed child and every descendant. A graceful destroy is given five seconds;
     * whatever remains is killed forcibly, so no grandchild outlives the CLI.
     */
    public void terminateChildProcess() {
        Process process = childProcess;
        if (process == null) {
            return;
        }
        synchronized (terminationLock) {
            Set<ProcessHandle> tree = new LinkedHashSet<>(observedDescendants);
            process.toHandle().descendants().forEach(tree::add);
            tree.add(process.toHandle());

            for (ProcessHandle handle : tree) {
                if (handle.isAlive()) {
                    handle.destroy();
                }
            }

            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(SHUTDOWN_GRACE_MILLIS);
            while (System.nanoTime() < deadline && anyAlive(tree)) {
                try {
                    Thread.sleep(25);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

            for (ProcessHandle handle : tree) {
                if (handle.isAlive()) {
                    handle.destroyForcibly();
                }
            }
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            try {
                process.waitFor(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }
    }

    private static boolean anyAlive(Set<ProcessHandle> handles) {
        for (ProcessHandle handle : handles) {
            if (handle.isAlive()) {
                return true;
            }
        }
        return false;
    }

    private static void joinQuietly(Thread thread) {
        try {
            thread.join(DRAIN_JOIN_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void closeQuietly(InputStream stream) {
        try {
            stream.close();
        } catch (IOException ignored) {
            // Closing is best effort; the reader unblocks on the child's exit regardless.
        }
    }

    public Process getChildProcess() {
        return childProcess;
    }
}
