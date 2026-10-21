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
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * High-performance Stdio proxy intercepting JSON-RPC MCP messages between parent client and child server.
 * Evaluates tool calls against declarative policies, scrubs responses via DLP engine, and logs inspections.
 * Anchors: FEAT-003, FEAT-005, NFR-001, NFR-002, C-001.
 */
public class StdioProxy {

    private static final Logger logger = LoggerFactory.getLogger(StdioProxy.class);

    private final List<String> command;
    private final PolicyEvaluator policyEvaluator;
    private final DlpScrubber dlpScrubber;
    private final TerminalInspector inspector;
    private final AgentIdentity localAgentIdentity;
    private final JsonRpcCodec codec;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private volatile Process childProcess;

    public StdioProxy(List<String> command, PolicyEvaluator policyEvaluator) {
        this(command, policyEvaluator, DlpScrubber.getInstance(), new TerminalInspector());
    }

    public StdioProxy(List<String> command, PolicyEvaluator policyEvaluator, DlpScrubber dlpScrubber, TerminalInspector inspector) {
        this.command = List.copyOf(Objects.requireNonNull(command, "command must not be null"));
        this.policyEvaluator = Objects.requireNonNull(policyEvaluator, "policyEvaluator must not be null");
        this.dlpScrubber = Objects.requireNonNull(dlpScrubber, "dlpScrubber must not be null");
        this.inspector = Objects.requireNonNull(inspector, "inspector must not be null");
        this.codec = JsonRpcCodec.getInstance();
        this.localAgentIdentity = new AgentIdentity("local-dev-agent", "spiffe://aegismcp.dev/agent/local", null, true);
    }

    /**
     * Starts the managed child process and runs stdio interception until streams close or process terminates.
     * Returns child process exit code (or 1 on failure).
     */
    public int start(InputStream parentIn, PrintStream parentOut, PrintStream parentErr) throws IOException, InterruptedException {
        if (command.isEmpty()) {
            inspector.logError("No target MCP server command provided.");
            return 1;
        }

        ProcessBuilder pb = new ProcessBuilder(command);
        try {
            childProcess = pb.start();
        } catch (IOException e) {
            inspector.logError("Failed to launch target MCP server: " + e.getMessage());
            return 1;
        }

        running.set(true);

        // Register shutdown hook for graceful cleanup
        Thread shutdownHook = new Thread(this::terminateChildProcess, "aegis-cli-shutdown-hook");
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        try {
            // Asynchronously drain child stderr to parentErr
            Thread errDrainThread = Thread.ofVirtual().name("child-stderr-drain").start(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(childProcess.getErrorStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        parentErr.println(line);
                        parentErr.flush();
                    }
                } catch (IOException ignored) {
                }
            });

            // Asynchronously proxy child stdout -> parent stdout with DLP scrubbing
            CompletableFuture<Void> childOutFuture = CompletableFuture.runAsync(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(childProcess.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.isBlank()) {
                            parentOut.println(line);
                            parentOut.flush();
                            continue;
                        }
                        String scrubbed = dlpScrubber.scrubJson(line);
                        parentOut.println(scrbedOrOriginal(line, scrubbed));
                        parentOut.flush();
                    }
                } catch (IOException ignored) {
                }
            }, Executors.newVirtualThreadPerTaskExecutor());

            // Synchronously proxy parent stdin -> child stdin with Policy Interception
            try (BufferedReader parentReader = new BufferedReader(new InputStreamReader(parentIn, StandardCharsets.UTF_8));
                 BufferedWriter childWriter = new BufferedWriter(new OutputStreamWriter(childProcess.getOutputStream(), StandardCharsets.UTF_8))) {

                String line;
                while (running.get() && (line = parentReader.readLine()) != null) {
                    if (line.isBlank()) {
                        childWriter.write(line);
                        childWriter.newLine();
                        childWriter.flush();
                        continue;
                    }

                    JsonRpcRequest request = tryParseJsonRpc(line);
                    if (request != null && request.isToolCall()) {
                        String toolName = request.toolName();
                        JsonNode toolArgs = request.toolArguments();

                        long startNs = System.nanoTime();
                        PolicyEvaluationResult evalResult = policyEvaluator.evaluate(localAgentIdentity, toolName, toolArgs);
                        double latencyMs = (System.nanoTime() - startNs) / 1_000_000.0;

                        if (evalResult.isAllowed()) {
                            inspector.logToolCall(toolName, toolArgs, latencyMs, true, null);
                            childWriter.write(line);
                            childWriter.newLine();
                            childWriter.flush();
                        } else {
                            String reason = evalResult.reason() != null ? evalResult.reason() : "Tool call rejected by policy";
                            inspector.logToolCall(toolName, toolArgs, latencyMs, false, reason);

                            // Synthesize JSON-RPC 2.0 error response directly to parent
                            JsonRpcError error = JsonRpcError.policyViolation(reason);
                            JsonRpcResponse errorResponse = JsonRpcResponse.error(request.id(), error);
                            byte[] errorBytes = codec.encode(errorResponse);
                            parentOut.println(new String(errorBytes, StandardCharsets.UTF_8));
                            parentOut.flush();
                        }
                    } else {
                        // Forward non-tool call (initialize, notifications, tools/list) directly to upstream child
                        childWriter.write(line);
                        childWriter.newLine();
                        childWriter.flush();
                    }
                }
            } catch (IOException e) {
                logger.debug("Parent input stream closed or error: {}", e.getMessage());
            }

            // Close child stdin to notify child process of EOF
            try {
                childProcess.getOutputStream().close();
            } catch (IOException ignored) {
            }

            int exitCode = childProcess.waitFor();
            running.set(false);

            try {
                childOutFuture.get(1, TimeUnit.SECONDS);
            } catch (Exception ignored) {
            }

            return exitCode;

        } finally {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);
            } catch (IllegalStateException ignored) {
                // JVM already shutting down
            }
            terminateChildProcess();
        }
    }

    private String scrbedOrOriginal(String original, String scrubbed) {
        return scrubbed != null ? scrubbed : original;
    }

    private JsonRpcRequest tryParseJsonRpc(String line) {
        try {
            return codec.decodeRequest(line.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Shuts down the managed child process hermetically.
     */
    public void terminateChildProcess() {
        Process p = childProcess;
        if (p != null && p.isAlive()) {
            p.destroy();
            try {
                if (!p.waitFor(1500, TimeUnit.MILLISECONDS)) {
                    p.destroyForcibly();
                }
            } catch (InterruptedException e) {
                p.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }
    }

    public Process getChildProcess() {
        return childProcess;
    }
}
