package dev.aegismcp.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import dev.aegismcp.gateway.dlp.DlpScrubber;

import java.io.PrintStream;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Objects;

/**
 * Interactive color-coded terminal inspection logger for MCP tool calls.
 * Renders real-time inspection logs to stderr to keep stdout pure for JSON-RPC traffic.
 *
 * <p>FEAT-003 bounds what an inspection line may reveal: every argument value is truncated to
 * {@value #MAX_ARGUMENT_VALUE_LENGTH} characters and any credential- or PII-shaped span is replaced
 * through the same DLP scrubber the gateway applies. Values are scrubbed before they are truncated,
 * so a secret that starts inside the first 512 characters can never survive in fragmentary form.
 *
 * <p>Anchors: FEAT-003, FEAT-005, NFR-001.
 */
public class TerminalInspector {

    /** FEAT-003: the longest argument value an inspection line may show. */
    static final int MAX_ARGUMENT_VALUE_LENGTH = 512;

    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    // ANSI escape codes
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BOLD = "\u001B[1m";
    public static final String ANSI_DIM = "\u001B[2m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_CYAN = "\u001B[36m";

    private final PrintStream out;
    private final boolean colorEnabled;
    private final DlpScrubber dlpScrubber;

    public TerminalInspector() {
        this(System.err, ColorMode.AUTO);
    }

    /**
     * Builds an inspector that resolves color from the requested mode and the destination stream.
     * Anchors: FEAT-003.
     */
    public TerminalInspector(PrintStream out, ColorMode mode) {
        this(out, mode, DlpScrubber.getInstance());
    }

    /**
     * Builds an inspector that resolves color from the requested mode and the destination stream and
     * uses the caller's DLP scrubber for argument redaction.
     */
    public TerminalInspector(PrintStream out, ColorMode mode, DlpScrubber dlpScrubber) {
        this(out, isColorEnabled(mode, isInteractiveTerminal(out)), dlpScrubber);
    }

    public TerminalInspector(PrintStream out, boolean colorEnabled) {
        this(out, colorEnabled, DlpScrubber.getInstance());
    }

    public TerminalInspector(PrintStream out, boolean colorEnabled, DlpScrubber dlpScrubber) {
        this.out = Objects.requireNonNull(out, "out must not be null");
        this.colorEnabled = colorEnabled;
        this.dlpScrubber = Objects.requireNonNull(dlpScrubber, "dlpScrubber must not be null");
    }

    /**
     * Decides whether ANSI escapes may be written for the given mode and destination.
     * {@code NO_COLOR} and a dumb terminal force plain text regardless of the requested mode.
     * Anchors: FEAT-003, NFR-006.
     *
     * @param mode                the resolved {@code --color} policy
     * @param interactiveTerminal whether the destination is an interactive terminal
     */
    public static boolean isColorEnabled(ColorMode mode, boolean interactiveTerminal) {
        Objects.requireNonNull(mode, "mode must not be null");
        if (isPlainTextEnvironment()) {
            return false;
        }
        return switch (mode) {
            case ALWAYS -> true;
            case NEVER -> false;
            case AUTO -> interactiveTerminal;
        };
    }

    /**
     * True only when the stream is one of the process's own console streams. Captured writers, pipes,
     * and redirected files are never interactive. The JDK exposes console attachment for the process,
     * so any other target is treated as plain.
     */
    public static boolean isInteractiveTerminal(PrintStream target) {
        return target != null && (target == System.out || target == System.err) && System.console() != null;
    }

    /** {@code NO_COLOR} or {@code TERM=dumb} forces plain text on every channel. */
    private static boolean isPlainTextEnvironment() {
        return System.getenv("NO_COLOR") != null || "dumb".equalsIgnoreCase(System.getenv("TERM"));
    }

    /**
     * Prints a startup banner indicating the active policy and wrapped MCP server command. The
     * command line is scrubbed because a developer can pass a credential as an argument.
     */
    public void printBanner(String policyId, String policyVersion, String command) {
        String timestamp = LocalTime.now().format(TIME_FORMATTER);
        String scrubbedCommand = dlpScrubber.scrubText(command);
        if (colorEnabled) {
            out.println(ANSI_CYAN + ANSI_BOLD + "=== AegisMCP Local Developer Proxy (aegis-cli) ===" + ANSI_RESET);
            out.println(ANSI_DIM + "[" + timestamp + "] Active Policy: " + ANSI_RESET + ANSI_BOLD + policyId + " (v" + policyVersion + ")" + ANSI_RESET);
            out.println(ANSI_DIM + "[" + timestamp + "] Wrapped Target: " + ANSI_RESET + ANSI_YELLOW + scrubbedCommand + ANSI_RESET);
            out.println(ANSI_CYAN + "----------------------------------------------------" + ANSI_RESET);
        } else {
            out.println("=== AegisMCP Local Developer Proxy (aegis-cli) ===");
            out.println("[" + timestamp + "] Active Policy: " + policyId + " (v" + policyVersion + ")");
            out.println("[" + timestamp + "] Wrapped Target: " + scrubbedCommand);
            out.println("----------------------------------------------------");
        }
        out.flush();
    }

    /**
     * Logs an intercepted tool call with evaluation latency and verdict. Argument values are
     * redacted and truncated per FEAT-003 before they reach the terminal.
     * Anchors: FEAT-003, FEAT-005.
     */
    public void logToolCall(String toolName, JsonNode arguments, double latencyMs, boolean allowed, String reason) {
        String timestamp = LocalTime.now().format(TIME_FORMATTER);
        String argsStr = renderArguments(arguments);
        String latencyStr = String.format("%.2fms", latencyMs);
        String safeReason = reason != null && !reason.isBlank()
                ? truncate(dlpScrubber.scrubText(reason))
                : null;

        if (colorEnabled) {
            String verdictTag = allowed
                    ? ANSI_GREEN + ANSI_BOLD + "[ALLOWED]" + ANSI_RESET
                    : ANSI_RED + ANSI_BOLD + "[BLOCKED]" + ANSI_RESET;

            StringBuilder sb = new StringBuilder();
            sb.append(ANSI_DIM).append("[").append(timestamp).append("] ").append(ANSI_RESET);
            sb.append(ANSI_CYAN).append("TOOL: ").append(ANSI_BOLD).append(toolName).append(ANSI_RESET).append(" ");
            sb.append(ANSI_DIM).append("ARGS: ").append(ANSI_RESET).append(argsStr).append(" ");
            sb.append(ANSI_YELLOW).append("LATENCY: ").append(latencyStr).append(ANSI_RESET).append(" ");
            sb.append("VERDICT: ").append(verdictTag);

            if (!allowed && safeReason != null) {
                sb.append(" ").append(ANSI_RED).append("(").append(safeReason).append(")").append(ANSI_RESET);
            }

            out.println(sb);
        } else {
            String verdictTag = allowed ? "[ALLOWED]" : "[BLOCKED]";
            StringBuilder sb = new StringBuilder();
            sb.append("[").append(timestamp).append("] ");
            sb.append("TOOL: ").append(toolName).append(" ");
            sb.append("ARGS: ").append(argsStr).append(" ");
            sb.append("LATENCY: ").append(latencyStr).append(" ");
            sb.append("VERDICT: ").append(verdictTag);

            if (!allowed && safeReason != null) {
                sb.append(" (").append(safeReason).append(")");
            }

            out.println(sb);
        }
        out.flush();
    }

    /**
     * Renders tool arguments with every value scrubbed and bounded. Structure and keys are kept so
     * a developer can see which parameter was refused; nested values are treated the same way.
     */
    private String renderArguments(JsonNode arguments) {
        if (arguments == null || arguments.isNull()) {
            return "{}";
        }
        return sanitize(arguments).toString();
    }

    private JsonNode sanitize(JsonNode node) {
        if (node == null || node.isNull()) {
            return node;
        }
        if (node.isTextual()) {
            return TextNode.valueOf(truncate(dlpScrubber.scrubText(node.asText())));
        }
        if (node.isObject()) {
            ObjectNode sanitized = JsonNodeFactory.instance.objectNode();
            for (Map.Entry<String, JsonNode> entry : node.properties()) {
                sanitized.set(entry.getKey(), sanitize(entry.getValue()));
            }
            return sanitized;
        }
        if (node.isArray()) {
            ArrayNode sanitized = JsonNodeFactory.instance.arrayNode(node.size());
            for (JsonNode element : node) {
                sanitized.add(sanitize(element));
            }
            return sanitized;
        }
        return node;
    }

    private static String truncate(String value) {
        if (value == null || value.length() <= MAX_ARGUMENT_VALUE_LENGTH) {
            return value;
        }
        return value.substring(0, MAX_ARGUMENT_VALUE_LENGTH);
    }

    /**
     * Logs general operational or warning messages.
     */
    public void logMessage(String message) {
        String timestamp = LocalTime.now().format(TIME_FORMATTER);
        String safe = dlpScrubber.scrubText(message);
        if (colorEnabled) {
            out.println(ANSI_DIM + "[" + timestamp + "] " + ANSI_RESET + safe);
        } else {
            out.println("[" + timestamp + "] " + safe);
        }
        out.flush();
    }

    /**
     * Logs an error message.
     */
    public void logError(String error) {
        String timestamp = LocalTime.now().format(TIME_FORMATTER);
        String safe = dlpScrubber.scrubText(error);
        if (colorEnabled) {
            out.println(ANSI_RED + ANSI_BOLD + "[" + timestamp + "] ERROR: " + ANSI_RESET + ANSI_RED + safe + ANSI_RESET);
        } else {
            out.println("[" + timestamp + "] ERROR: " + safe);
        }
        out.flush();
    }
}
