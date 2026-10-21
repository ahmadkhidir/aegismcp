package dev.aegismcp.cli;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.PrintStream;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;

/**
 * Interactive color-coded terminal inspection logger for MCP tool calls.
 * Renders real-time inspection logs to stderr to keep stdout pure for JSON-RPC traffic.
 * Anchors: FEAT-003, NFR-001.
 */
public class TerminalInspector {

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

    public TerminalInspector() {
        this(System.err, isAnsiSupported());
    }

    public TerminalInspector(PrintStream out, boolean colorEnabled) {
        this.out = Objects.requireNonNull(out, "out must not be null");
        this.colorEnabled = colorEnabled;
    }

    private static boolean isAnsiSupported() {
        if (System.getenv("NO_COLOR") != null) {
            return false;
        }
        String term = System.getenv("TERM");
        if ("dumb".equalsIgnoreCase(term)) {
            return false;
        }
        return true;
    }

    /**
     * Prints a startup banner indicating the active policy and wrapped MCP server command.
     */
    public void printBanner(String policyId, String policyVersion, String command) {
        String timestamp = LocalTime.now().format(TIME_FORMATTER);
        if (colorEnabled) {
            out.println(ANSI_CYAN + ANSI_BOLD + "=== AegisMCP Local Developer Proxy (aegis-cli) ===" + ANSI_RESET);
            out.println(ANSI_DIM + "[" + timestamp + "] Active Policy: " + ANSI_RESET + ANSI_BOLD + policyId + " (v" + policyVersion + ")" + ANSI_RESET);
            out.println(ANSI_DIM + "[" + timestamp + "] Wrapped Target: " + ANSI_RESET + ANSI_YELLOW + command + ANSI_RESET);
            out.println(ANSI_CYAN + "----------------------------------------------------" + ANSI_RESET);
        } else {
            out.println("=== AegisMCP Local Developer Proxy (aegis-cli) ===");
            out.println("[" + timestamp + "] Active Policy: " + policyId + " (v" + policyVersion + ")");
            out.println("[" + timestamp + "] Wrapped Target: " + command);
            out.println("----------------------------------------------------");
        }
        out.flush();
    }

    /**
     * Logs an intercepted tool call with evaluation latency and verdict.
     * Anchors: FEAT-003.
     */
    public void logToolCall(String toolName, JsonNode arguments, double latencyMs, boolean allowed, String reason) {
        String timestamp = LocalTime.now().format(TIME_FORMATTER);
        String argsStr = arguments != null ? arguments.toString() : "{}";
        if (argsStr.length() > 80) {
            argsStr = argsStr.substring(0, 77) + "...";
        }
        String latencyStr = String.format("%.2fms", latencyMs);

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

            if (!allowed && reason != null && !reason.isBlank()) {
                sb.append(" ").append(ANSI_RED).append("(").append(reason).append(")").append(ANSI_RESET);
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

            if (!allowed && reason != null && !reason.isBlank()) {
                sb.append(" (").append(reason).append(")");
            }

            out.println(sb);
        }
        out.flush();
    }

    /**
     * Logs general operational or warning messages.
     */
    public void logMessage(String message) {
        String timestamp = LocalTime.now().format(TIME_FORMATTER);
        if (colorEnabled) {
            out.println(ANSI_DIM + "[" + timestamp + "] " + ANSI_RESET + message);
        } else {
            out.println("[" + timestamp + "] " + message);
        }
        out.flush();
    }

    /**
     * Logs an error message.
     */
    public void logError(String error) {
        String timestamp = LocalTime.now().format(TIME_FORMATTER);
        if (colorEnabled) {
            out.println(ANSI_RED + ANSI_BOLD + "[" + timestamp + "] ERROR: " + ANSI_RESET + ANSI_RED + error + ANSI_RESET);
        } else {
            out.println("[" + timestamp + "] ERROR: " + error);
        }
        out.flush();
    }
}
