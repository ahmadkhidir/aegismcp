package dev.aegismcp.e2e.fixtures;

import java.time.Duration;

/**
 * Raised when the packaged gateway cannot be brought up for a test.
 *
 * <p>A startup failure is not a contract assertion result: it means the artifact never reached the
 * point where a suite could exercise it, so the failure carries its own type, a machine-readable
 * {@link Failure} cause, the wait that was spent, and the captured stdout/stderr. The message names
 * the cause and never suggests that the product behavior under test was wrong (NFR-005).
 */
public final class GatewayStartupException extends IllegalStateException {

    /** Why the artifact did not reach its bound-port line. */
    public enum Failure {
        /** The installed distribution is missing and the harness could not build it. */
        DISTRIBUTION_UNAVAILABLE,
        /** The child process could not be prepared or started at all. */
        LAUNCH_FAILED,
        /** The child exited before announcing the port it bound. */
        PROCESS_EXITED,
        /** The child was still running when the bounded readiness wait expired. */
        READINESS_TIMEOUT,
        /** The test thread was interrupted while waiting for readiness. */
        INTERRUPTED
    }

    private final Failure failure;
    private final Duration waited;
    private final String capturedOutput;

    GatewayStartupException(String message, Failure failure, Duration waited, String capturedOutput,
                            Throwable cause) {
        super(message, cause);
        this.failure = failure;
        this.waited = waited;
        this.capturedOutput = capturedOutput;
    }

    public Failure failure() {
        return failure;
    }

    /** How long the harness waited for the bound-port line before giving up. */
    public Duration waited() {
        return waited;
    }

    /** The stdout and stderr lines the child produced before the failure, labelled by stream. */
    public String capturedOutput() {
        return capturedOutput;
    }

    /**
     * Renders a duration for a failure message. Whole seconds read as {@code 45s}; sub-second
     * budgets keep millisecond precision so a deliberately short diagnostic wait is unambiguous.
     */
    static String describe(Duration duration) {
        long millis = duration.toMillis();
        return millis % 1_000 == 0 ? (millis / 1_000) + "s" : millis + "ms";
    }

    /** Wraps a captured output tail in markers so it is unmistakable inside a failed test report. */
    static String renderOutput(String capturedOutput) {
        String body = capturedOutput == null || capturedOutput.isBlank()
                ? "<the process produced no output>"
                : capturedOutput;
        return "\n--- captured startup output (last lines, stdout and stderr) ---\n"
                + body
                + "\n--- end of captured startup output ---";
    }
}
