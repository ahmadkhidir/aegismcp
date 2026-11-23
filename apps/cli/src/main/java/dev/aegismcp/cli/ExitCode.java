package dev.aegismcp.cli;

/**
 * The only process exit codes {@code aegis-cli} returns, in one place so every command agrees.
 * FEAT-003 fixes the vocabulary: {@code 0} success, {@code 1} a failure the command ran into,
 * {@code 2} a usage error or unreadable input path, {@code 130} after an interrupt, and
 * {@code 143} after a termination signal. A child process exit status is reported on stderr and
 * mapped onto {@link #FAILURE}; it is never returned raw, because a raw status could collide with
 * a code the CLI gives a different meaning.
 *
 * <p>Anchors: FEAT-003, NFR-006.
 */
public final class ExitCode {

    /** The command completed successfully. */
    public static final int SUCCESS = 0;

    /** The command ran and failed: invalid policy, refused request, child failure, internal error. */
    public static final int FAILURE = 1;

    /** The invocation was malformed or named an unreadable input path; no work was attempted. */
    public static final int USAGE = 2;

    /** The process received an interrupt ({@code SIGINT}). */
    public static final int INTERRUPTED = 130;

    /** The process received a termination request ({@code SIGTERM}). */
    public static final int TERMINATED = 143;

    /** Signal names whose conventional exit status the CLI reports. */
    public enum Signal {
        INT(INTERRUPTED),
        TERM(TERMINATED);

        private final int exitCode;

        Signal(int exitCode) {
            this.exitCode = exitCode;
        }

        public int exitCode() {
            return exitCode;
        }

        /**
         * Resolves a platform signal name.
         *
         * @param name {@code INT} or {@code TERM}
         * @return the matching signal
         * @throws IllegalArgumentException for any other signal
         */
        public static Signal fromName(String name) {
            for (Signal signal : values()) {
                if (signal.name().equalsIgnoreCase(name)) {
                    return signal;
                }
            }
            throw new IllegalArgumentException("Unsupported signal '" + name + "': expected INT or TERM.");
        }
    }

    private ExitCode() {
    }

    /**
     * Maps a managed child's native exit status onto the CLI vocabulary. A child that exited
     * successfully keeps {@link #SUCCESS}; every non-zero child status is a failure of the wrapped
     * session and becomes {@link #FAILURE}.
     */
    public static int fromChildExit(int childExitStatus) {
        return childExitStatus == 0 ? SUCCESS : FAILURE;
    }
}
