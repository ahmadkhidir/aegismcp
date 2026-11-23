package dev.aegismcp.cli;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Exit-code vocabulary tests. FEAT-003 fixes the set; a child status is reported and mapped rather
 * than returned raw.
 * Anchors: FEAT-003, NFR-006.
 */
class ExitCodeTest {

    @Test
    @DisplayName("FEAT-003: a successful child keeps exit code 0")
    void testSuccessfulChildIsSuccess() {
        assertEquals(ExitCode.SUCCESS, ExitCode.fromChildExit(0));
    }

    @Test
    @DisplayName("FEAT-003: every non-zero child status maps to the documented failure code")
    void testFailingChildIsFailure() {
        assertEquals(ExitCode.FAILURE, ExitCode.fromChildExit(1));
        assertEquals(ExitCode.FAILURE, ExitCode.fromChildExit(7));
        assertEquals(ExitCode.FAILURE, ExitCode.fromChildExit(130));
        assertEquals(ExitCode.FAILURE, ExitCode.fromChildExit(143));
    }

    @Test
    @DisplayName("FEAT-003: INT resolves to 130 and TERM to 143")
    void testSignalCodes() {
        assertEquals(ExitCode.INTERRUPTED, ExitCode.Signal.fromName("INT").exitCode());
        assertEquals(ExitCode.TERMINATED, ExitCode.Signal.fromName("TERM").exitCode());
    }

    @Test
    @DisplayName("FEAT-003: any other signal is rejected rather than guessed")
    void testUnknownSignalIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ExitCode.Signal.fromName("HUP"));
    }
}
