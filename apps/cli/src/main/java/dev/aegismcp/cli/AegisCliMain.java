package dev.aegismcp.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;

import java.io.PrintWriter;
import java.util.concurrent.Callable;

/**
 * Main command-line entrypoint for aegis-cli.
 * Anchors: FEAT-003, FEAT-010.
 */
@Command(
        name = "aegis-cli",
        description = "AegisMCP Local Developer CLI & Security Tool",
        mixinStandardHelpOptions = true,
        version = "1.0.0",
        subcommands = {
                WrapCommand.class,
                LintCommand.class,
                KillCommand.class
        }
)
public class AegisCliMain implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    @Override
    public Integer call() {
        spec.commandLine().usage(spec.commandLine().getOut());
        return 0;
    }

    public static void main(String[] args) {
        int exitCode = execute(args);
        System.exit(exitCode);
    }

    /**
     * Executes the CLI with standard output and error streams.
     */
    public static int execute(String... args) {
        CommandLine cmd = new CommandLine(new AegisCliMain());
        return cmd.execute(args);
    }

    /**
     * Executes the CLI with custom output and error streams (for testing).
     */
    public static int execute(PrintWriter out, PrintWriter err, String... args) {
        CommandLine cmd = new CommandLine(new AegisCliMain());
        cmd.setOut(out);
        cmd.setErr(err);
        return cmd.execute(args);
    }
}
