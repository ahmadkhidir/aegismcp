package dev.aegismcp.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Help;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

import java.io.PrintWriter;
import java.util.concurrent.Callable;

/**
 * Main command-line entrypoint for aegis-cli.
 * Color is resolved once here, at the command boundary, so every surface obeys the same decision:
 * {@code auto} colors an interactive terminal only, and piped or redirected output stays plain.
 * Anchors: FEAT-003, FEAT-010, NFR-006.
 */
@Command(
        name = "aegis-cli",
        description = "AegisMCP Local Developer CLI & Security Tool",
        mixinStandardHelpOptions = true,
        version = "1.0.0",
        footer = {
                "",
                "Exit codes:",
                "  0    success",
                "  1    failure: invalid policy, refused request, child failure, or internal error",
                "  2    usage error or unreadable input path",
                "  130  interrupted",
                "  143  terminated"
        },
        subcommands = {
                WrapCommand.class,
                LintCommand.class,
                KillCommand.class
        }
)
public class AegisCliMain implements Callable<Integer> {

    private final boolean signalsEnabled;

    public AegisCliMain() {
        this(false);
    }

    /**
     * @param signalsEnabled whether this root may install process signal handlers. Only the
     *                       production entrypoint enables it; tests drive {@code execute} directly
     *                       and must not replace the test JVM's signal handlers.
     */
    public AegisCliMain(boolean signalsEnabled) {
        this.signalsEnabled = signalsEnabled;
    }

    @Spec
    private CommandSpec spec;

    @Option(
            names = "--color",
            paramLabel = "WHEN",
            defaultValue = "auto",
            converter = ColorMode.Converter.class,
            scope = CommandLine.ScopeType.INHERIT,
            description = "Colorize terminal output: auto (interactive terminal only), always, or never (default: auto)"
    )
    private ColorMode colorMode = ColorMode.AUTO;

    @Option(
            names = "--no-color",
            hidden = true,
            scope = CommandLine.ScopeType.INHERIT,
            description = "Alias for --color=never"
    )
    private boolean noColor;

    @Override
    public Integer call() {
        spec.commandLine().usage(spec.commandLine().getOut());
        return ExitCode.SUCCESS;
    }

    /**
     * Resolves the requested color policy. The hidden {@code --no-color} alias always wins.
     */
    ColorMode colorMode() {
        return noColor ? ColorMode.NEVER : colorMode;
    }

    /** True only for the production entrypoint, which forwards signals to the managed child. */
    boolean signalsEnabled() {
        return signalsEnabled;
    }

    public static void main(String[] args) {
        int exitCode = execute(args);
        System.exit(exitCode);
    }

    /**
     * Executes the CLI with the process streams. This is the production path: {@code auto} may color
     * only when the JVM is attached to a console, and signal handlers are installed so a wrapped
     * child is reaped on interrupt or termination.
     */
    public static int execute(String... args) {
        PrintWriter out = new PrintWriter(System.out, true);
        PrintWriter err = new PrintWriter(System.err, true);
        return run(out, err, System.console() != null, true, args);
    }

    /**
     * Executes the CLI with custom output and error streams (for testing). Captured writers are never
     * considered interactive terminals, so {@code auto} stays plain; {@code --color=always} still forces
     * ANSI escapes. Signal handlers are left untouched so the test JVM keeps its own.
     */
    public static int execute(PrintWriter out, PrintWriter err, String... args) {
        return run(out, err, false, false, args);
    }

    private static int run(PrintWriter out, PrintWriter err, boolean interactiveTerminal,
                           boolean signalsEnabled, String... args) {
        CommandLine cmd = new CommandLine(new AegisCliMain(signalsEnabled));
        cmd.setOut(out);
        cmd.setErr(err);
        applyExitCodePolicy(cmd);

        ColorMode requested = detectColorMode(args);
        boolean colorEnabled = TerminalInspector.isColorEnabled(requested, interactiveTerminal);
        applyColorScheme(cmd, colorEnabled ? Help.Ansi.ON : Help.Ansi.OFF);

        try {
            return cmd.execute(args);
        } finally {
            out.flush();
            err.flush();
        }
    }

    /**
     * Pins every outcome of the command framework to the documented vocabulary, including the
     * subcommands: bad input is {@link ExitCode#USAGE}, an uncaught execution failure is
     * {@link ExitCode#FAILURE}, and help or version output is success. Keeping the mapping here means
     * no command can silently inherit a different default.
     */
    static void applyExitCodePolicy(CommandLine commandLine) {
        commandLine.getCommandSpec().exitCodeOnInvalidInput(ExitCode.USAGE);
        commandLine.getCommandSpec().exitCodeOnExecutionException(ExitCode.FAILURE);
        commandLine.getCommandSpec().exitCodeOnUsageHelp(ExitCode.SUCCESS);
        commandLine.getCommandSpec().exitCodeOnVersionHelp(ExitCode.SUCCESS);
        commandLine.setExecutionExceptionHandler((exception, failedCommand, parseResult) -> {
            failedCommand.getErr().println("Error: " + exception.getMessage());
            failedCommand.getErr().flush();
            return ExitCode.FAILURE;
        });
        for (CommandLine subcommand : commandLine.getSubcommands().values()) {
            applyExitCodePolicy(subcommand);
        }
    }

    /**
     * Reads the requested color mode before picocli renders help or usage text, because the usage
     * renderer needs the decision before any command body runs. An unparseable value falls back to
     * {@code auto} so picocli can report the option error itself.
     */
    private static ColorMode detectColorMode(String[] args) {
        ColorMode mode = ColorMode.AUTO;
        boolean noColor = false;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--".equals(arg)) {
                break;
            }
            if ("--no-color".equals(arg)) {
                noColor = true;
            } else if ("--color".equals(arg)) {
                if (i + 1 < args.length) {
                    mode = parseOrDefault(args[++i]);
                }
            } else if (arg.startsWith("--color=")) {
                mode = parseOrDefault(arg.substring("--color=".length()));
            }
        }
        return noColor ? ColorMode.NEVER : mode;
    }

    private static ColorMode parseOrDefault(String value) {
        try {
            return ColorMode.parse(value);
        } catch (IllegalArgumentException e) {
            return ColorMode.AUTO;
        }
    }

    private static void applyColorScheme(CommandLine commandLine, Help.Ansi ansi) {
        Help.ColorScheme scheme = new Help.ColorScheme.Builder(commandLine.getColorScheme())
                .ansi(ansi)
                .build();
        commandLine.setColorScheme(scheme);
        for (CommandLine subcommand : commandLine.getSubcommands().values()) {
            applyColorScheme(subcommand, ansi);
        }
    }
}
