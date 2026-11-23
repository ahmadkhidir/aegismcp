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
        subcommands = {
                WrapCommand.class,
                LintCommand.class,
                KillCommand.class
        }
)
public class AegisCliMain implements Callable<Integer> {

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
        return 0;
    }

    /**
     * Resolves the requested color policy. The hidden {@code --no-color} alias always wins.
     */
    ColorMode colorMode() {
        return noColor ? ColorMode.NEVER : colorMode;
    }

    public static void main(String[] args) {
        int exitCode = execute(args);
        System.exit(exitCode);
    }

    /**
     * Executes the CLI with the process streams. This is the production path: {@code auto} may color
     * only when the JVM is attached to a console.
     */
    public static int execute(String... args) {
        PrintWriter out = new PrintWriter(System.out, true);
        PrintWriter err = new PrintWriter(System.err, true);
        return run(out, err, System.console() != null, args);
    }

    /**
     * Executes the CLI with custom output and error streams (for testing). Captured writers are never
     * considered interactive terminals, so {@code auto} stays plain; {@code --color=always} still forces
     * ANSI escapes.
     */
    public static int execute(PrintWriter out, PrintWriter err, String... args) {
        return run(out, err, false, args);
    }

    private static int run(PrintWriter out, PrintWriter err, boolean interactiveTerminal, String... args) {
        CommandLine cmd = new CommandLine(new AegisCliMain());
        cmd.setOut(out);
        cmd.setErr(err);

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
