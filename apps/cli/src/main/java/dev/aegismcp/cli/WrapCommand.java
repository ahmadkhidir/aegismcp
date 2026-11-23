package dev.aegismcp.cli;

import dev.aegismcp.gateway.dlp.DlpScrubber;
import dev.aegismcp.gateway.policy.PolicyAst;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyCompiler;
import dev.aegismcp.gateway.policy.PolicyCompilationException;
import dev.aegismcp.gateway.policy.PolicyEvaluator;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;
import picocli.CommandLine.Spec;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Command line action to wrap a local MCP stdio server child process, intercepting and enforcing
 * security policies and scrubbing sensitive outputs.
 *
 * <p>FEAT-003 scopes the wrapper to a managed stdio child: an SSE or WebSocket upstream is reached
 * through the gateway, never through {@code wrap}, so the command offers no transport switch. The
 * command validates every input before the child exists, then delegates process, pipe, signal, and
 * exit-code behaviour to {@link StdioProxy}.
 *
 * <p>Anchors: FEAT-003, FEAT-002, FEAT-005, NFR-001, C-001.
 */
@Command(
        name = "wrap",
        description = "Wrap a local MCP server child process with declarative policy enforcement and DLP scrubbing",
        mixinStandardHelpOptions = true
)
public class WrapCommand implements Callable<Integer> {

    @Option(names = {"-p", "--policy"}, required = true, description = "Path to the declarative security policy YAML file")
    private File policyFile;

    @Parameters(arity = "1..*", description = "Command and arguments to execute the upstream MCP server")
    private List<String> serverCommand;

    @ParentCommand
    private AegisCliMain root;

    @Spec
    private CommandSpec spec;

    private final PolicyCompiler compiler;
    private final DlpScrubber dlpScrubber;

    public WrapCommand() {
        this(PolicyCompiler.getInstance(), DlpScrubber.getInstance());
    }

    public WrapCommand(PolicyCompiler compiler, DlpScrubber dlpScrubber) {
        this.compiler = compiler;
        this.dlpScrubber = dlpScrubber;
    }

    @Override
    public Integer call() {
        if (!hasCommandSeparator()) {
            System.err.println("Error: The upstream command must follow a '--' separator, "
                    + "for example: aegis-cli wrap --policy policy.yaml -- npx server.");
            return ExitCode.USAGE;
        }

        if (serverCommand == null || serverCommand.isEmpty()) {
            System.err.println("Error: Missing target MCP server command to wrap.");
            return ExitCode.USAGE;
        }

        if (policyFile == null) {
            System.err.println("Error: --policy option is required.");
            return ExitCode.USAGE;
        }

        Path path = policyFile.toPath();
        if (!Files.exists(path)) {
            System.err.println("Error: Policy file not found: " + policyFile.getPath());
            return ExitCode.USAGE;
        }
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            System.err.println("Error: Policy file is not a readable regular file: " + policyFile.getPath());
            return ExitCode.USAGE;
        }

        String rawYaml;
        try {
            rawYaml = Files.readString(path);
        } catch (IOException e) {
            System.err.println("Error: Unable to read policy file: " + e.getMessage());
            return ExitCode.USAGE;
        }

        PolicyAst ast;
        try {
            ast = compiler.compile(rawYaml);
        } catch (PolicyCompilationException e) {
            System.err.println("Error: Policy validation failed: " + e.getMessage());
            return ExitCode.FAILURE;
        } catch (Exception e) {
            System.err.println("Error: Unexpected failure compiling policy: " + e.getMessage());
            return ExitCode.FAILURE;
        }

        // Initialize policy cache and evaluator
        PolicyCache policyCache = new PolicyCache(compiler);
        SecurityPolicy policy = SecurityPolicy.of(ast.id(), ast.name(), ast.version(), rawYaml, "local-cli");
        policyCache.putPolicy(policy);
        policyCache.bindAgentToPolicy("*", policy.id());
        policyCache.bindAgentToPolicy("local-dev-agent", policy.id());

        PolicyEvaluator policyEvaluator = new PolicyEvaluator(policyCache);
        ColorMode mode = root != null ? root.colorMode() : ColorMode.AUTO;
        TerminalInspector inspector = new TerminalInspector(System.err, mode, dlpScrubber);

        inspector.printBanner(ast.id(), ast.version(), String.join(" ", serverCommand));

        StdioProxy proxy = new StdioProxy(serverCommand, policyEvaluator, dlpScrubber, inspector);

        SignalBridge signalBridge = installSignalHandlers(proxy);
        try {
            return proxy.start(System.in, System.out, System.err);
        } catch (Exception e) {
            inspector.logError("Stdio proxy runtime failure: " + e.getMessage());
            return ExitCode.FAILURE;
        } finally {
            if (signalBridge != null) {
                signalBridge.close();
            }
        }
    }

    /**
     * The production entrypoint forwards SIGINT/SIGTERM to the child tree and halts with the
     * documented status. Tests drive {@link AegisCliMain#execute(java.io.PrintWriter,
     * java.io.PrintWriter, String...)} and keep the test JVM's own handlers.
     */
    private SignalBridge installSignalHandlers(StdioProxy proxy) {
        if (root == null || !root.signalsEnabled()) {
            return null;
        }
        return SignalBridge.install(signal -> {
            int code = proxy.forwardShutdownSignal(signal.exitCode());
            System.out.flush();
            System.err.flush();
            Runtime.getRuntime().halt(code);
        });
    }

    /**
     * FEAT-003 requires the explicit {@code --} separator. Picocli itself accepts a bare command,
     * so the parse result is the only place the separator can still be observed.
     */
    private boolean hasCommandSeparator() {
        if (spec == null || spec.commandLine() == null || spec.commandLine().getParseResult() == null) {
            return true;
        }
        return spec.commandLine().getParseResult().originalArgs().contains("--");
    }

    public void setPolicyFile(File policyFile) {
        this.policyFile = policyFile;
    }

    public void setServerCommand(List<String> serverCommand) {
        this.serverCommand = serverCommand;
    }
}
