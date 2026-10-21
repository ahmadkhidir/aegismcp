package dev.aegismcp.cli;

import dev.aegismcp.gateway.dlp.DlpScrubber;
import dev.aegismcp.gateway.policy.PolicyAst;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyCompiler;
import dev.aegismcp.gateway.policy.PolicyCompilationException;
import dev.aegismcp.gateway.policy.PolicyEvaluator;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Command line action to wrap a local MCP server child process,
 * intercepting and enforcing security policies and scrubbing sensitive outputs.
 * Anchors: FEAT-003, FEAT-002, FEAT-005, NFR-001, C-001.
 */
@Command(
        name = "wrap",
        description = "Wrap a local MCP server child process with declarative policy enforcement and DLP scrubbing",
        mixinStandardHelpOptions = true
)
public class WrapCommand implements Callable<Integer> {

    @Option(names = {"-p", "--policy"}, required = true, description = "Path to the declarative security policy YAML file")
    private File policyFile;

    @Option(names = {"-u", "--upstream"}, defaultValue = "stdio", description = "Upstream transport type: stdio or sse (default: stdio)")
    private String upstream = "stdio";

    @Option(names = {"--no-color"}, defaultValue = "false", description = "Disable ANSI color coding in terminal inspection logs")
    private boolean noColor = false;

    @Parameters(arity = "1..*", description = "Command and arguments to execute the upstream MCP server")
    private List<String> serverCommand;

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
        if (serverCommand == null || serverCommand.isEmpty()) {
            System.err.println("Error: Missing target MCP server command to wrap.");
            return 1;
        }

        if (policyFile == null) {
            System.err.println("Error: --policy option is required.");
            return 1;
        }

        Path path = policyFile.toPath();
        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            System.err.println("Error: Policy file does not exist or is not a readable file: " + policyFile.getPath());
            return 1;
        }

        String rawYaml;
        try {
            rawYaml = Files.readString(path);
        } catch (IOException e) {
            System.err.println("Error: Unable to read policy file: " + e.getMessage());
            return 1;
        }

        PolicyAst ast;
        try {
            ast = compiler.compile(rawYaml);
        } catch (PolicyCompilationException e) {
            System.err.println("Error: Policy validation failed: " + e.getMessage());
            return 1;
        } catch (Exception e) {
            System.err.println("Error: Unexpected failure compiling policy: " + e.getMessage());
            return 1;
        }

        // Initialize policy cache and evaluator
        PolicyCache policyCache = new PolicyCache(compiler);
        SecurityPolicy policy = SecurityPolicy.of(ast.id(), ast.name(), ast.version(), rawYaml, "local-cli");
        policyCache.putPolicy(policy);
        policyCache.bindAgentToPolicy("*", policy.id());
        policyCache.bindAgentToPolicy("local-dev-agent", policy.id());

        PolicyEvaluator policyEvaluator = new PolicyEvaluator(policyCache);
        TerminalInspector inspector = new TerminalInspector(System.err, !noColor);

        inspector.printBanner(ast.id(), ast.version(), String.join(" ", serverCommand));

        StdioProxy proxy = new StdioProxy(serverCommand, policyEvaluator, dlpScrubber, inspector);

        try {
            return proxy.start(System.in, System.out, System.err);
        } catch (Exception e) {
            inspector.logError("Stdio proxy runtime failure: " + e.getMessage());
            return 1;
        }
    }

    public void setPolicyFile(File policyFile) {
        this.policyFile = policyFile;
    }

    public void setServerCommand(List<String> serverCommand) {
        this.serverCommand = serverCommand;
    }

    public void setNoColor(boolean noColor) {
        this.noColor = noColor;
    }
}
