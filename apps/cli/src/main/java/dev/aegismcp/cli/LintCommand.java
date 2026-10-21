package dev.aegismcp.cli;

import dev.aegismcp.gateway.policy.PolicyAst;
import dev.aegismcp.gateway.policy.PolicyCompiler;
import dev.aegismcp.gateway.policy.PolicyCompilationException;
import dev.aegismcp.gateway.policy.PolicyRule;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * Command line action to validate policy YAML files, inspect schema compliance,
 * and detect unreachable rules.
 * Anchors: FEAT-003, FEAT-002, NFR-027.
 */
@Command(
        name = "lint",
        description = "Validate declarative security policy YAML schema and detect unreachable rules",
        mixinStandardHelpOptions = true
)
public class LintCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Path to the security policy YAML file")
    private File policyFile;

    private final PolicyCompiler compiler;

    public LintCommand() {
        this(PolicyCompiler.getInstance());
    }

    public LintCommand(PolicyCompiler compiler) {
        this.compiler = compiler;
    }

    @Override
    public Integer call() {
        if (policyFile == null) {
            System.err.println("Error: Policy file parameter is required.");
            return 1;
        }

        Path path = policyFile.toPath();
        if (!Files.exists(path)) {
            System.err.println("Error: Policy file not found: " + policyFile.getPath());
            return 1;
        }

        if (!Files.isRegularFile(path)) {
            System.err.println("Error: Path is not a regular file: " + policyFile.getPath());
            return 1;
        }

        String content;
        try {
            content = Files.readString(path);
        } catch (IOException e) {
            System.err.println("Error: Unable to read file '" + policyFile.getPath() + "': " + e.getMessage());
            return 1;
        }

        if (content.isBlank()) {
            System.err.println("Error: Policy file is empty.");
            return 1;
        }

        PolicyAst ast;
        try {
            ast = compiler.compile(content);
        } catch (PolicyCompilationException e) {
            System.err.println("Validation Failed: Syntax or schema error in policy file:");
            System.err.println("  " + e.getMessage());
            return 1;
        } catch (Exception e) {
            System.err.println("Validation Failed: Unexpected error compiling policy:");
            System.err.println("  " + e.getMessage());
            return 1;
        }

        // Analyze rules for unreachable/shadowed rules
        List<String> warnings = checkUnreachableRules(ast);

        System.out.println("✓ Policy '" + ast.id() + "' (version: " + ast.version() + ") is valid.");
        System.out.println("  Name:           " + ast.name());
        System.out.println("  Target Agents:  " + String.join(", ", ast.targetAgents()));
        System.out.println("  Default Action: " + ast.defaultAction());
        System.out.println("  Total Rules:    " + ast.rules().size());

        if (!warnings.isEmpty()) {
            System.out.println("\nWarnings:");
            for (String warning : warnings) {
                System.out.println("  ⚠ " + warning);
            }
        }

        return 0;
    }

    /**
     * Inspects rules to find shadowed/unreachable rules.
     */
    public static List<String> checkUnreachableRules(PolicyAst ast) {
        List<String> issues = new ArrayList<>();
        List<PolicyRule> rules = ast.rules();
        Set<String> unconstrainedTools = new HashSet<>();
        boolean wildcardSeen = false;
        String wildcardRuleId = null;

        for (int i = 0; i < rules.size(); i++) {
            PolicyRule rule = rules.get(i);
            String tool = rule.tool();

            if (wildcardSeen) {
                issues.add("Rule '" + rule.id() + "' for tool '" + tool +
                        "' is unreachable (shadowed by wildcard rule '" + wildcardRuleId + "')");
                continue;
            }

            if (unconstrainedTools.contains(tool.toLowerCase())) {
                issues.add("Rule '" + rule.id() + "' for tool '" + tool +
                        "' is unreachable (shadowed by previous unconstrained rule for the same tool)");
                continue;
            }

            if (rule.constraints().isEmpty()) {
                if ("*".equals(tool)) {
                    wildcardSeen = true;
                    wildcardRuleId = rule.id();
                } else {
                    unconstrainedTools.add(tool.toLowerCase());
                }
            }
        }

        return issues;
    }
}
