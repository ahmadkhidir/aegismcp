package dev.aegismcp.gateway.policy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * YAML Parser and AST Compiler for declarative security policies.
 * Transforms raw YAML specification text into a pre-compiled {@link PolicyAst}.
 * Anchors: FEAT-002, NFR-001, C-006.
 */
public class PolicyCompiler {

    private static final Logger logger = LoggerFactory.getLogger(PolicyCompiler.class);

    private static final PolicyCompiler INSTANCE = new PolicyCompiler();

    private final ObjectMapper yamlMapper;

    public PolicyCompiler() {
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
        this.yamlMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public static PolicyCompiler getInstance() {
        return INSTANCE;
    }

    /**
     * Compiles raw YAML policy content into an executable AST.
     * Throws {@link PolicyCompilationException} if YAML syntax is invalid or required fields are missing.
     */
    public PolicyAst compile(String yamlContent) {
        if (yamlContent == null || yamlContent.isBlank()) {
            throw new PolicyCompilationException("YAML policy content must not be null or blank");
        }

        try {
            PolicyAst ast = yamlMapper.readValue(yamlContent, PolicyAst.class);
            validateAst(ast);
            return ast;
        } catch (JsonProcessingException e) {
            logger.debug("Policy YAML compilation syntax error", e);
            Throwable cause = e.getCause();
            if (cause instanceof IllegalArgumentException iae) {
                throw new PolicyCompilationException("Invalid AST policy rules: " + iae.getMessage(), e);
            }
            throw new PolicyCompilationException("Syntax error in YAML policy: " + e.getOriginalMessage(), e);
        } catch (IllegalArgumentException e) {
            logger.debug("Policy AST validation error", e);
            throw new PolicyCompilationException("Invalid AST policy rules: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.debug("Unexpected error compiling policy YAML", e);
            throw new PolicyCompilationException("Failed to compile policy: " + e.getMessage(), e);
        }
    }

    /**
     * Compiles a {@link SecurityPolicy} entity into an executable AST.
     */
    public PolicyAst compile(SecurityPolicy policy) {
        Objects.requireNonNull(policy, "policy must not be null");
        try {
            return compile(policy.rawYaml());
        } catch (PolicyCompilationException e) {
            throw new PolicyCompilationException("Failed to compile policy '" + policy.id() + "': " + e.getMessage(), policy.id(), e);
        }
    }

    private void validateAst(PolicyAst ast) {
        if (ast == null) {
            throw new IllegalArgumentException("Parsed policy AST is empty");
        }
        if (ast.id() == null || ast.id().isBlank()) {
            throw new IllegalArgumentException("Policy 'id' is required");
        }
        if (ast.name() == null || ast.name().isBlank()) {
            throw new IllegalArgumentException("Policy 'name' is required");
        }
        if (ast.version() == null || ast.version().isBlank()) {
            throw new IllegalArgumentException("Policy 'version' is required");
        }
    }
}
