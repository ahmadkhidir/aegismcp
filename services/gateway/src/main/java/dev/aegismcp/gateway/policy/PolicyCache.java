package dev.aegismcp.gateway.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe, high-performance in-memory cache for compiled SecurityPolicy ASTs.
 * Guarantees sub-millisecond rule evaluation with atomic zero-downtime policy reloading.
 * Anchors: FEAT-002, NFR-001, architecture.md.
 */
public class PolicyCache {

    private static final Logger logger = LoggerFactory.getLogger(PolicyCache.class);

    private final PolicyCompiler compiler;
    private final Map<String, SecurityPolicy> policiesById = new ConcurrentHashMap<>();
    private final Map<String, PolicyAst> compiledAsts = new ConcurrentHashMap<>();
    private final Map<String, String> agentBindings = new ConcurrentHashMap<>();

    private volatile String defaultPolicyId = null;

    public PolicyCache() {
        this(PolicyCompiler.getInstance());
    }

    public PolicyCache(PolicyCompiler compiler) {
        this.compiler = Objects.requireNonNull(compiler, "compiler must not be null");
    }

    /**
     * Atomically compiles and stores a new or updated {@link SecurityPolicy}.
     * If the policy YAML has syntax or schema errors, compilation fails fast and
     * the previously active valid policy in memory is preserved intact (FEAT-002).
     */
    public PolicyAst putPolicy(SecurityPolicy policy) {
        Objects.requireNonNull(policy, "policy must not be null");

        // 1. Compile AST first; fails fast without corrupting existing cache state
        PolicyAst ast = compiler.compile(policy);

        // 2. Atomically store validated policy and AST
        policiesById.put(policy.id(), policy);
        compiledAsts.put(policy.id(), ast);

        // 3. Register target agent bindings if active
        if (SecurityPolicy.STATUS_ACTIVE.equals(policy.status())) {
            for (String targetAgent : ast.targetAgents()) {
                if ("*".equals(targetAgent)) {
                    defaultPolicyId = policy.id();
                } else {
                    agentBindings.put(targetAgent, policy.id());
                }
            }
        }

        logger.info("SecurityPolicy '{}' (v{}) loaded successfully into in-memory cache", policy.id(), policy.version());
        return ast;
    }

    /**
     * Binds an explicit agent identifier or SPIFFE ID pattern to a policy ID.
     */
    public void bindAgentToPolicy(String agentPattern, String policyId) {
        Objects.requireNonNull(agentPattern, "agentPattern must not be null");
        Objects.requireNonNull(policyId, "policyId must not be null");
        if (!policiesById.containsKey(policyId)) {
            throw new IllegalArgumentException("Cannot bind to unknown policy ID: " + policyId);
        }
        agentBindings.put(agentPattern, policyId);
    }

    /**
     * Retrieves the compiled {@link PolicyAst} governing the given agent workload.
     * Returns null if no active policy is bound (fail-closed trigger).
     */
    public PolicyAst getPolicyForAgent(String agentId, String spiffeId) {
        // 1. Direct agentId binding
        if (agentId != null) {
            String policyId = agentBindings.get(agentId);
            if (policyId != null) {
                PolicyAst ast = compiledAsts.get(policyId);
                if (ast != null) {
                    return ast;
                }
            }
        }

        // 2. Direct spiffeId binding
        if (spiffeId != null) {
            String policyId = agentBindings.get(spiffeId);
            if (policyId != null) {
                PolicyAst ast = compiledAsts.get(policyId);
                if (ast != null) {
                    return ast;
                }
            }
        }

        // 3. Pattern match across active policies
        for (PolicyAst ast : compiledAsts.values()) {
            SecurityPolicy pol = policiesById.get(ast.id());
            if (pol != null && SecurityPolicy.STATUS_ACTIVE.equals(pol.status())) {
                if (ast.matchesAgent(agentId, spiffeId) && !ast.targetAgents().contains("*")) {
                    return ast;
                }
            }
        }

        // 4. Fallback to default wildcard policy
        if (defaultPolicyId != null) {
            SecurityPolicy defPol = policiesById.get(defaultPolicyId);
            if (defPol != null && SecurityPolicy.STATUS_ACTIVE.equals(defPol.status())) {
                return compiledAsts.get(defaultPolicyId);
            }
        }

        return null;
    }

    public SecurityPolicy getPolicy(String id) {
        return id != null ? policiesById.get(id) : null;
    }

    public PolicyAst getAst(String id) {
        return id != null ? compiledAsts.get(id) : null;
    }

    public List<SecurityPolicy> getAllPolicies(String statusFilter) {
        List<SecurityPolicy> list = new ArrayList<>();
        for (SecurityPolicy policy : policiesById.values()) {
            if (statusFilter == null || statusFilter.isBlank() || statusFilter.equalsIgnoreCase(policy.status())) {
                list.add(policy);
            }
        }
        return list;
    }

    public SecurityPolicy removePolicy(String id) {
        if (id == null) {
            return null;
        }
        SecurityPolicy removed = policiesById.remove(id);
        compiledAsts.remove(id);
        agentBindings.values().removeIf(id::equals);
        if (id.equals(defaultPolicyId)) {
            defaultPolicyId = null;
        }
        return removed;
    }

    public int size() {
        return policiesById.size();
    }

    public void clear() {
        policiesById.clear();
        compiledAsts.clear();
        agentBindings.clear();
        defaultPolicyId = null;
    }
}
