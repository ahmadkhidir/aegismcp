package dev.aegismcp.gateway.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe, high-performance in-memory cache for compiled SecurityPolicy ASTs.
 * Guarantees sub-millisecond rule evaluation with atomic zero-downtime policy reloading.
 *
 * <p>The cache also owns the policy lifecycle the management contracts expose: a published
 * document is stored as a {@code draft}, one version is {@code active} at a time, and an
 * activation archives the version it replaces (C-005, C-006, C-017, C-018).
 *
 * <p>Anchors: FEAT-002, NFR-001, C-005, C-006, C-017, C-018, architecture.md.
 */
public class PolicyCache {

    private static final Logger logger = LoggerFactory.getLogger(PolicyCache.class);

    private final PolicyCompiler compiler;
    private final Map<String, SecurityPolicy> policiesById = new ConcurrentHashMap<>();
    private final Map<String, PolicyAst> compiledAsts = new ConcurrentHashMap<>();
    private final Map<String, String> agentBindings = new ConcurrentHashMap<>();

    private volatile String activePolicyId = null;

    public PolicyCache() {
        this(PolicyCompiler.getInstance());
    }

    public PolicyCache(PolicyCompiler compiler) {
        this.compiler = Objects.requireNonNull(compiler, "compiler must not be null");
    }

    /**
     * Atomically compiles and stores a new or updated {@link SecurityPolicy}. A draft is validated
     * and catalogued without governing traffic; an active policy replaces the previous active
     * version, which is archived.
     */
    public PolicyAst putPolicy(SecurityPolicy policy) {
        Objects.requireNonNull(policy, "policy must not be null");

        // 1. Compile AST first; fails fast without corrupting existing cache state
        PolicyAst ast = compiler.compile(policy);

        synchronized (this) {
            if (SecurityPolicy.STATUS_ACTIVE.equals(policy.status())) {
                archiveCurrentActiveLocked();
                policiesById.put(policy.id(), policy);
                compiledAsts.put(policy.id(), ast);
                activePolicyId = policy.id();
                registerAgentBindings(policy, ast);
            } else {
                policiesById.put(policy.id(), policy);
                compiledAsts.put(policy.id(), ast);
                if (SecurityPolicy.STATUS_ARCHIVED.equals(policy.status())) {
                    unbind(policy.id());
                }
            }
        }

        logger.info("SecurityPolicy '{}' (v{}) loaded with status {} into the in-memory cache",
                policy.id(), policy.version(), policy.status());
        return ast;
    }

    /**
     * Activates a policy version, archiving the version it replaces and replacing the compiled
     * document governing traffic before this method returns (C-018).
     */
    public synchronized SecurityPolicy activate(SecurityPolicy policy) {
        Objects.requireNonNull(policy, "policy must not be null");
        PolicyAst ast = compiler.compile(policy);

        archiveCurrentActiveLocked();
        SecurityPolicy active = policy.withStatus(SecurityPolicy.STATUS_ACTIVE);
        policiesById.put(active.id(), active);
        compiledAsts.put(active.id(), ast);
        activePolicyId = active.id();
        registerAgentBindings(active, ast);

        logger.info("SecurityPolicy '{}' (v{}) activated in the in-memory cache", active.id(), active.version());
        return active;
    }

    /** The currently active policy version, or null when no version has been activated. */
    public SecurityPolicy getActivePolicy() {
        String id = activePolicyId;
        return id != null ? policiesById.get(id) : null;
    }

    /** Finds a catalogued policy whose declared YAML is byte-identical to the supplied document. */
    public SecurityPolicy findByRawYaml(String rawYaml) {
        if (rawYaml == null) {
            return null;
        }
        for (SecurityPolicy policy : policiesById.values()) {
            if (rawYaml.equals(policy.rawYaml())) {
                return policy;
            }
        }
        return null;
    }

    private void archiveCurrentActiveLocked() {
        String previousId = activePolicyId;
        if (previousId == null) {
            return;
        }
        SecurityPolicy previous = policiesById.get(previousId);
        if (previous != null && SecurityPolicy.STATUS_ACTIVE.equals(previous.status())) {
            policiesById.put(previousId, previous.withStatus(SecurityPolicy.STATUS_ARCHIVED));
            unbind(previousId);
        }
        activePolicyId = null;
    }

    private void registerAgentBindings(SecurityPolicy policy, PolicyAst ast) {
        for (String targetAgent : ast.targetAgents()) {
            if (!"*".equals(targetAgent)) {
                agentBindings.put(targetAgent, policy.id());
            }
        }
    }

    private void unbind(String policyId) {
        agentBindings.values().removeIf(policyId::equals);
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

        // 4. Fallback to the active wildcard policy; an active policy scoped to named agents
        // never governs an unidentified workload.
        String currentActiveId = activePolicyId;
        if (currentActiveId != null) {
            SecurityPolicy defPol = policiesById.get(currentActiveId);
            PolicyAst activeAst = compiledAsts.get(currentActiveId);
            if (defPol != null && activeAst != null
                    && SecurityPolicy.STATUS_ACTIVE.equals(defPol.status())
                    && activeAst.targetAgents().contains("*")) {
                return activeAst;
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
        list.sort(Comparator.comparing(SecurityPolicy::createdAt));
        return list;
    }

    public SecurityPolicy removePolicy(String id) {
        if (id == null) {
            return null;
        }
        SecurityPolicy removed;
        synchronized (this) {
            removed = policiesById.remove(id);
            compiledAsts.remove(id);
            unbind(id);
            if (id.equals(activePolicyId)) {
                activePolicyId = null;
            }
        }
        return removed;
    }

    public int size() {
        return policiesById.size();
    }

    public void clear() {
        synchronized (this) {
            policiesById.clear();
            compiledAsts.clear();
            agentBindings.clear();
            activePolicyId = null;
        }
    }
}
