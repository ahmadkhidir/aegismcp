package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.aegismcp.gateway.codec.JsonRpcError;
import dev.aegismcp.gateway.codec.JsonRpcId;
import dev.aegismcp.gateway.codec.JsonRpcRequest;
import dev.aegismcp.gateway.policy.DeclarativePolicyInterceptor;
import dev.aegismcp.gateway.policy.PolicyCache;
import dev.aegismcp.gateway.policy.PolicyCompiler;
import dev.aegismcp.gateway.policy.PolicyEvaluator;
import dev.aegismcp.gateway.policy.SecurityPolicy;
import dev.aegismcp.gateway.proxy.AgentIdentity;
import dev.aegismcp.gateway.proxy.InterceptionVerdict;
import dev.aegismcp.gateway.proxy.SecurityContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying ApprovalManager behavior, lifecycle, timeout scheduling, and policy integration.
 * Anchors: FEAT-006, C-003, C-004, NFR-001.
 */
class ApprovalManagerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private ApprovalManager approvalManager;

    @BeforeEach
    void setUp() {
        approvalManager = new ApprovalManager(Duration.ofSeconds(2));
    }

    @AfterEach
    void tearDown() {
        if (approvalManager != null) {
            approvalManager.close();
        }
    }

    private SecurityContext createContext(String agentId) {
        AgentIdentity identity = new AgentIdentity(agentId, null, "test-token", true);
        return SecurityContext.of(identity, new InetSocketAddress("127.0.0.1", 54321));
    }

    @Test
    @DisplayName("FEAT-006 / C-003: Creating approval ticket suspends async future and registers ticket in store")
    void testCreateAndSuspendTicket() {
        ObjectNode args = mapper.createObjectNode();
        args.put("database", "production_master");

        CompletableFuture<InterceptionVerdict> future = approvalManager.createAndSuspendTicket(
                "agent-007",
                "drop_database",
                args,
                95.0,
                "pol_strict",
                Duration.ofMinutes(5)
        );

        assertNotNull(future);
        assertFalse(future.isDone(), "Future should be suspended awaiting human review");

        List<ApprovalTicket> tickets = approvalManager.getTickets("pending");
        assertEquals(1, tickets.size());

        ApprovalTicket ticket = tickets.get(0);
        assertEquals("agent-007", ticket.agentId());
        assertEquals("drop_database", ticket.toolName());
        assertEquals("pending", ticket.status());
        assertEquals(95.0, ticket.riskScore());
    }

    @Test
    @DisplayName("FEAT-006 / C-004: Operator APPROVE decision resumes suspended future with InterceptionVerdict.allow")
    void testOperatorApprovalResumesFuture() throws ExecutionException, InterruptedException, TimeoutException {
        ObjectNode args = mapper.createObjectNode();
        args.put("amount", 50000);

        CompletableFuture<InterceptionVerdict> future = approvalManager.createAndSuspendTicket(
                "agent-finance",
                "wire_transfer",
                args,
                88.0,
                "pol_finance_v1",
                Duration.ofMinutes(5)
        );

        List<ApprovalTicket> tickets = approvalManager.getTickets("pending");
        assertEquals(1, tickets.size());
        String ticketId = tickets.get(0).id();

        ApprovalDto.DecisionResponse response = approvalManager.submitDecision(
                ticketId,
                "APPROVE",
                "ciso_reviewer",
                "Transaction verified against invoice #4092"
        );

        assertNotNull(response);
        assertEquals(ticketId, response.ticketId());
        assertEquals("APPROVE", response.status());

        InterceptionVerdict verdict = future.get(1, TimeUnit.SECONDS);
        assertInstanceOf(InterceptionVerdict.Allow.class, verdict, "Approved request must yield Allow verdict");

        Optional<ApprovalTicket> updatedOpt = approvalManager.getTicket(ticketId);
        assertTrue(updatedOpt.isPresent());
        ApprovalTicket updated = updatedOpt.get();
        assertEquals("approved", updated.status());
        assertEquals("ciso_reviewer", updated.reviewer());
        assertEquals("Transaction verified against invoice #4092", updated.decisionReason());
    }

    @Test
    @DisplayName("FEAT-006 / C-004: Operator REJECT decision resumes future with Policy Violation (-32001 -> HTTP 403)")
    void testOperatorRejectionFailsWithPolicyViolation() throws ExecutionException, InterruptedException, TimeoutException {
        ObjectNode args = mapper.createObjectNode();
        args.put("query", "DROP DATABASE users;");

        CompletableFuture<InterceptionVerdict> future = approvalManager.createAndSuspendTicket(
                "agent-dba",
                "execute_sql",
                args,
                99.0,
                "pol_db_guard",
                Duration.ofMinutes(5)
        );

        String ticketId = approvalManager.getTickets("pending").get(0).id();

        ApprovalDto.DecisionResponse response = approvalManager.submitDecision(
                ticketId,
                "REJECT",
                "lead_dba",
                "Prohibited operation on production cluster"
        );

        assertEquals("REJECT", response.status());

        InterceptionVerdict verdict = future.get(1, TimeUnit.SECONDS);
        assertInstanceOf(InterceptionVerdict.Block.class, verdict);
        InterceptionVerdict.Block block = (InterceptionVerdict.Block) verdict;

        assertEquals(JsonRpcError.POLICY_VIOLATION, block.error().code());
        assertTrue(block.error().message().contains("Prohibited operation on production cluster"));
        assertEquals(io.netty.handler.codec.http.HttpResponseStatus.FORBIDDEN, block.error().toHttpStatus());

        ApprovalTicket updated = approvalManager.getTicket(ticketId).orElseThrow();
        assertEquals("rejected", updated.status());
        assertEquals("lead_dba", updated.reviewer());
        assertEquals("Prohibited operation on production cluster", updated.decisionReason());
    }

    @Test
    @DisplayName("FEAT-006: Timeout auto-rejection completes future with Approval Timed Out (-32002 -> HTTP 408)")
    void testTimeoutAutoRejection() throws ExecutionException, InterruptedException, TimeoutException {
        // Short TTL for deterministic test execution
        ApprovalManager quickTimeoutManager = new ApprovalManager(Duration.ofMillis(200));
        try {
            CompletableFuture<InterceptionVerdict> future = quickTimeoutManager.createAndSuspendTicket(
                    "agent-cron",
                    "scale_cluster",
                    mapper.createObjectNode(),
                    75.0,
                    "pol_infra",
                    Duration.ofMillis(200)
            );

            InterceptionVerdict verdict = future.get(2, TimeUnit.SECONDS);
            assertInstanceOf(InterceptionVerdict.Block.class, verdict);
            InterceptionVerdict.Block block = (InterceptionVerdict.Block) verdict;

            assertEquals(JsonRpcError.APPROVAL_TIMED_OUT, block.error().code());
            assertEquals(io.netty.handler.codec.http.HttpResponseStatus.REQUEST_TIMEOUT, block.error().toHttpStatus());
            assertTrue(block.error().message().contains("Approval request timed out"));

            List<ApprovalTicket> timedOutTickets = quickTimeoutManager.getTickets("timed_out");
            assertEquals(1, timedOutTickets.size());
            assertEquals("timed_out", timedOutTickets.get(0).status());
        } finally {
            quickTimeoutManager.close();
        }
    }

    @Test
    @DisplayName("C-004: Idempotency check prevents resolving already resolved ticket (HTTP 400)")
    void testIdempotencyCannotResolveAlreadyResolvedTicket() {
        approvalManager.createAndSuspendTicket(
                "agent-test",
                "restart_service",
                mapper.createObjectNode(),
                50.0,
                "pol_ops",
                Duration.ofMinutes(5)
        );

        String ticketId = approvalManager.getTickets("pending").get(0).id();

        // First resolution: approve
        approvalManager.submitDecision(ticketId, "APPROVE", "ops_admin", "Approved restart");

        // Second resolution attempt must fail with TicketAlreadyResolvedException
        assertThrows(ApprovalException.TicketAlreadyResolvedException.class, () -> {
            approvalManager.submitDecision(ticketId, "REJECT", "secops", "Late reject");
        });
    }

    @Test
    @DisplayName("C-004: Submitting decision on non-existent or expired ticket throws TicketNotFoundException (HTTP 404)")
    void testCannotResolveNonExistentOrExpiredTicket() {
        assertThrows(ApprovalException.TicketNotFoundException.class, () -> {
            approvalManager.submitDecision("appr_non_existent", "APPROVE", "admin", "reason");
        });
    }

    @Test
    @DisplayName("C-003: Ticket listing with status filtering returns only matching status")
    void testListingWithStatusFiltering() {
        approvalManager.createAndSuspendTicket("agent-1", "tool_a", mapper.createObjectNode(), 50.0, "pol", Duration.ofMinutes(5));
        approvalManager.createAndSuspendTicket("agent-2", "tool_b", mapper.createObjectNode(), 60.0, "pol", Duration.ofMinutes(5));
        approvalManager.createAndSuspendTicket("agent-3", "tool_c", mapper.createObjectNode(), 70.0, "pol", Duration.ofMinutes(5));

        List<ApprovalTicket> pendingTickets = approvalManager.getTickets("pending");
        assertEquals(3, pendingTickets.size());

        String id1 = pendingTickets.get(0).id();
        String id2 = pendingTickets.get(1).id();

        approvalManager.submitDecision(id1, "APPROVE", "rev1", "ok");
        approvalManager.submitDecision(id2, "REJECT", "rev2", "deny");

        assertEquals(1, approvalManager.getTickets("pending").size());
        assertEquals(1, approvalManager.getTickets("approved").size());
        assertEquals(1, approvalManager.getTickets("rejected").size());
        assertEquals(3, approvalManager.getTickets(null).size());
    }

    @Test
    @DisplayName("FEAT-006: Agent cancellation / client disconnect cancels pending approval ticket")
    void testAgentDisconnectCancelsPendingTicket() {
        CompletableFuture<InterceptionVerdict> future = approvalManager.createAndSuspendTicket(
                "agent-dc",
                "long_running_migration",
                mapper.createObjectNode(),
                90.0,
                "pol_db",
                Duration.ofMinutes(5)
        );

        assertEquals(1, approvalManager.getActiveTicketCount());

        // Simulate agent disconnecting / future cancelled
        future.cancel(true);

        assertEquals(0, approvalManager.getActiveTicketCount());
        List<ApprovalTicket> tickets = approvalManager.getTickets("rejected");
        assertEquals(1, tickets.size());
        assertTrue(tickets.get(0).decisionReason().contains("cancelled"));
    }

    @Test
    @DisplayName("FEAT-002 / FEAT-006: DeclarativePolicyInterceptor wires seamlessly with ApprovalManager on REQUIRE_APPROVAL")
    void testIntegrationWithDeclarativePolicyInterceptor() throws Exception {
        String yaml = """
                id: pol_hitl_test
                name: HITL Policy
                version: 1.0.0
                rules:
                  - id: rule_critical
                    tool: delete_all_data
                    action: require_approval
                """;

        SecurityPolicy policy = SecurityPolicy.of("pol_hitl_test", "HITL Policy", "1.0.0", yaml, "sha-hitl");
        PolicyCache cache = new PolicyCache();
        cache.putPolicy(policy);
        PolicyEvaluator evaluator = new PolicyEvaluator(cache);

        DeclarativePolicyInterceptor interceptor = new DeclarativePolicyInterceptor(evaluator, approvalManager);

        SecurityContext context = createContext("agent-dba");
        ObjectNode params = mapper.createObjectNode();
        params.put("name", "delete_all_data");

        JsonRpcRequest request = new JsonRpcRequest(JsonRpcId.of("req-delete-1"), JsonRpcRequest.METHOD_TOOLS_CALL, params);

        CompletableFuture<InterceptionVerdict> future = interceptor.intercept(context, request);
        assertNotNull(future);
        assertFalse(future.isDone());

        List<ApprovalTicket> pending = approvalManager.getTickets("pending");
        assertEquals(1, pending.size());
        assertEquals("delete_all_data", pending.get(0).toolName());

        // Approve ticket
        approvalManager.submitDecision(pending.get(0).id(), "APPROVE", "lead_admin", "Emergency authorization granted");

        InterceptionVerdict verdict = future.get(1, TimeUnit.SECONDS);
        assertInstanceOf(InterceptionVerdict.Allow.class, verdict);
    }
}
