package dev.aegismcp.gateway.approval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ApprovalTicket model conforming to schema.md and contract C-003.
 * Anchors: FEAT-006, C-003, schema.md#ApprovalTicket.
 */
class ApprovalTicketTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("schema.md & C-003: Model holds all required fields and JSON aliases")
    void testModelFieldsAndSerialization() throws Exception {
        ObjectNode args = mapper.createObjectNode();
        args.put("table", "customers");
        args.put("cascade", true);

        String now = Instant.now().toString();
        String later = Instant.now().plusSeconds(300).toString();

        ApprovalTicket ticket = new ApprovalTicket(
                "appr_12345",
                "agent-alpha",
                "drop_table",
                args,
                92.5,
                "pending",
                now,
                later,
                null,
                null,
                "pol_strict_db"
        );

        assertEquals("appr_12345", ticket.id());
        assertEquals("agent-alpha", ticket.agentId());
        assertEquals("drop_table", ticket.toolName());
        assertEquals(args, ticket.arguments());
        assertEquals(92.5, ticket.riskScore());
        assertEquals("pending", ticket.status());
        assertEquals(now, ticket.requestedAt());
        assertEquals(later, ticket.expiresAt());
        assertTrue(ticket.isPending());
        assertFalse(ticket.isExpired());

        // schema.md aliases
        assertEquals(args.toString(), ticket.argumentsPayload());
        assertEquals(now, ticket.createdAt());
        assertNull(ticket.reviewedBy());
        assertNull(ticket.rejectionReason());

        // JSON serialization
        String json = mapper.writeValueAsString(ticket);
        JsonNode tree = mapper.readTree(json);

        assertEquals("appr_12345", tree.get("id").asText());
        assertEquals("agent-alpha", tree.get("agentId").asText());
        assertEquals("drop_table", tree.get("toolName").asText());
        assertEquals("customers", tree.get("arguments").get("table").asText());
        assertEquals(92.5, tree.get("riskScore").asDouble());
        assertEquals("pending", tree.get("status").asText());
        assertEquals(now, tree.get("requestedAt").asText());
        assertEquals(later, tree.get("expiresAt").asText());
        assertEquals(args.toString(), tree.get("argumentsPayload").asText());
        assertEquals(now, tree.get("createdAt").asText());
    }

    @Test
    @DisplayName("FEAT-006: withDecision creates updated immutable ticket with reviewer and reason")
    void testWithDecision() {
        ApprovalTicket pending = new ApprovalTicket(
                "appr_test",
                "agent-beta",
                "transfer_funds",
                mapper.createObjectNode(),
                80.0,
                ApprovalStatus.PENDING.getValue(),
                Instant.now().toString(),
                Instant.now().plusSeconds(300).toString(),
                null,
                null,
                "pol_finance"
        );

        ApprovalTicket approved = pending.withDecision(ApprovalStatus.APPROVED, "secops_admin", "Verified legitimate");
        assertEquals("approved", approved.status());
        assertEquals("secops_admin", approved.reviewer());
        assertEquals("secops_admin", approved.reviewedBy());
        assertEquals("Verified legitimate", approved.decisionReason());
        assertEquals(pending.id(), approved.id());
        assertEquals(pending.toolName(), approved.toolName());
    }

    @Test
    @DisplayName("FEAT-006: isExpired detects expired tickets accurately")
    void testIsExpired() {
        String past = Instant.now().minusSeconds(10).toString();
        String future = Instant.now().plusSeconds(100).toString();

        ApprovalTicket expiredTicket = new ApprovalTicket(
                "appr_old",
                "agent-gamma",
                "exec_cmd",
                null,
                99.0,
                ApprovalStatus.PENDING.getValue(),
                past,
                past,
                null,
                null,
                null
        );

        ApprovalTicket activeTicket = new ApprovalTicket(
                "appr_new",
                "agent-gamma",
                "exec_cmd",
                null,
                99.0,
                ApprovalStatus.PENDING.getValue(),
                past,
                future,
                null,
                null,
                null
        );

        assertTrue(expiredTicket.isExpired());
        assertFalse(activeTicket.isExpired());
    }
}
