package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying SQL injection detection across common attack vectors.
 * Anchors: FEAT-012 AC 3, NFR-024.
 */
class SqlInjectionDetectorTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private SqlInjectionDetector detector;
    private ToolSchema dbTool;

    @BeforeEach
    void setUp() {
        detector = new SqlInjectionDetector();
        dbTool = ToolSchema.database("execute_sql", null);
    }

    @Test
    @DisplayName("FEAT-012 AC 3: UNION SELECT injection payload is detected and blocked")
    void testUnionSelectDetected() {
        ObjectNode args = mapper.createObjectNode();
        args.put("query", "SELECT id, name FROM users WHERE id = 1 UNION SELECT password, email FROM admin_users");

        List<ValidationViolation> violations = detector.detect(dbTool, args);
        assertFalse(violations.isEmpty(), "UNION SELECT must be flagged as violation");
        assertTrue(violations.get(0).message().contains("SQL injection pattern detected"));
    }

    @Test
    @DisplayName("FEAT-012 AC 3: Tautology ' OR '1'='1 injection is detected")
    void testTautologySingleQuoteDetected() {
        ObjectNode args = mapper.createObjectNode();
        args.put("filter", "admin' OR '1'='1");

        List<ValidationViolation> violations = detector.detect(dbTool, args);
        assertFalse(violations.isEmpty());
        assertTrue(violations.get(0).message().contains("SQL injection pattern detected"));
    }

    @Test
    @DisplayName("FEAT-012 AC 3: Tautology OR 1=1 -- injection is detected")
    void testTautologyCommentDetected() {
        ObjectNode args = mapper.createObjectNode();
        args.put("where", "id = 5 OR 1=1 --");

        List<ValidationViolation> violations = detector.detect(dbTool, args);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("FEAT-012 AC 3: DROP TABLE DDL injection is detected")
    void testDropTableDetected() {
        ObjectNode args = mapper.createObjectNode();
        args.put("statement", "SELECT * FROM orders; DROP TABLE audit_log");

        List<ValidationViolation> violations = detector.detect(dbTool, args);
        assertFalse(violations.isEmpty());
        assertTrue(violations.get(0).message().contains("SQL injection pattern detected"));
    }

    @Test
    @DisplayName("FEAT-012 AC 3: TRUNCATE TABLE injection is detected")
    void testTruncateTableDetected() {
        ObjectNode args = mapper.createObjectNode();
        args.put("query", "TRUNCATE TABLE users");

        List<ValidationViolation> violations = detector.detect(dbTool, args);
        assertFalse(violations.isEmpty());
    }

    @Test
    @DisplayName("FEAT-012: Benign parameterized query without injection passes")
    void testBenignQueryPasses() {
        ObjectNode args = mapper.createObjectNode();
        args.put("query", "SELECT id, title, price FROM products WHERE category_id = 42 ORDER BY price DESC LIMIT 10");

        List<ValidationViolation> violations = detector.detect(dbTool, args);
        assertTrue(violations.isEmpty(), "Benign SQL query should not trigger false positives");
    }
}
