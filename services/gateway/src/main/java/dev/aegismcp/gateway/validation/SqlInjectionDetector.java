package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Inspector detecting SQL injection keywords and malicious syntax patterns in tool arguments.
 * Anchors: FEAT-012, NFR-024.
 */
public class SqlInjectionDetector {

    private static final Set<String> SQL_PARAM_NAMES = Set.of(
            "query", "sql", "statement", "db_query", "sql_query",
            "filter", "where", "command", "querystring", "search"
    );

    private static final List<Pattern> SQL_INJECTION_PATTERNS = List.of(
            // UNION [ALL] SELECT
            Pattern.compile("\\bUNION\\b\\s+(?:ALL\\s+)?\\bSELECT\\b", Pattern.CASE_INSENSITIVE),

            // DDL injection: DROP TABLE, ALTER TABLE, TRUNCATE TABLE
            Pattern.compile("\\b(DROP|ALTER|TRUNCATE)\\s+(TABLE|DATABASE|VIEW|INDEX|SCHEMA|PROCEDURE)\\b", Pattern.CASE_INSENSITIVE),

            // Tautology: ' OR '1'='1, ' OR 1=1, " OR "1"="1", OR 1=1, OR 'a'='a'
            Pattern.compile("['\"]\\s*(?:OR|AND)\\s*['\"]?[\\w\\d]+['\"]?\\s*=\\s*['\"]?[\\w\\d]+['\"]?", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(?:OR|AND)\\b\\s+['\"]?1['\"]?\\s*=\\s*['\"]?1['\"]?", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(?:OR|AND)\\b\\s+['\"]?a['\"]?\\s*=\\s*['\"]?a['\"]?", Pattern.CASE_INSENSITIVE),
            Pattern.compile("['\"]\\s*(?:OR|AND)\\s*true\\b", Pattern.CASE_INSENSITIVE),

            // Comment sequence with quote or operator: ' OR ... -- or ; DROP ...
            Pattern.compile("['\"][^;\\n]*--", Pattern.CASE_INSENSITIVE),
            Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL),

            // Stacked commands: ; DROP TABLE ..., ; DELETE FROM ...
            Pattern.compile(";\\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER|TRUNCATE|EXEC|EXECUTE)\\b", Pattern.CASE_INSENSITIVE),

            // SQL delay / blind execution
            Pattern.compile("\\b(WAITFOR\\s+DELAY|SLEEP\\s*\\(|PG_SLEEP\\s*\\(|BENCHMARK\\s*\\()", Pattern.CASE_INSENSITIVE),

            // Stored procs
            Pattern.compile("\\b(EXEC|EXECUTE)\\s+(?:xp_\\w+|sp_\\w+)", Pattern.CASE_INSENSITIVE)
    );

    public List<ValidationViolation> detect(ToolSchema toolSchema, JsonNode arguments) {
        List<ValidationViolation> violations = new ArrayList<>();
        if (arguments == null || !arguments.isObject()) {
            return violations;
        }

        boolean isDbTool = toolSchema != null && toolSchema.isDatabaseTool();

        Iterator<Map.Entry<String, JsonNode>> fields = arguments.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            String paramName = field.getKey();
            JsonNode paramValue = field.getValue();

            if (paramValue.isTextual()) {
                String text = paramValue.asText();
                boolean shouldInspect = isDbTool || isSqlParameter(paramName) || containsObviousSqlKeywords(text);
                if (shouldInspect) {
                    checkSqlInjection(paramName, text, violations);
                }
            } else if (paramValue.isArray()) {
                int idx = 0;
                for (JsonNode item : paramValue) {
                    if (item.isTextual()) {
                        String text = item.asText();
                        if (isDbTool || isSqlParameter(paramName) || containsObviousSqlKeywords(text)) {
                            checkSqlInjection(paramName + "[" + idx + "]", text, violations);
                        }
                    }
                    idx++;
                }
            }
        }

        return violations;
    }

    private boolean isSqlParameter(String paramName) {
        if (paramName == null) return false;
        String lower = paramName.toLowerCase(Locale.ROOT);
        return SQL_PARAM_NAMES.contains(lower) || lower.endsWith("query") || lower.endsWith("sql");
    }

    private boolean containsObviousSqlKeywords(String text) {
        if (text == null) return false;
        String upper = text.toUpperCase(Locale.ROOT);
        return upper.contains("UNION") || upper.contains("DROP TABLE") || upper.contains("1=1") || upper.contains("--");
    }

    private void checkSqlInjection(String paramName, String value, List<ValidationViolation> violations) {
        if (value == null || value.isBlank()) {
            return;
        }

        for (Pattern pattern : SQL_INJECTION_PATTERNS) {
            if (pattern.matcher(value).find()) {
                violations.add(ValidationViolation.sqlInjection(
                        paramName,
                        "SQL injection pattern detected in parameter '" + paramName + "'",
                        value
                ));
                return;
            }
        }
    }
}
