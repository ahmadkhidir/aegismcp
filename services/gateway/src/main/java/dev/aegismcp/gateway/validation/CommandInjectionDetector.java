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
 * Detector identifying shell command injection tokens and chaining operators.
 * Anchors: FEAT-012, NFR-024.
 */
public class CommandInjectionDetector {

    private static final Set<String> COMMAND_PARAM_NAMES = Set.of(
            "cmd", "command", "exec", "script", "shell", "args", "run", "bash", "sh", "cli"
    );

    private static final Set<String> SQL_PARAM_NAMES = Set.of(
            "query", "sql", "statement", "db_query", "sql_query"
    );

    // Chaining tokens: &&, |, ||, ;, backticks (`), and $()
    private static final Pattern COMMAND_CHAINING_PATTERN = Pattern.compile(
            "(&&|\\|\\||\\||;|`|\\$\\()",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern STRONG_SHELL_TOKENS_PATTERN = Pattern.compile(
            "(&&|\\|\\||\\||`|\\$\\()",
            Pattern.CASE_INSENSITIVE
    );

    public List<ValidationViolation> detect(ToolSchema toolSchema, JsonNode arguments) {
        List<ValidationViolation> violations = new ArrayList<>();
        if (arguments == null || !arguments.isObject()) {
            return violations;
        }

        boolean isCmdTool = toolSchema != null && toolSchema.isCommandTool();
        boolean isDbTool = toolSchema != null && toolSchema.isDatabaseTool();

        Iterator<Map.Entry<String, JsonNode>> fields = arguments.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            String paramName = field.getKey();
            JsonNode paramValue = field.getValue();

            // Skip command injection checking on database tools or SQL parameters
            if (isDbTool || isSqlParameter(paramName)) {
                continue;
            }

            if (paramValue.isTextual()) {
                String text = paramValue.asText();
                checkParam(paramName, text, isCmdTool, violations);
            } else if (paramValue.isArray()) {
                int idx = 0;
                for (JsonNode item : paramValue) {
                    if (item.isTextual()) {
                        checkParam(paramName + "[" + idx + "]", item.asText(), isCmdTool, violations);
                    }
                    idx++;
                }
            }
        }

        return violations;
    }

    private void checkParam(String paramName, String text, boolean isCmdTool, List<ValidationViolation> violations) {
        if (text == null || text.isBlank()) {
            return;
        }

        boolean isCmdParam = isCommandParameter(paramName);
        if (isCmdTool || isCmdParam) {
            var matcher = COMMAND_CHAINING_PATTERN.matcher(text);
            if (matcher.find()) {
                String token = matcher.group();
                violations.add(ValidationViolation.commandInjection(
                        paramName,
                        "Command injection chaining token '" + token + "' detected in parameter '" + paramName + "'",
                        text
                ));
            }
        } else {
            // In generic parameters, detect strong shell chaining tokens: &&, |, `...`, $()
            var matcher = STRONG_SHELL_TOKENS_PATTERN.matcher(text);
            if (matcher.find()) {
                String token = matcher.group();
                violations.add(ValidationViolation.commandInjection(
                        paramName,
                        "Command injection chaining token '" + token + "' detected in parameter '" + paramName + "'",
                        text
                ));
            }
        }
    }

    private boolean isCommandParameter(String paramName) {
        if (paramName == null) return false;
        String lower = paramName.toLowerCase(Locale.ROOT);
        return COMMAND_PARAM_NAMES.contains(lower) || lower.endsWith("command") || lower.endsWith("cmd");
    }

    private boolean isSqlParameter(String paramName) {
        if (paramName == null) return false;
        String lower = paramName.toLowerCase(Locale.ROOT);
        return SQL_PARAM_NAMES.contains(lower) || lower.endsWith("query") || lower.endsWith("sql");
    }
}
