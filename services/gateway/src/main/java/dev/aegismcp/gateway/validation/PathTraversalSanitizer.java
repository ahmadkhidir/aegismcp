package dev.aegismcp.gateway.validation;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Sanitizer detecting directory traversal patterns, null byte injections, and out-of-bounds canonical paths.
 * Anchors: FEAT-012, NFR-024.
 */
public class PathTraversalSanitizer {

    private static final Set<String> PATH_PARAMETER_NAMES = Set.of(
            "path", "filepath", "file_path", "filename", "file_name",
            "dir", "directory", "folder", "dest", "destination",
            "src", "source", "target", "file", "uri", "url"
    );

    private static final Pattern TRAVERSAL_PATTERN = Pattern.compile(
            "(\\.\\./|\\.\\.\\\\|/\\.\\.|\\\\\\.\\.|%2e%2e%2f|%2e%2e/|\\.\\.%2f|%2e%2e%5c|\\.\\.%5c|%252e%252e)",
            Pattern.CASE_INSENSITIVE
    );

    private static final List<String> SENSITIVE_PATHS = List.of(
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/", "/sys/", "c:\\windows\\", "c:/windows/"
    );

    public List<ValidationViolation> sanitize(ToolSchema toolSchema, JsonNode arguments) {
        List<ValidationViolation> violations = new ArrayList<>();
        if (arguments == null || !arguments.isObject()) {
            return violations;
        }

        String allowedBaseDir = toolSchema != null ? toolSchema.allowedBaseDir() : null;
        boolean isFilesystemTool = toolSchema != null && toolSchema.isFilesystemTool();

        Iterator<Map.Entry<String, JsonNode>> fields = arguments.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            String paramName = field.getKey();
            JsonNode paramValue = field.getValue();

            if (paramValue.isTextual()) {
                String rawPath = paramValue.asText();
                boolean shouldInspect = isFilesystemTool || isPathParameter(paramName) || containsTraversalTokens(rawPath);

                if (shouldInspect) {
                    checkPath(paramName, rawPath, allowedBaseDir, violations);
                }
            } else if (paramValue.isArray()) {
                // If array of paths
                int idx = 0;
                for (JsonNode item : paramValue) {
                    if (item.isTextual()) {
                        String rawPath = item.asText();
                        if (isFilesystemTool || isPathParameter(paramName) || containsTraversalTokens(rawPath)) {
                            checkPath(paramName + "[" + idx + "]", rawPath, allowedBaseDir, violations);
                        }
                    }
                    idx++;
                }
            }
        }

        return violations;
    }

    private boolean isPathParameter(String paramName) {
        if (paramName == null) return false;
        String lower = paramName.toLowerCase(Locale.ROOT);
        return PATH_PARAMETER_NAMES.contains(lower) || lower.endsWith("path") || lower.endsWith("file") || lower.endsWith("dir");
    }

    private boolean containsTraversalTokens(String value) {
        if (value == null) return false;
        return value.contains("../") || value.contains("..\\") || value.contains("..") || TRAVERSAL_PATTERN.matcher(value).find();
    }

    private void checkPath(String paramName, String rawPath, String allowedBaseDir, List<ValidationViolation> violations) {
        if (rawPath == null || rawPath.isBlank()) {
            return;
        }

        // 1. Detect null byte injection
        if (rawPath.contains("\0") || rawPath.contains("%00")) {
            violations.add(ValidationViolation.pathTraversal(
                    paramName,
                    "Null byte injection detected in path parameter '" + paramName + "'",
                    rawPath
            ));
            return;
        }

        // 2. Decode URL encoded values for analysis
        String decoded = rawPath;
        try {
            decoded = URLDecoder.decode(rawPath, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
        }

        // 3. Inspect raw and decoded traversal tokens
        boolean hasToken = TRAVERSAL_PATTERN.matcher(rawPath).find()
                || TRAVERSAL_PATTERN.matcher(decoded).find()
                || decoded.startsWith("../") || decoded.startsWith("..\\")
                || decoded.equals("..");

        // 4. Canonical path resolution check
        boolean outOfBounds = false;
        try {
            if (allowedBaseDir != null && !allowedBaseDir.isBlank()) {
                Path base = Paths.get(allowedBaseDir).toAbsolutePath().normalize();
                Path resolved;
                Path given = Paths.get(decoded);
                if (given.isAbsolute()) {
                    resolved = given.normalize();
                } else {
                    resolved = base.resolve(given).normalize();
                }

                if (!resolved.startsWith(base)) {
                    outOfBounds = true;
                }
            } else {
                // Without explicit base dir, resolve path and check if it escapes relative boundary
                Path p = Paths.get(decoded).normalize();
                if (p.toString().startsWith("..") || hasToken) {
                    outOfBounds = true;
                }
                String normalizedStr = p.toString().toLowerCase(Locale.ROOT).replace('\\', '/');
                for (String sensitive : SENSITIVE_PATHS) {
                    if (normalizedStr.contains(sensitive)) {
                        outOfBounds = true;
                        break;
                    }
                }
            }
        } catch (Exception e) {
            // Unparseable path with traversal tokens
            if (hasToken) {
                outOfBounds = true;
            }
        }

        if (hasToken || outOfBounds) {
            violations.add(ValidationViolation.pathTraversal(
                    paramName,
                    "Path traversal detected in parameter '" + paramName + "': out-of-bounds traversal attempt (" + rawPath + ")",
                    rawPath
            ));
        }
    }
}
