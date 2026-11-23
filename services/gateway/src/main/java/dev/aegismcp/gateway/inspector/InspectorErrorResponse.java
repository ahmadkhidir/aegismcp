package dev.aegismcp.gateway.inspector;

/**
 * Error body of a refused {@code GET /api/v1/stream/traffic} request. C-002 fixes the status codes
 * ({@code 401}, {@code 403}, {@code 503}) and the shape is the {@code {"error": "..."}} envelope the
 * other management endpoints answer with, so the console renders the reason it already knows how to
 * read.
 *
 * <p>Anchors: FEAT-008, C-002.
 */
public record InspectorErrorResponse(String error) {
}
