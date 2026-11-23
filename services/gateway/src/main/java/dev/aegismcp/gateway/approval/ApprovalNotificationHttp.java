package dev.aegismcp.gateway.approval;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Shared HTTP POST used by the Slack and webhook notification channels.
 *
 * <p>The failure type carries only the HTTP status, never the URI or the response body: a Slack
 * incoming-webhook URL is itself a credential and a receiver's body may echo request content, so
 * neither may reach a log line or a delivery record (NFR-023, FEAT-006).
 */
final class ApprovalNotificationHttp {

    private ApprovalNotificationHttp() {
    }

    /** A delivery failure whose detail is safe to report. */
    static final class DeliveryFailedException extends Exception {
        private final int statusCode;

        DeliveryFailedException(String reason, int statusCode, Throwable cause) {
            super(reason, cause);
            this.statusCode = statusCode;
        }

        /** The HTTP status, or {@code -1} when the request never reached the destination. */
        int statusCode() {
            return statusCode;
        }
    }

    /**
     * Posts a JSON body and treats any non-2xx answer as a delivery failure so the dispatcher
     * retries instead of assuming the reviewer saw the message.
     */
    static void postJson(HttpClient client, Duration timeout, URI uri, byte[] body)
            throws DeliveryFailedException {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        HttpResponse<Void> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new DeliveryFailedException("interrupted", -1, e);
        } catch (Exception e) {
            throw new DeliveryFailedException("transport failure", -1, e);
        }
        int status = response.statusCode();
        if (status < 200 || status > 299) {
            throw new DeliveryFailedException("HTTP " + status, status, null);
        }
    }
}
