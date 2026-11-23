package dev.aegismcp.gateway.inspector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import dev.aegismcp.gateway.dlp.DlpCategory;
import dev.aegismcp.gateway.dlp.DlpDetection;
import dev.aegismcp.gateway.dlp.DlpScrubber;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Builds the payload of one {@code traffic} event.
 *
 * <p>The intercepted arguments are scanned and scrubbed before they are attached, and the scan result
 * becomes the event's redaction summary, so the live inspector can render the payload and mark the
 * masked spans while the broadcast itself never carries a secret or personal data. A scanner failure
 * falls back to an empty argument object rather than forwarding what it could not classify.
 *
 * <p>Latency is the interval between the request reaching the edge and the event being produced,
 * measured per call rather than sampled, which is what the inspector's latency column and the filter
 * range in screen 02 read.
 *
 * <p>Anchors: FEAT-005, FEAT-008, NFR-005, C-002.
 */
public final class TrafficEventFactory {

    private final DlpScrubber scrubber;

    public TrafficEventFactory(DlpScrubber scrubber) {
        this.scrubber = Objects.requireNonNull(scrubber, "scrubber must not be null");
    }

    /** Renders one observed call with the terminal decision it reached. */
    public TrafficEvent create(TrafficObservations.Observation observation, TrafficDecision decision) {
        Objects.requireNonNull(observation, "observation must not be null");
        Objects.requireNonNull(decision, "decision must not be null");

        JsonNode arguments = observation.arguments() != null && observation.arguments().isObject()
                ? observation.arguments()
                : JsonNodeFactory.instance.objectNode();

        JsonNode scrubbedArguments;
        List<RedactionSummary> redactions;
        try {
            redactions = summarize(arguments);
            scrubbedArguments = scrubber.scrub(arguments);
        } catch (RuntimeException e) {
            // A scan that cannot classify the payload must not forward it: the event keeps its shape
            // with no arguments and no claim about what was masked.
            scrubbedArguments = JsonNodeFactory.instance.objectNode();
            redactions = List.of();
        }

        return new TrafficEvent(
                Instant.now().toString(),
                observation.agentId(),
                observation.toolName(),
                scrubbedArguments,
                decision.name(),
                latencyMillis(observation.receivedAt()),
                observation.matchedRuleIds(),
                redactions);
    }

    /** Counts the detections the scrubber would mask, grouped into the contract's summary rows. */
    private List<RedactionSummary> summarize(JsonNode arguments) {
        List<DlpDetection> detections = scrubber.scan(arguments.toString());
        Map<String, RedactionSummary> summaries = new LinkedHashMap<>();
        for (DlpDetection detection : detections) {
            String category = category(detection.category());
            String type = detection.patternType().name();
            String key = category + '\u0000' + type;
            RedactionSummary existing = summaries.get(key);
            summaries.put(key, new RedactionSummary(category, type,
                    existing != null ? existing.count() + 1 : 1));
        }
        return new ArrayList<>(summaries.values());
    }

    /** Collapses the scanner's five categories onto the two the contract names. */
    private static String category(DlpCategory category) {
        return category == DlpCategory.PII ? "PII" : "SECRET";
    }

    private static double latencyMillis(Instant receivedAt) {
        long nanos = Duration.between(receivedAt, Instant.now()).toNanos();
        if (nanos <= 0) {
            return 0.0;
        }
        return Math.round(nanos / 1_000.0) / 1_000.0;
    }
}
