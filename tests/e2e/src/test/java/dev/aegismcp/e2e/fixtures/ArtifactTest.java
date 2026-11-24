package dev.aegismcp.e2e.fixtures;

import org.junit.jupiter.api.AfterEach;

/**
 * Base for the artifact-level conformance suites. The gateway is started lazily on first use so a
 * test that needs a different deployment surface can start its own harness without paying for an
 * unused one. Every started harness is torn down after the test, including on failure.
 */
public abstract class ArtifactTest {

    private GatewayHarness gateway;

    protected GatewayHarness gateway() throws Exception {
        if (gateway == null) {
            gateway = GatewayHarness.start();
        }
        return gateway;
    }

    protected GatewayHarness start(GatewayOptions options) throws Exception {
        return GatewayHarness.start(options);
    }

    @AfterEach
    void closeArtifact() {
        if (gateway != null) {
            gateway.close();
            gateway = null;
        }
    }
}
