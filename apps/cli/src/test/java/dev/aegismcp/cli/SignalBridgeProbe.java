package dev.aegismcp.cli;

/**
 * Test helper process: installs the production signal bridge, raises the requested signal against
 * itself, and halts from the handler with the documented exit status. Running in its own process
 * lets the test observe real signal delivery without replacing the test runner's handlers.
 *
 * <p>Anchors: FEAT-003.
 */
public final class SignalBridgeProbe {

    public static void main(String[] args) throws Exception {
        String signalName = args.length > 0 ? args[0] : "INT";

        SignalBridge bridge = SignalBridge.install(received -> {
            System.out.println("HANDLED " + received.name() + " " + received.exitCode());
            System.out.flush();
            Runtime.getRuntime().halt(received.exitCode());
        });

        try {
            Class<?> signalClass = Class.forName("sun.misc.Signal");
            Object signal = signalClass.getConstructor(String.class).newInstance(signalName);
            signalClass.getMethod("raise", signalClass).invoke(null, signal);

            // raise() is asynchronous; a live process here means the handler was never invoked.
            Thread.sleep(3_000L);
            System.out.println("NO_HANDLER");
            System.out.flush();
            bridge.close();
            System.exit(4);
        } catch (ReflectiveOperationException e) {
            System.out.println("UNSUPPORTED");
            System.out.flush();
            bridge.close();
            System.exit(3);
        }
    }

    private SignalBridgeProbe() {
    }
}
