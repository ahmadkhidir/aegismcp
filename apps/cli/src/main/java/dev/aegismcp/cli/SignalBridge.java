package dev.aegismcp.cli;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

/**
 * Installs the process signal handlers that let the CLI forward {@code SIGINT} and {@code SIGTERM}
 * to the managed child and exit with {@link ExitCode#INTERRUPTED} or
 * {@link ExitCode#TERMINATED}.
 *
 * <p>The JDK signal API lives in a non-exported-to-{@code --release} package, so it is reached
 * reflectively: compiling against it directly would fail the pinned Java 21 release build. When
 * the platform has no such signal (Windows has no native {@code SIGTERM}), installation degrades to
 * the JVM shutdown hook that {@link StdioProxy} always registers, so the child is still reaped.
 *
 * <p>A bridge restores the handlers it replaced when closed, so a wrap that runs inside a
 * long-lived JVM (tests, tooling) leaves the process as it found it.
 *
 * <p>Anchors: FEAT-003, NFR-006.
 */
final class SignalBridge implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(SignalBridge.class);

    /** Receives the resolved signal after the platform reports it. */
    @FunctionalInterface
    interface Handler {
        void onSignal(ExitCode.Signal signal);
    }

    private record Registration(Object signal, Object previousHandler) {
    }

    private final Class<?> signalClass;
    private final Method handleMethod;
    private final List<Registration> registrations = new ArrayList<>();

    private SignalBridge(Class<?> signalClass, Method handleMethod) {
        this.signalClass = signalClass;
        this.handleMethod = handleMethod;
    }

    /**
     * Installs {@code INT} and {@code TERM} handlers. A handler that cannot be installed is left
     * alone; the caller's shutdown hook remains the safety net.
     */
    static SignalBridge install(Handler handler) {
        Class<?> signalClass;
        Method handleMethod;
        try {
            signalClass = Class.forName("sun.misc.Signal");
            Class<?> handlerClass = Class.forName("sun.misc.SignalHandler");
            handleMethod = signalClass.getMethod("handle", signalClass, handlerClass);
        } catch (ReflectiveOperationException | RuntimeException e) {
            logger.debug("JDK signal API unavailable; relying on the shutdown hook", e);
            return new SignalBridge(null, null);
        }

        SignalBridge bridge = new SignalBridge(signalClass, handleMethod);
        for (ExitCode.Signal signal : ExitCode.Signal.values()) {
            bridge.register(signal, handler);
        }
        return bridge;
    }

    private void register(ExitCode.Signal signal, Handler handler) {
        try {
            Object platformSignal = signalClass.getConstructor(String.class).newInstance(signal.name());
            Object previous = handleMethod.invoke(null, platformSignal, signalHandler(handler));
            registrations.add(new Registration(platformSignal, previous));
        } catch (ReflectiveOperationException | RuntimeException e) {
            logger.debug("Signal {} is not supported on this platform; relying on the shutdown hook",
                    signal.name(), e);
        }
    }

    private static Object signalHandler(Handler handler) {
        InvocationHandler invocationHandler = (proxy, method, args) -> {
            if ("handle".equals(method.getName()) && args != null && args.length == 1) {
                try {
                    Method getName = args[0].getClass().getMethod("getName");
                    handler.onSignal(ExitCode.Signal.fromName((String) getName.invoke(args[0])));
                } catch (ReflectiveOperationException | RuntimeException e) {
                    logger.warn("Unhandled signal; the child will be reaped by the shutdown hook", e);
                }
                return null;
            }
            return switch (method.getName()) {
                case "toString" -> "aegis-cli-signal-handler";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> args != null && args.length == 1 && proxy == args[0];
                default -> null;
            };
        };
        ClassLoader loader = SignalBridge.class.getClassLoader();
        try {
            Class<?> handlerClass = Class.forName("sun.misc.SignalHandler");
            return Proxy.newProxyInstance(loader, new Class<?>[]{handlerClass}, invocationHandler);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("sun.misc.SignalHandler disappeared", e);
        }
    }

    @Override
    public void close() {
        for (Registration registration : registrations) {
            try {
                handleMethod.invoke(null, registration.signal(), registration.previousHandler());
            } catch (ReflectiveOperationException | RuntimeException e) {
                logger.debug("Failed to restore the previous signal handler", e);
            }
        }
        registrations.clear();
    }
}
