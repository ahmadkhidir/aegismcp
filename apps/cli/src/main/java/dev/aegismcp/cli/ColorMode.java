package dev.aegismcp.cli;

import picocli.CommandLine;

/**
 * Color policy for terminal output, selected with {@code --color=auto|always|never}.
 * {@link #AUTO} emits ANSI escapes only when the destination is an interactive terminal, so piped and
 * redirected output stays plain. Anchors: FEAT-003, NFR-006.
 */
public enum ColorMode {

    /** Colorize only when the destination is an interactive terminal. */
    AUTO,

    /** Always colorize, unless {@code NO_COLOR} or a dumb terminal forces plain text. */
    ALWAYS,

    /** Never colorize. */
    NEVER;

    /**
     * Parses a color mode case-insensitively.
     *
     * @param value {@code auto}, {@code always}, or {@code never}
     * @return the matching mode
     * @throws IllegalArgumentException when the value is not one of the three modes
     */
    public static ColorMode parse(String value) {
        if (value != null) {
            String normalized = value.trim();
            for (ColorMode mode : values()) {
                if (mode.name().equalsIgnoreCase(normalized)) {
                    return mode;
                }
            }
        }
        throw new IllegalArgumentException(
                "Invalid color mode '" + value + "': expected auto, always, or never.");
    }

    /** Picocli converter that accepts the flag values case-insensitively. */
    public static final class Converter implements CommandLine.ITypeConverter<ColorMode> {

        @Override
        public ColorMode convert(String value) {
            return parse(value);
        }
    }
}
