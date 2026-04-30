package de.robv.android.xposed;

/**
 * Minimal compile-time stub. {@link #log(String)} dispatches to
 * the real Xposed framework which writes to its own log file
 * (visible in LSPosed Manager's "Logs" tab). We use it so the
 * verifier can confirm that the hook actually fired even before
 * the device-side detector reports back.
 */
public final class XposedBridge {
    private XposedBridge() {}
    public static void log(String message) {}
    public static void log(Throwable t) {}
}
