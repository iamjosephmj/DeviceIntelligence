package de.robv.android.xposed.callbacks;

/**
 * Minimal compile-time stub. Only the inner
 * {@link LoadPackageParam} is referenced from our hook.
 */
public final class XC_LoadPackage {
    private XC_LoadPackage() {}

    public static class LoadPackageParam {
        public String packageName;
        public String processName;
        public ClassLoader classLoader;
        // Note: the real Xposed API also exposes `appInfo`
        // (android.content.pm.ApplicationInfo), but our hook
        // doesn't read it, and omitting it lets these stubs
        // build as a plain JVM library (no Android SDK needed).
        public boolean isFirstApplication;
    }
}
