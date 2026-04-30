package de.robv.android.xposed;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Minimal compile-time stub of the Xposed API entry-point
 * interface. The real implementation is supplied by the LSPosed
 * framework at runtime — the dex compiled from this module never
 * embeds these classes; they are looked up from the host process's
 * classpath after `xposed_init` is read.
 *
 * Reference: https://api.xposed.info/reference/de/robv/android/xposed/IXposedHookLoadPackage.html
 */
public interface IXposedHookLoadPackage {
    void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable;
}
