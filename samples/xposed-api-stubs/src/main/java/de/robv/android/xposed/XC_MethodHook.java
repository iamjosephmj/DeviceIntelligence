package de.robv.android.xposed;

import java.lang.reflect.Member;

/**
 * Minimal compile-time stub of `XC_MethodHook`. See note on
 * {@link IXposedHookLoadPackage} for why these are stubs only.
 *
 * Subclasses override {@link #beforeHookedMethod(MethodHookParam)}
 * and / or {@link #afterHookedMethod(MethodHookParam)}; the real
 * Xposed dispatcher calls them at the right time.
 */
public abstract class XC_MethodHook {
    public XC_MethodHook() {}
    public XC_MethodHook(int priority) {}

    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {}
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {}

    public static class MethodHookParam {
        public Member method;
        public Object thisObject;
        public Object[] args;
        public Object getResult() { return null; }
        public void setResult(Object result) {}
        public Throwable getThrowable() { return null; }
        public void setThrowable(Throwable throwable) {}
    }

    public static class Unhook {
        public void unhook() {}
    }
}
