package de.robv.android.xposed;

/**
 * Minimal compile-time stub of `XposedHelpers`. We only declare
 * the overloads we actually call from {@code MainHook}; the
 * runtime implementation supports many more.
 */
public final class XposedHelpers {
    private XposedHelpers() {}

    /**
     * Find a method by class name + method name + parameter
     * types and install [callback] as a hook. Last argument in
     * the varargs MUST be the {@link XC_MethodHook} callback;
     * everything before it is the method-signature spec. Each
     * spec entry is either a {@link Class}, a {@link String}
     * (fully-qualified class name; resolved via [classLoader]),
     * or a primitive descriptor.
     */
    public static XC_MethodHook.Unhook findAndHookMethod(
            String className,
            ClassLoader classLoader,
            String methodName,
            Object... parameterTypesAndCallback) {
        return null;
    }
}
