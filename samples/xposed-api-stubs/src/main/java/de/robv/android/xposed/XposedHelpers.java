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

    /**
     * Resolves a class via the supplied {@link ClassLoader}.
     * Equivalent to {@code Class.forName(className, true, classLoader)};
     * Xposed's runtime variant additionally caches lookups.
     */
    public static Class<?> findClass(String className, ClassLoader classLoader) {
        return null;
    }

    /**
     * Reads a static reference-typed field. Used for grabbing the
     * `INSTANCE` field of a Kotlin `object` from the host process.
     */
    public static Object getStaticObjectField(Class<?> clazz, String fieldName) {
        return null;
    }

    /**
     * Invokes a method on the supplied receiver, picking the
     * matching overload by argument count and runtime types.
     * The runtime variant is loose about boxing/unboxing and
     * subtype matching, which is what makes it usable from a
     * module that has no compile-time type information about
     * the host.
     */
    public static Object callMethod(Object obj, String methodName, Object... args) {
        return null;
    }
}
