package io.ssemaj.deviceintelligence.internal

/**
 * Marker annotation: this function is a [StackGuard]-checkpoint
 * entry point. Every public DeviceIntelligence API surface that
 * calls `StackGuard.verify()` carries this annotation so the
 * intent is explicit at the call site (and so a future
 * compiler-plugin / lint check could, in theory, enforce that
 * any `@Critical fun` actually contains a `StackGuard.verify()`
 * call).
 *
 * Today it has no behaviour beyond documentation. We keep it
 * around because the design doc names it as a recognised entry
 * point in the rollout — collapsing it would lose the explicit
 * contract.
 */
@Retention(AnnotationRetention.SOURCE)
@Target(
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY_GETTER,
    AnnotationTarget.PROPERTY_SETTER,
)
internal annotation class Critical
