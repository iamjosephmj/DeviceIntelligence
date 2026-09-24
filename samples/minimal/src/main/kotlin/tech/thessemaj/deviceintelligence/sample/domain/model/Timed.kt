package tech.thessemaj.deviceintelligence.sample.domain.model

/**
 * A value and how long the SDK call that produced it took.
 *
 * Every phase of the flow is timed and both numbers are shown, because the
 * interesting property of this SDK is WHERE the cost lands: `initialize` is
 * local and cheap, `setSession` pays for one TEE/StrongBox keygen, and every
 * scan afterwards is TEE-free.
 */
data class Timed<T>(val value: T, val millis: Long)
