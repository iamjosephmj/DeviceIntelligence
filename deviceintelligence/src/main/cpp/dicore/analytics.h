#pragma once

// analytics.h — fire-and-forget event delivery to the configured
// analytics endpoint from native code.
//
// Analytics is part of the device-intelligence native runtime
// (libdicore). Consumers can opt out at build time via
//
//   deviceintelligence { disableAnalytics.set(true) }
//
// which makes the Gradle plugin inject a manifest <meta-data> tag that
// analytics::init() checks at startup.

#include <jni.h>

namespace dicore::analytics {

// Call once from JNI_OnLoad.
// Reads the opt-out manifest meta-data, derives the anonymous client_id,
// and (if enabled) starts the background drain thread. Safe to call even
// if ActivityThread.currentApplication() is not yet populated — the flag
// defaults to "enabled" in that edge case, which is the common path.
void init(JavaVM* vm, JNIEnv* env);

// Thread-safe, non-blocking. Enqueues event_name + a compact JSON params
// object string for async delivery to Firebase Measurement Protocol.
// No-ops if analytics was disabled, or if the ring buffer is full
// (silently dropped rather than blocking the calling thread).
//
// event_name  ASCII, no quotes (used both as a JSON string value and as
//              part of the run document's `events` map key).
// params_json a compact, well-formed JSON object. May be arbitrarily large
//              — the queue uses a heap-backed buffer per slot, so tens of KB
//              (e.g. a full telemetry_report) is fine.
void queue_event(const char* event_name, const char* params_json);

} // namespace dicore::analytics
