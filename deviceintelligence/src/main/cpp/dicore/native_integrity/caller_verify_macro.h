#pragma once

// `DI_VERIFY_CALLER()` — drop this as the first line of any JNI
// entry point in `native_integrity_jni.cpp` (and, when G7.5
// ships, every other entry point in libdicore). It records a
// `native_caller_out_of_range` violation if the immediate caller
// (i.e. `__builtin_return_address(0)`) doesn't resolve to
// `libart.so`'s RX range.
//
// The macro intentionally has zero side-effects beyond the
// recording: it never throws, never blocks, and never returns
// anything. The check is fail-soft — if the ring buffer is full
// the oldest record is dropped (the runtime side already caps
// per-scan reads to 64 records, so the alternative — blocking
// the JNI call — would do nothing useful).
//
// Header carries no implementation: just the inline macro and
// an extern declaration of the recorder. This keeps the macro's
// expansion at the call site to a single statement, which
// matters because the macro is meant to be the FIRST thing in
// every JNI function and we don't want to expand into anything
// the function body has to step around.

#include "caller_verify.h"

#define DI_VERIFY_CALLER() \
    ::dicore::native_integrity::record_if_foreign(__func__, __builtin_return_address(0))
