#pragma once

// device-intelligence-lab: detection-only. There is no enforcement, so the
// orchestrator trail is always available (observe build). ORCH_LOG maps to the
// normal info log; findings are surfaced to the caller via the verdict string
// returned by the single JNI entry point.
#include "dicore/platform/log.h"
#define ORCH_LOG(...) RLOGI(__VA_ARGS__)
