#pragma once

#include <string>
#include <vector>

#include "dicore/orchestrator/finding.h"

// US(0x1f)-framed record helpers shared across the orchestrator. The framing
// conventions (severity is field 1; "__meta"/"__status" rows are plumbing, not
// findings) are interpreted ONLY by dicore/orchestrator/finding.h's
// decode_record() — the helpers below delegate to it.

namespace dicore {

// (kFS and the Finding/Severity types come from finding.h.)

// True iff the record decodes to a non-meta CRITICAL finding.
bool is_critical(const std::string& rec);

// Field [idx] (0-based) of a US-framed record, or "" if absent.
std::string field(const std::string& rec, int idx);

// Count CRITICAL records across a verdict, logging each kind for the dual-run.
int count_critical(const char* detector, const std::vector<std::string>& recs);

}  // namespace dicore
