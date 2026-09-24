#pragma once

#include <string>
#include <vector>

// US(0x1f)-framed record helpers shared across the orchestrator. Every verdict
// record is `kind \x1f SEVERITY \x1f ...`, so severity is always field index 1.
// "__meta"/"__status" rows carry a non-severity token there, so they never match
// "CRITICAL". Extracted from dicore_orchestrate.cpp's anonymous namespace.

namespace dicore {

constexpr char kFS = '\x1f';

// True iff field[1] of a record is exactly "CRITICAL".
bool is_critical(const std::string& rec);

// Field [idx] (0-based) of a US-framed record, or "" if absent.
std::string field(const std::string& rec, int idx);

// Count CRITICAL records across a verdict, logging each kind for the dual-run.
int count_critical(const char* detector, const std::vector<std::string>& recs);

}  // namespace dicore
