#pragma once

// The typed verdict-record layer. Every verdict core emits US(0x1f)-framed
// record strings ("<kind> FS <SEVERITY> FS <detail...>"); before finding.h the
// interpretation of that framing — severity is field 1, "__"-prefixed kinds are
// on-device plumbing and never findings — lived as conventions re-derived at
// every consumer (is_critical, append, count_critical). It now lives in exactly
// one place: decode_record(). Severity is a type; a meta row can never be a
// critical finding no matter what its second field says.
//
// The framing itself is unchanged and stays the wire-adjacent format: nothing
// that consumes records via decode_record may re-parse fields by hand.
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace dicore {

inline constexpr char kFS = '\x1f';

enum class Severity : uint8_t { kUnknown, kLow, kMedium, kHigh, kCritical };

inline std::optional<Severity> severity_from_token(std::string_view t) {
    if (t == "CRITICAL") return Severity::kCritical;
    if (t == "HIGH") return Severity::kHigh;
    if (t == "MEDIUM") return Severity::kMedium;
    if (t == "LOW") return Severity::kLow;
    return std::nullopt;
}

inline std::string_view severity_name(Severity s) {
    switch (s) {
        case Severity::kLow: return "LOW";
        case Severity::kMedium: return "MEDIUM";
        case Severity::kHigh: return "HIGH";
        case Severity::kCritical: return "CRITICAL";
        case Severity::kUnknown: break;
    }
    return "";
}

struct Finding {
    std::string kind;            // field 0 ("__meta"/"__status" for plumbing rows)
    std::string severity_token;  // field 1 verbatim ("" when the row has no second field)
    Severity severity = Severity::kUnknown;
    std::string detail;          // raw text after field 1 (US separators preserved verbatim)
    bool meta = false;           // kind starts with "__": never a finding, never counted
};

inline bool is_critical(const Finding& f) {
    return !f.meta && f.severity == Severity::kCritical;
}

// THE single interpreter of the record framing. Returns nullopt only for an
// empty record; unknown severity tokens stay lossless (severity_token keeps the
// raw field, severity is kUnknown, never counted as critical).
inline std::optional<Finding> decode_record(std::string_view rec) {
    if (rec.empty()) return std::nullopt;
    Finding f;
    const size_t a = rec.find(kFS);
    if (a == std::string_view::npos) {
        f.kind.assign(rec);
        return f;
    }
    f.kind.assign(rec.substr(0, a));
    f.meta = f.kind.rfind("__", 0) == 0;
    const size_t b = rec.find(kFS, a + 1);
    if (b == std::string_view::npos) {
        f.severity_token.assign(rec.substr(a + 1));
    } else {
        f.severity_token.assign(rec.substr(a + 1, b - (a + 1)));
        f.detail.assign(rec.substr(b + 1));
    }
    if (auto s = severity_from_token(f.severity_token)) f.severity = *s;
    return f;
}

// --- producer side -------------------------------------------------------
// Verdict cores construct their records through make_finding() so a mistyped
// severity is a compile error, not an silently-uncountable string on the wire.
// encode_record() reproduces the legacy hand-assembled bytes exactly
// ("kind FS SEV FS field1 FS field2..."), so the wire format is pinned by the
// round-trip test, not by convention.

inline Finding make_finding(std::string kind, Severity sev,
                            std::vector<std::string> fields) {
    Finding f;
    f.kind = std::move(kind);
    f.severity = sev;
    f.severity_token = std::string(severity_name(sev));
    for (size_t i = 0; i < fields.size(); ++i) {
        if (i) f.detail += kFS;
        f.detail += std::move(fields[i]);
    }
    return f;
}

inline std::string encode_record(const Finding& f) {
    std::string out = f.kind;
    out += kFS;
    out += f.severity_token;
    if (!f.detail.empty()) { out += kFS; out += f.detail; }
    return out;
}

// Drop-in for the append_field chain style: records assembled field-by-field
// get their severity as a TYPE at the position-1 slot instead of a string
// literal (a mistyped "CRITCAL" would decode as kUnknown and never count).
inline std::string append_severity(std::string r, Severity s) {
    r += kFS;
    r += severity_name(s);
    return r;
}

}  // namespace dicore
