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
    std::string kind;            // fields[0]
    std::string severity_token;  // fields[1] verbatim ("" when the row has no second field)
    Severity severity = Severity::kUnknown;
    std::string detail;          // raw text after field 1 (US separators preserved verbatim)
    bool meta = false;           // kind starts with "__": never a finding, never counted
    std::vector<std::string> fields;  // the whole record split on US; fields[0] == kind

    std::string_view field(size_t i) const {
        return i < fields.size() ? std::string_view(fields[i]) : std::string_view();
    }
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
    size_t pos = 0;
    for (;;) {
        const size_t fs = rec.find(kFS, pos);
        f.fields.emplace_back(rec.substr(pos, fs == std::string_view::npos
                                                ? std::string_view::npos : fs - pos));
        if (fs == std::string_view::npos) break;
        pos = fs + 1;
    }
    f.kind = f.fields[0];
    f.meta = f.kind.rfind("__", 0) == 0;
    if (f.fields.size() > 1) f.severity_token = f.fields[1];
    for (size_t i = 2; i < f.fields.size(); ++i) {
        if (i > 2) f.detail += kFS;
        f.detail += f.fields[i];
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
                            std::vector<std::string> det_fields) {
    Finding f;
    f.kind = kind;
    f.severity = sev;
    f.severity_token = std::string(severity_name(sev));
    f.fields.push_back(f.kind);
    f.fields.push_back(f.severity_token);
    for (auto& d : det_fields) {
        if (!f.detail.empty()) f.detail += kFS;
        f.detail += d;
        f.fields.push_back(std::move(d));
    }
    return f;
}

// Plumbing rows ("__meta"/"__status") carry arbitrary payload fields with no
// severity semantics — the payload's first element lands at fields[1] (the
// position-1 slot holds the row's status/sub-token, not a severity). Meta rows
// are never findings: is_critical() is false for them by construction.
inline Finding make_meta(std::string kind, std::vector<std::string> payload_fields) {
    Finding f;
    f.kind = kind;
    f.meta = true;
    f.fields.push_back(std::move(kind));
    for (auto& p : payload_fields) f.fields.push_back(std::move(p));
    f.severity_token = f.fields.size() > 1 ? f.fields[1] : std::string();
    for (size_t i = 2; i < f.fields.size(); ++i) {
        if (i > 2) f.detail += kFS;
        f.detail += f.fields[i];
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
