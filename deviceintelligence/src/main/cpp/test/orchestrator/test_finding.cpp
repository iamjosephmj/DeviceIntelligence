// deviceintelligence/src/main/cpp/test/orchestrator/test_finding.cpp
// Host test for the typed Finding layer (finding.h): the US(0x1f) record framing
// is interpreted in exactly ONE place, so the "severity is field 1" and
// "__-prefixed rows are plumbing, never findings" conventions are checked here
// instead of being re-derived at every consumer. Pure string logic — no JVM,
// no device. Compile with the test/stub include dir for <android/log.h>.
#include "dicore/orchestrator/finding.h"
#include "dicore/orchestrator/record_util.h"

#include <cstdio>

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

using namespace dicore;

int main() {
    const std::string FS(1, kFS);
    // NOTE: a core's record starts at the KIND — the detector name is prefixed
    // later by orchestrate.cpp's append(), outside the Finding layer.

    // --- a full CRITICAL finding decodes with kind/severity/detail ---
    auto f1 = decode_record("apk_signature_mismatch" + FS + "CRITICAL" + FS + "sig=abc");
    CHECK(f1.has_value());
    CHECK(f1->kind == "apk_signature_mismatch");
    CHECK(f1->severity == Severity::kCritical);
    CHECK(f1->severity_token == "CRITICAL");
    CHECK(f1->detail == "sig=abc");
    CHECK(f1->meta == false);
    CHECK(is_critical(*f1) == true);

    // --- HIGH decodes and is not critical ---
    auto f2 = decode_record("su_binary" + FS + "HIGH" + FS + "path=/system/bin/su");
    CHECK(f2.has_value() && f2->severity == Severity::kHigh && !is_critical(*f2));

    // --- severity is parsed by name, not by position luck: MEDIUM too ---
    auto f3 = decode_record("k" + FS + "MEDIUM");
    CHECK(f3.has_value() && f3->severity == Severity::kMedium && !is_critical(*f3));

    // --- __-prefixed rows are plumbing: never findings, never critical ---
    // (this is the convention append()/count_critical relied on via r[0]=='_')
    auto m1 = decode_record("__meta" + FS + "__status" + FS + "ok" + FS + "hash=deadbeef");
    CHECK(m1.has_value() && m1->meta == true && !is_critical(*m1));
    auto m2 = decode_record("__weird" + FS + "CRITICAL" + FS + "trap");
    CHECK(m2.has_value() && m2->meta == true && !is_critical(*m2));

    // --- unknown/absent severity tokens stay lossless but never count ---
    auto u1 = decode_record("watching" + FS + "OBSERVE" + FS + "x=1");
    CHECK(u1.has_value() && u1->severity == Severity::kUnknown &&
          u1->severity_token == "OBSERVE" && !is_critical(*u1));
    auto u2 = decode_record("bare");
    CHECK(u2.has_value() && u2->severity_token.empty() &&
          u2->severity == Severity::kUnknown && !is_critical(*u2));
    auto u3 = decode_record("k" + FS + "CRITICAL");
    CHECK(u3.has_value() && u3->severity == Severity::kCritical && is_critical(*u3));

    // --- malformed input is rejected, not half-decoded ---
    CHECK(!decode_record("").has_value());

    // --- detail with embedded US separators is preserved verbatim ---
    auto f4 = decode_record("k" + FS + "HIGH" + FS + "a=1" + FS + "b=2");
    CHECK(f4.has_value() && f4->detail == "a=1" + FS + "b=2");

    // --- record_util's string API now delegates to the typed layer ---
    CHECK(is_critical("k" + FS + "CRITICAL" + FS + "d"));
    CHECK(!is_critical("k" + FS + "HIGH" + FS + "d"));
    CHECK(!is_critical("__meta" + FS + "__status" + FS + "ok"));
    CHECK(field("a" + FS + "b" + FS + "c" + FS + "d" + FS + "e5f", 4) == "e5f");
    CHECK(field("solo", 0) == "solo");
    CHECK(field("solo", 1).empty());

    // --- count_critical counts only real critical findings ---
    CHECK(count_critical("t", {"k1" + FS + "CRITICAL",
                               "k2" + FS + "HIGH",
                               "__m" + FS + "CRITICAL",
                               "k3" + FS + "CRITICAL" + FS + "x"}) == 2);

    // --- producer side: make_finding + encode_record are byte-exact ---
    // (the legacy producers assembled "kind FS SEV FS f1 FS f2" by hand; the
    // typed path must reproduce those bytes exactly or the wire changes.)
    const std::string legacy_su =
        "su_binary_present" + FS + "HIGH" + FS +
        "su binary present in PATH" + FS + "artifact=path=/system/bin/su";
    const Finding su = make_finding("su_binary_present", Severity::kHigh,
        {"su binary present in PATH", "artifact=path=/system/bin/su"});
    CHECK(su.kind == "su_binary_present");
    CHECK(su.severity == Severity::kHigh);
    CHECK(encode_record(su) == legacy_su);
    CHECK(encode_record(su) == decode_record(legacy_su)->kind + FS +
                               decode_record(legacy_su)->severity_token + FS +
                               decode_record(legacy_su)->detail);

    // critical single-detail field
    const std::string legacy_tls =
        "tls_trust_store_tampered" + FS + "CRITICAL" + FS +
        "tmpfs over conscrypt" + FS + "artifact=mountpoint=/apex/x";
    CHECK(encode_record(make_finding("tls_trust_store_tampered", Severity::kCritical,
        {"tmpfs over conscrypt", "artifact=mountpoint=/apex/x"})) == legacy_tls);

    // a producer that emits only kind+severity (no detail fields)
    CHECK(encode_record(make_finding("bare_kind", Severity::kMedium, {})) ==
          "bare_kind" + FS + "MEDIUM");

    // decoded-then-re-encoded round trip is byte-identical (lossless edge:
    // no trailing empty fields — producers never emit those)
    for (const std::string& rec : {legacy_su, legacy_tls, "k" + FS + "HIGH" + FS + "one"}) {
        auto d = decode_record(rec);
        CHECK(d.has_value() && encode_record(*d) == rec);
    }

    // severity_name round-trips every severity the producers use
    for (auto s : {Severity::kLow, Severity::kMedium, Severity::kHigh, Severity::kCritical})
        CHECK(severity_from_token(severity_name(s)).value() == s);

    // --- decode populates typed fields (index 0 = kind, 1 = severity token) ---
    auto ff = decode_record("k" + FS + "CRITICAL" + FS + "f2" + FS + "f3" + FS + "f4");
    CHECK(ff.has_value() && ff->fields.size() == 5);
    CHECK(ff->fields[0] == "k" && ff->fields[1] == "CRITICAL" &&
          ff->fields[2] == "f2" && ff->fields[3] == "f3" && ff->fields[4] == "f4");
    CHECK(ff->field(4) == "f4" && ff->field(9).empty());

    // --- make_meta: plumbing rows keep arbitrary field payloads losslessly ---
    const Finding mm = make_meta("__meta", {"3", "raven", "1.0", "hash123", "a,b"});
    CHECK(mm.meta == true && mm.severity == Severity::kUnknown);
    CHECK(mm.fields.size() == 6 && mm.fields[4] == "hash123");  // [0]=kind + 5 payload
    const std::string enc = encode_record(mm);
    CHECK(enc == "__meta" + FS + "3" + FS + "raven" + FS + "1.0" + FS + "hash123" + FS + "a,b");
    auto dm = decode_record(enc);
    CHECK(dm.has_value() && dm->meta && dm->fields.size() == 6 && dm->fields[4] == "hash123");
    CHECK(!is_critical(*dm));  // a meta row is never a finding

    if (fails == 0) printf("test_finding: all checks passed\n");
    return fails == 0 ? 0 : 1;
}
