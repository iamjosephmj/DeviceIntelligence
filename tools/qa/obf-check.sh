#!/usr/bin/env bash
# Artifact-level check of the Arkari toolchain. Compiles tools/qa/obf/fixture.cpp
# through the pass plugin with plain clang-18 — mirroring arkari-launch.sh's
# -fpass-plugin injection — then:
#   1. strings leg: every dicoreobf registration marker (pointer-table
#      names/sigs, char-array tables embedded by value, the FindClass-style
#      class path, the digest-array bytes) must be ABSENT from `strings` of the
#      object, at -O0 and -O2 (the debug/release compile shapes AGP produces);
#   2. short-name leg: the <4-byte method name is invisible to `strings`, so it
#      is checked with a byte-exact grep instead;
#   3. roundtrip leg: the fixture linked with tools/qa/obf/main.cpp runs the
#      registrar and verifies the pass-emitted load-time decryptor restored
#      every string exactly (what RegisterNatives would receive) — with
#      SEED-ONLY keys (no bind tool ran: un-tooled artifacts must stay
#      self-consistent);
#   4. bind leg (task A1): tools/native/dicore-bind-strkeys.py re-encrypts the
#      linked roundtrip binary in place against its own exec-page digest; the
#      SAME binary must still roundtrip — the ctor recomputed the digest from
#      its live image and derived every key. Idempotency: a second run binds
#      nothing new.
#   5. tamper leg: tools/qa/obf/tamper_check.cpp verifies, file-based, that
#      flipping the exec first page turns every digest-bound string to garbage
#      while the NEVER_BIND digest array (INTEL_0059 stand-in) still decrypts
#      seed-only — patched .text breaks all strings, but not INTEL_0059's
#      baseline.
#   6. zip-embedded load leg (fix round 1): tools/qa/obf/zip_load_check.cpp
#      packs the BOUND artifact as a real STORED zip entry, mmaps it from the
#      entry's page-aligned data offset (the kernel shows file offset = that
#      offset, not 0) and proves the resolver derives the base + digest from
#      the marker's own mapping in BOTH shapes (whole-entry and linker-split
#      apk!/lib-style absolute offsets) and the live-derived key roundtrips
#      every bound string.
#   7. RELR refuse-guard (W1): the binder must refuse relative-reloc-packed
#      binaries loudly (packed addends are unreadable from RELA/REL — binding
#      would silently key wrong slots), never skip them silently.
#   8. prose sweep leg (F1): tools/qa/artifact-sweep.sh runs its cleartext
#      pattern/prose sweep + offline-decrypted-strtab machinery against the
#      linked roundtrip binary (fixture object if the roundtrip build already
#      failed) and must exit clean — the fixture carries no registry prose or
#      anti-analysis tokens by construction, so this regression-proofs the
#      sweep machinery itself; the REAL-artifact gate runs in release
#      acceptance.
# Exit 77 (skip) when LLVM-18 / the pass plugin is unavailable so CI without
# the toolchain doesn't fail; any real regression exits 1.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBF="$(cd "$HERE/../obfuscator" && pwd)"
FIX="$HERE/obf"
CPP="$(cd "$HERE/../../deviceintelligence/src/main/cpp" && pwd)"
BIND="$HERE/../native/dicore-bind-strkeys.py"
SYS_LLVM_BIN="/usr/lib/llvm-18/bin"

if command -v clang++-18 >/dev/null 2>&1; then
  CXX=clang++-18
elif [ -x "$SYS_LLVM_BIN/clang++" ]; then
  CXX="$SYS_LLVM_BIN/clang++"
else
  echo "SKIP  obf-check: clang-18 not found (LLVM-18 toolchain absent)"
  exit 77
fi

# Always rebuild the pass before the legs (incremental ninja is cheap when
# nothing changed): running against a STALE plugin silently validated an old
# pass — a false-CI green. A missing toolchain (no cmake/ninja/llvm-18-dev)
# is still a skip, not a failure.
if ! bash "$OBF/build.sh" >/dev/null 2>&1; then
  echo "SKIP  obf-check: pass plugin not buildable (llvm-18-dev / cmake / ninja absent?)"
  exit 77
fi
PLUGIN="$OBF/build/libdicoreobf.so"

TMP="$(mktemp -d)"
SHIM="$(mktemp -d)"; mkdir -p "$SHIM/android"
cat > "$SHIM/android/log.h" <<'SH'
#pragma once
#include <cstdarg>
enum { ANDROID_LOG_VERBOSE, ANDROID_LOG_DEBUG, ANDROID_LOG_INFO, ANDROID_LOG_WARN, ANDROID_LOG_ERROR, ANDROID_LOG_FATAL };
static inline int __android_log_print(int,const char*,const char*,...){return 0;}
static inline int __android_log_write(int,const char*,const char*){return 0;}
SH
trap 'rm -rf "$TMP" "$SHIM"' EXIT
# Deterministic ciphertext: the byte-exact short-name grep must not depend on
# the ambient environment (release builds override this per-build on purpose).
export DI_OBF_SEED=0x525156454E32
rc=0
fail() { echo "FAIL  obf-check: $*"; rc=1; }

for OPT in O0 O2; do
  if ! "$CXX" -std=c++17 -$OPT -c "$FIX/fixture.cpp" -fpass-plugin="$PLUGIN" \
        -o "$TMP/fixture-$OPT.o"; then
    fail "fixture compile (-$OPT) through the pass"
    continue
  fi
  if strings -a "$TMP/fixture-$OPT.o" | grep -q DICOREOBFMARK; then
    fail "plaintext DICOREOBFMARK markers in strings of fixture-$OPT.o:"
    strings -a "$TMP/fixture-$OPT.o" | grep DICOREOBFMARK | head -5 | sed 's/^/    /'
  fi
  # <4-byte standalone name "q7\0": `strings` cannot see it (min run 4).
  if LC_ALL=C grep -qaP 'q7\x00' "$TMP/fixture-$OPT.o"; then
    fail "plaintext short name 'q7' in fixture-$OPT.o"
  fi
  # digest-array stand-in bytes (task A1 exemption must still ENCRYPT them)
  if LC_ALL=C grep -qa 'DICOREOBFMARK_DIGESTBASE' "$TMP/fixture-$OPT.o"; then
    fail "plaintext digest-array bytes in fixture-$OPT.o"
  fi
done

# Roundtrip: fixture + the runtime that plays the JNI side + the helper TU the
# pass-emitted ctor calls (own_image: /proc/self/maps resolution + raw SHA-256
# over the exec first page — the live half of every bound key).
OWNIMG="$CPP/dicore/platform/own_image.cpp $CPP/dicore/crypto/raw_sha256.cpp \
$CPP/dicore/platform/svc_io.cpp $CPP/dicore/platform/syscalls.cpp"
if "$CXX" -std=c++17 -O2 "$FIX/fixture.cpp" "$FIX/main.cpp" $OWNIMG \
     -I"$SHIM" -I"$CPP" -fpass-plugin="$PLUGIN" -o "$TMP/roundtrip" 2>"$TMP/roundtrip.build"; then
  "$TMP/roundtrip" || fail "runtime roundtrip (decryptor did not restore plaintext)"
else
  fail "roundtrip build"; cat "$TMP/roundtrip.build"
fi

# ---- bind leg (task A1): digest-bound keys on the linked artifact ----------
if command -v python3 >/dev/null 2>&1; then
  if out="$(python3 "$BIND" "$TMP/roundtrip" 2>&1)"; then
    echo "$out" | sed 's/^/      /'
    if ! echo "$out" | grep -qE 'bound ([1-9][0-9]*) '; then
      fail "strkey bind tool bound nothing (strtab missing or empty?)"
    fi
    "$TMP/roundtrip" || fail "bound roundtrip (live digest derivation != build-time binding)"
    # idempotent: the second run must bind zero new ranges
    out2="$(python3 "$BIND" "$TMP/roundtrip" 2>&1)" || fail "strkey bind tool (second run)"
    echo "$out2" | grep -qE 'bound 0 ' || fail "strkey bind tool not idempotent: $out2"
  else
    fail "strkey bind tool: $out"
  fi

  # ---- tamper leg: patched exec page breaks bound strings, not the baseline
  if "$CXX" -std=c++17 -O2 "$FIX/tamper_check.cpp" \
       "$CPP/dicore/platform/own_image.cpp" "$CPP/dicore/crypto/raw_sha256.cpp" \
       "$CPP/dicore/platform/svc_io.cpp" "$CPP/dicore/platform/syscalls.cpp" \
       -I"$SHIM" -I"$CPP" -o "$TMP/tamper" 2>"$TMP/tamper.build"; then
    "$TMP/tamper" "$TMP/roundtrip" || fail "tamper leg (binding not digest-bound / baseline not independent)"
  else
    fail "tamper_check build"; cat "$TMP/tamper.build"
  fi

  # ---- zip-embedded load leg: apk!/lib-style offsets must resolve ---------
  if "$CXX" -std=c++17 -O2 "$FIX/zip_load_check.cpp" \
       "$CPP/dicore/platform/own_image.cpp" "$CPP/dicore/crypto/raw_sha256.cpp" \
       "$CPP/dicore/platform/svc_io.cpp" "$CPP/dicore/platform/syscalls.cpp" \
       -I"$SHIM" -I"$CPP" -o "$TMP/zipload" 2>"$TMP/zipload.build"; then
    "$TMP/zipload" "$TMP/roundtrip" || fail "zip-embedded load leg (base derivation / roundtrip)"
  else
    fail "zip_load_check build"; cat "$TMP/zipload.build"
  fi

  # ---- RELR refuse-guard (W1): packed relative relocs must fail loudly ----
  if printf 'extern "C" int f(void){return 1;}\nextern "C" void* const g = (void*)&f;\n' \
       | "$CXX" -shared -fPIC -Wl,-z,pack-relative-relocs -x c++ - -o "$TMP/relr.so" 2>/dev/null \
     && readelf -d "$TMP/relr.so" 2>/dev/null | grep -qi relr; then
    if out_relr="$(python3 "$BIND" "$TMP/relr.so" 2>&1)"; then
      fail "strkey bind tool accepted an RELR-packed binary: $out_relr"
    elif ! echo "$out_relr" | grep -qi relr; then
      fail "strkey bind tool refused RELR without saying so: $out_relr"
    else
      echo "      RELR refuse-guard: $(echo "$out_relr" | head -1)"
    fi
  else
    echo "      note: RELR refuse-guard not probed (host linker lacks -z pack-relative-relocs)"
  fi
else
  fail "python3 unavailable: bind + tamper + zip legs cannot run"
fi

# ---- leg 8: prose sweep machinery (F1 regression gate) ----------------------
# The fixture contains no registry prose by construction; this leg proves the
# sweep tool itself runs end-to-end against a linked artifact and exits clean.
# The REAL-artifact gate runs in release acceptance (see the 2026-09-10 plan).
# Target: the linked roundtrip binary when it was built; else the fixture
# object — a missing roundtrip means the roundtrip-build leg already recorded
# the failure above, so no artifact is not a new failure mode here either; if
# no artifact survived the earlier builds, skip without re-reporting them.
if [ -x "$HERE/artifact-sweep.sh" ]; then
  sweep_target=""
  if [ -f "$TMP/roundtrip" ]; then
    sweep_target="$TMP/roundtrip"
  elif [ -f "$TMP/fixture-O2.o" ]; then
    sweep_target="$TMP/fixture-O2.o"
  fi
  if [ -z "$sweep_target" ]; then
    echo "      note: prose sweep leg skipped (no artifact from earlier build failures)"
  elif out_sweep="$(bash "$HERE/artifact-sweep.sh" "$sweep_target" 2>&1)"; then
    echo "$out_sweep" | sed 's/^/      /'
  else
    sweep_rc=$?
    echo "$out_sweep" | sed 's/^/      /'
    if [ "$sweep_rc" -eq 1 ]; then
      fail "prose sweep leg (sweep tool reported leaks on a clean fixture)"
    else
      fail "prose sweep leg (sweep tooling error rc=$sweep_rc; gate fails closed)"
    fi
  fi
else
  fail "artifact-sweep.sh missing or not executable"
fi

if [ $rc -eq 0 ]; then
  echo "PASS  obf-check (registration strings encrypted + roundtrip + digest-bound keys + zip-embedded load + prose sweep)"
fi
exit $rc
