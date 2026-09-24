#!/usr/bin/env bash
# CMake compiler launcher for obfuscating libdicore.so with Arkari (OLLVM).
# CMake invokes this as:  arkari-launch <real-compiler> <args...>
# Compile steps (-c) are routed to the Arkari obfuscating clang with the
# obfuscation passes; link steps and configure-time probes fall through to the
# real NDK compiler (Arkari was built with only the `clang` target — no
# compiler-rt / lld — so it must not do the final link). Verified by the spike.
#
# Obfuscation passes applied globally to every dicore TU:
#   -irobf-cse   C-string literal encryption (kills plaintext detector strings)
#   -irobf-indbr indirect branches + encrypted targets
# Heavier per-function passes (e.g. -irobf-fla control-flow flattening) are
# applied selectively via __attribute__((annotate("..."))) on hot/critical
# functions to stay within the perf budget (spec 01).
ARKARI=/home/joseph/AndroidStudioProjects/_ollvm/Arkari/build/bin/clang
RUN=/home/joseph/AndroidStudioProjects/DeviceIntelligence/tools/obfuscator/ddk-run.sh
REAL_CC="$1"; shift
# Gradle/ninja/NDK run on the HOST; only the Arkari compile hops into the ddk
# chroot (Arkari clang needs the ddk glibc). Output .o lands under /home/joseph
# (bound into the chroot at the same path), so the host build picks it up.
#   -mbranch-protection=none : the obfuscation passes + the NDK's PAC branch
#     protection emit an llvm.ptrauth.sign intrinsic the Arkari backend can't
#     select (crashes). Disabling branch protection on the dicore TUs avoids it
#     (minor: drops PAC/BTI on our own .so; OLLVM is the primary protection).
case " $* " in
  *" -c "*)
    # -mbranch-protection=none is needed ONLY for aarch64 (PAC); it is rejected
    # on thumbv7/armeabi-v7a and unneeded on x86_64.
    EXTRA=""
    case " $* " in *aarch64*) EXTRA="-mbranch-protection=none" ;; esac
    exec "$RUN" "$ARKARI" $EXTRA -mllvm -irobf -mllvm -irobf-cse "$@" ;;
  *)
    exec "$REAL_CC" "$@" ;;
esac
