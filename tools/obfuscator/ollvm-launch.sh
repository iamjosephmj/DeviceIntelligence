#!/usr/bin/env bash
# CMake compiler launcher: compile steps go to the obfuscating clang,
# everything else falls through to the NDK compiler.
OLLVM=/home/joseph/AndroidStudioProjects/_ollvm/ollvm17/build/bin/clang
REAL_CC="$1"; shift
case " $* " in
  *" -c "*)
    # the digest probe stays plain
    case " $* " in
      *text_digest_probe.cpp*) exec "$REAL_CC" "$@" ;;
    esac
    DI_OBF_SEED=0x4449434f52452e544558542e53454544 exec "$OLLVM" -mllvm -sobf "$@" ;;
  *)
    exec "$REAL_CC" "$@" ;;
esac
