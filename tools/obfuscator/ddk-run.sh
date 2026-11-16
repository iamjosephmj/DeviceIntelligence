#!/usr/bin/env bash
# Run a command inside the ddk-min-root GCC-14 rootfs (rootless, via bwrap).
# Binds host /home/joseph (project + Android SDK/NDK) and /snap (Android Studio
# JBR) so both the LLVM build and the Android Gradle build can run inside the
# same consistent glibc environment.
DDK=/home/joseph/ddk-min-root
exec bwrap \
  --bind "$DDK" / \
  --bind /home/joseph /home/joseph \
  --bind /tmp /tmp \
  --ro-bind /snap /snap \
  --proc /proc --dev /dev --ro-bind /sys /sys \
  --setenv PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/joseph/Android/Sdk/cmake/3.22.1/bin" \
  --setenv HOME /home/joseph \
  --setenv LANG C \
  "$@"
