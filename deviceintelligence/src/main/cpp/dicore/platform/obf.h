#pragma once

// Obfuscation-profile markers, kept only so call sites stay legible about intent
// (kill engine / attestation parser / orchestrator / emulator probe).
//
// Obfuscation is applied by our own out-of-tree LLVM pass plugin
// (tools/obfuscator/) GLOBALLY to every function when the build routes
// compiles through dicoreobf-launch.sh (`-Pdeviceintelligence.obfuscate=...`, see
// deviceintelligence/build.gradle.kts). It does not read per-function
// annotations, so these markers are NO-OPS — expanding them to nothing also
// keeps the old annotation strings out of the binary.
#define DI_OBF_MAX
#define DI_OBF_KILL
#define DI_OBF_ATTEST
#define DI_OBF_ORCH
#define DI_OBF_EMU
