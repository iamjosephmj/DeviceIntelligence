// cloner_probe.h — F13 app-cloner / multi-app-launcher detection.
//
// All three readers below operate on /proc/self/* via the raw
// syscalls in dicore::sys, so a Java- or libc-side hook installed
// by the cloner (Waxmoon, Parallel Space, Dual Apps, VirtualXposed,
// Frida scripts, …) cannot intercept or rewrite the values we read.
//
// None of the three "decides" anything on its own; each just hands
// kernel-truth state back to the Kotlin facade, which compares
// against the corresponding Java-level value (Context.packageName,
// Process.myUid()) and emits a Finding (kind="uid_mismatch")
// when they disagree. That comparison is where the actual signal
// comes from: a cloner can lie about either side, but it can't keep
// both sides in sync without root.

#ifndef DICORE_CLONER_PROBE_H_
#define DICORE_CLONER_PROBE_H_

#include <cstddef>

namespace dicore::cloner {

// Reads /proc/self/maps and writes the path of the first mapping
// that ends in "/base.apk" into [out]. Returns the number of bytes
// written (excluding the NUL terminator), 0 if no such mapping was
// found, or -1 on read error.
//
// Diagnostic only — see [find_foreign_apk_in_maps] for the actual
// cloner-detection signal.
int read_apk_path_from_maps(char* out, size_t out_size);

// Walks /proc/self/maps for ALL "*.apk" mappings and returns the
// first one whose path does NOT contain [my_package] as a
// `/`-or-`-`-bounded component.
//
// This is the strongest signal against multi-app launchers
// (Waxmoon, Parallel Space, Dual Apps, …): even when the launcher
// dlopens our legitimate APK alongside its own, its OWN base.apk
// MUST also be mmapped in the process address space (that's where
// the launcher's host code runs from), and that mapping carries
// the launcher's package name. A real install only ever has its
// own apk(s) mapped.
//
// Returns byte count of the foreign path written to [out], 0 if
// every apk mapping is "ours", or -1 on read error.
int find_foreign_apk_in_maps(const char* my_package,
                             char* out, size_t out_size);

// Reads /proc/self/mountinfo and looks for *suspicious* mounts that
// touch [package_name]. A mount is suspicious if it satisfies any of:
//   - mount-point ends with "/<package_name>" AND fstype is "tmpfs"
//     (real Android never tmpfs-mounts an app's data dir; cloners
//     using fs-virtualisation routinely do)
//   - mount-point ends with "/<package_name>" AND the source path
//     (mountinfo column 4) contains a different package-shaped
//     string (e.g. "/com.parallel.intl/")
//
// On a hit, writes a "fstype=...|source=...|mount=..." dump into
// [out] and returns the byte count. Returns 0 if no suspicious
// mount was found. Returns -1 on read error.
int find_suspicious_mount(const char* package_name,
                          char* out, size_t out_size);

// Walks /proc/self/mountinfo and collects the package-name
// component out of every mount-point that looks like an app data
// dir, i.e. matches one of:
//   /data/data/<pkg>
//   /data/user/<n>/<pkg>
//   /data/user_de/<n>/<pkg>
//   /data/misc/profiles/cur/<n>/<pkg>
//   /data/misc/profiles/ref/<pkg>
//
// Writes a "|"-separated, deduplicated list of package names into
// [out]. Returns byte count, 0 if no such mount-points exist (rare
// — happens if the kernel exposes neither bind-mounts nor profile
// mounts), or -1 on read error.
//
// The Kotlin facade then asserts [our package] appears in this set;
// if it doesn't, we're in someone else's mount namespace, which
// only happens inside a multi-app launcher.
int list_data_dir_owners(char* out, size_t out_size);

// Reads /proc/self/status, parses the "Uid:\treal\teff\tsaved\tfs"
// line, and returns the kernel-reported real UID. Returns -1 on
// read or parse failure (caller treats that as "no signal").
int read_kernel_uid_from_status();

// Walks /proc/self/mountinfo and collects unique filesystem type names
// (e.g. "ext4", "overlay", "tmpfs", "fuse"). Writes a comma-separated
// list into [out]. Returns byte count written, -1 on read error.
// If out_count is non-null, stores the total number of mount entries seen.
// No paths or package names are ever written to [out].
int collect_mount_fstypes(char* out, size_t out_size, int* out_count);

}  // namespace dicore::cloner

#endif  // DICORE_CLONER_PROBE_H_
