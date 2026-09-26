import { SignalRegistry } from "./registry.js";
import { Policy, isBlocking } from "./policy.js";
import { ResolvedSignal } from "./models.js";

const ATTR_KEYS = new Set(["path", "module_id", "needed", "links_hook_lib", "hooked_symbol",
  "hooked_by", "target", "ondisk_confirmed", "on_disk_prologue", "trampoline_class",
  "object", "base", "seals", "key", "get", "area", "hook_stub_regions", "region_count"]);

export function parseAttrs(detail: string): Record<string, string> {
  const m: Record<string, string> = {};
  if (!detail) return m;
  for (const tok of detail.split(" ")) {
    const eq = tok.indexOf("=");
    if (eq > 0) { const k = tok.slice(0, eq); if (ATTR_KEYS.has(k)) m[k] = tok.slice(eq + 1); }
  }
  return m;
}

export function resolve(doc: any, registry: SignalRegistry, policy: Policy): ResolvedSignal[] {
  const raw = doc.signals ?? [];
  return raw.map((s: any) => {
    const rawId = s.id ?? "INTEL_UNKNOWN";
    const id = rawId.startsWith("SIG_") ? "INTEL_" + rawId.slice(4) : rawId;
    const meta = registry.get(id);
    const severity = s.severity ?? meta?.severity ?? "";
    const detail = s.detail ?? "";
    const attrs = parseAttrs(detail);
    const stubs = attrs["hook_stub_regions"] ? parseInt(attrs["hook_stub_regions"]) : undefined;
    const blocking = isBlocking(policy, id, severity, meta?.kind, stubs);
    const out: ResolvedSignal = { id, detector: meta?.detector ?? "?", kind: meta?.kind ?? "?",
      title: meta?.title ?? "", severity, detail, blocking, attributes: attrs };
    if (attrs["module_id"]) out.moduleId = attrs["module_id"];
    if (attrs["path"]) out.path = attrs["path"];
    if (attrs["needed"]) out.linkedLibraries = attrs["needed"].split(",").map((x: string) => x.trim()).filter(Boolean);
    if (attrs["links_hook_lib"]) out.linksHookLib = attrs["links_hook_lib"];
    if (attrs["hooked_symbol"]) out.hookedSymbol = attrs["hooked_symbol"];
    if (attrs["hooked_by"]) out.hookedBy = attrs["hooked_by"];
    if (stubs !== undefined) out.hookStubRegions = stubs;
    return out;
  });
}

export function device(doc: any): any | null {
  const d = doc.device;
  if (!d) return null;
  return { api: typeof d.api === "number" ? d.api : null, abi: d.abi ?? null, model: d.model ?? null };
}
