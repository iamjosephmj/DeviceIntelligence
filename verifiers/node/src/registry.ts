import { readFileSync } from "node:fs";
import path from "node:path";

export interface SignalMeta {
  id: string; detector: string; kind: string;
  severity: string; title: string; description: string;
}

export class SignalRegistry {
  constructor(private byId: Record<string, SignalMeta>) {}
  get(id: string | null | undefined): SignalMeta | null {
    return id ? this.byId[id] ?? null : null;
  }
  get size(): number { return Object.keys(this.byId).length; }
  static fromJson(text: string): SignalRegistry {
    const root = JSON.parse(text);
    const byId: Record<string, SignalMeta> = {};
    for (const s of root.signals ?? []) {
      if (s.status === "retired") continue;
      byId[s.id] = { id: s.id, detector: s.detector ?? "?", kind: s.kind ?? "?",
                     severity: s.severity ?? "", title: s.title ?? "", description: s.description ?? "" };
    }
    return new SignalRegistry(byId);
  }
  static bundled(): SignalRegistry {
    const p = path.join(path.dirname(new URL(import.meta.url).pathname),
                        "../resources/signals-registry.json");
    return SignalRegistry.fromJson(readFileSync(p, "utf8"));
  }
}
