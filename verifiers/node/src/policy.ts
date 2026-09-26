export interface Policy {
  blockSeverities: Set<string>;
  allow: Set<string>;
  block: Set<string>;
  requireStrongBox: boolean;
  maxPatchAgeDays: number;
  observeUnconfirmedRwx: boolean;
}

export function defaultPolicy(): Policy {
  return { blockSeverities: new Set(["CRITICAL"]), allow: new Set(), block: new Set(),
           requireStrongBox: false, maxPatchAgeDays: 365, observeUnconfirmedRwx: false };
}

export function isBlocking(p: Policy, id: string | null, severity: string | null,
                           kind?: string, hookStubRegions?: number): boolean {
  if (id && p.allow.has(id)) return false;
  if (id && p.block.has(id)) return true;
  if (kind === "rwx_memory_mapping" && (hookStubRegions ?? 0) > 0) return true;
  if (p.observeUnconfirmedRwx && kind === "rwx_memory_mapping" && (hookStubRegions ?? 0) === 0) return false;
  return (severity ?? "").toUpperCase() === "CRITICAL" ||
         [...p.blockSeverities].includes((severity ?? "").toUpperCase());
}
