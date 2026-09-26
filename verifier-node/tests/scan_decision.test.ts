import { test } from "node:test";
import assert from "node:assert/strict";
import { Decision, ResolvedSignal, ScanResult, scanDecision, blockingSignals } from "../src/model.js";

const signal = (sid: string, blocking: boolean): ResolvedSignal =>
  ({ id: sid, detector: "t", kind: "t", title: "", severity: "HIGH",
     detail: "", blocking, attributes: {} });

const result = (ok: boolean, deviceIntegrityOk = true, signals: ResolvedSignal[] = []): ScanResult =>
  ({ ok, bootstrap: false, deviceIntegrityOk, session: null, checks: [], signals,
     reason: ok ? null : "forgery", fingerprint: null });

test("a proven forgery is rejected even if everything else looks clean", () => {
  assert.equal(scanDecision(result(false)), Decision.REJECT);
});

test("an untrustworthy device is compromised not rejected", () => {
  assert.equal(scanDecision(result(true, false)), Decision.COMPROMISED);
});

test("a blocking signal is compromised", () => {
  assert.equal(scanDecision(result(true, true, [signal("INTEL_0025", true)])),
               Decision.COMPROMISED);
});

test("a non blocking signal stays trustworthy", () => {
  assert.equal(scanDecision(result(true, true, [signal("INTEL_0056", false)])),
               Decision.TRUSTWORTHY);
});

test("clean scan is trustworthy", () => {
  assert.equal(scanDecision(result(true)), Decision.TRUSTWORTHY);
});

test("blocking signals carries only the blocking findings", () => {
  const r = result(true, true, [signal("INTEL_0056", false), signal("INTEL_0025", true),
                                signal("INTEL_0044", true)]);
  assert.deepEqual(blockingSignals(r).map((s: ResolvedSignal) => s.id),
                   ["INTEL_0025", "INTEL_0044"]);
});

test("forgery wins over everything", () => {
  const r = result(false, false, [signal("INTEL_0025", true)]);
  assert.equal(scanDecision(r), Decision.REJECT);
});
