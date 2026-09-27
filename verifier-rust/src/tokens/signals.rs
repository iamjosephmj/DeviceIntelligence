//! Signal resolution: turn the device's opaque findings into registry-backed
//! ResolvedSignals, and correlate structural + behavioral hook evidence.

use serde_json::Value;

use crate::model::{DeviceInfo, ResolvedSignal};
use crate::policy::{Policy, Registry};

// The detail tokens a backend may enrich with (space-separated k=v pairs).
const ATTR_KEYS: [&str; 18] = [
    "path",
    "module_id",
    "needed",
    "links_hook_lib",
    "hooked_symbol",
    "hooked_by",
    "target",
    "ondisk_confirmed",
    "on_disk_prologue",
    "trampoline_class",
    "object",
    "base",
    "seals",
    "key",
    "get",
    "area",
    "hook_stub_regions",
    "region_count",
];

pub fn parse_attrs(detail: &str) -> std::collections::HashMap<String, String> {
    let mut attrs = std::collections::HashMap::new();
    for tok in detail.split(' ') {
        if let Some(eq) = tok.find('=') {
            if eq == 0 {
                continue;
            }
            let (k, v) = (tok[..eq].to_string(), tok[eq + 1..].to_string());
            if ATTR_KEYS.contains(&k.as_str()) {
                attrs.insert(k, v);
            }
        }
    }
    attrs
}

pub fn resolve(doc: &Value, registry: &Registry, policy: &Policy) -> Vec<ResolvedSignal> {
    doc["signals"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|s| resolve_one(s, registry, policy))
                .collect()
        })
        .unwrap_or_default()
}

fn resolve_one(s: &Value, registry: &Registry, policy: &Policy) -> ResolvedSignal {
    let raw_id = s["id"].as_str().unwrap_or("INTEL_UNKNOWN");
    // Legacy SIG_-prefixed ids normalize before lookup.
    let id = match raw_id.strip_prefix("SIG_") {
        Some(suffix) => format!("INTEL_{suffix}"),
        None => raw_id.to_string(),
    };
    let meta = registry.get(Some(&id));
    let severity = s["severity"]
        .as_str()
        .map(|v| v.to_string())
        .or_else(|| meta.as_ref().map(|m| m.severity.clone()))
        .unwrap_or_default();
    let detail = s["detail"].as_str().unwrap_or("").to_string();
    let attrs = parse_attrs(&detail);
    let stubs = attrs
        .get("hook_stub_regions")
        .and_then(|v| v.parse::<i64>().ok());
    let kind = meta
        .as_ref()
        .map(|m| m.kind.clone())
        .unwrap_or_else(|| "?".into());
    let blocking = policy.is_blocking(Some(&id), Some(&severity), Some(&kind), stubs);
    ResolvedSignal {
        id,
        detector: meta
            .as_ref()
            .map(|m| m.detector.clone())
            .unwrap_or_else(|| "?".into()),
        kind,
        title: meta.as_ref().map(|m| m.title.clone()).unwrap_or_default(),
        severity,
        detail,
        blocking,
        attributes: serde_json::to_value(&attrs).unwrap_or(Value::Null),
    }
}

pub fn device(doc: &Value) -> Option<DeviceInfo> {
    let d = doc["device"].as_object()?;
    Some(DeviceInfo {
        api: d["api"].as_i64(),
        abi: d["abi"].as_str().map(|s| s.to_string()),
        model: d["model"].as_str().map(|s| s.to_string()),
    })
}

// Definitive hook = the SAME symbol seen both structurally (inline hook /
// stub) and behaviorally (syscall divergence). Sorted for determinism.
pub fn definitive_hooks(signals: &[ResolvedSignal]) -> Vec<String> {
    let mut structural: Vec<String> = signals
        .iter()
        .filter(|s| s.kind == "libc_inline_hook" || s.kind == "libc_inline_stub")
        .filter_map(|s| s.attr("hooked_symbol").map(|v| v.to_string()))
        .collect();
    let behavioral: Vec<String> = signals
        .iter()
        .filter(|s| s.kind == "syscall_divergence")
        .filter_map(|s| s.attr("hooked_symbol").map(|v| v.to_string()))
        .collect();
    structural.retain(|sym| behavioral.contains(sym));
    structural.sort();
    structural.dedup();
    structural
}
