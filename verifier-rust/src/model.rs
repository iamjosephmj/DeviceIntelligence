//! The verdict and evidence types shared by every verifier flow.

use serde_json::Value;

pub mod decision {
    pub const TRUSTWORTHY: &str = "TRUSTWORTHY";
    pub const COMPROMISED: &str = "COMPROMISED";
    pub const REJECT: &str = "REJECT";
}

pub mod check_kind {
    pub const AUTH: &str = "AUTH";
    pub const INTEGRITY: &str = "INTEGRITY";
}

pub mod assurance {
    pub const SOFTWARE: &str = "SOFTWARE";
    pub const TEE: &str = "TEE";
    pub const STRONGBOX: &str = "STRONGBOX";
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
    pub kind: String,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct DeviceInfo {
    pub api: Option<i64>,
    pub abi: Option<String>,
    pub model: Option<String>,
}

/// One resolved signal: the opaque INTEL_ code plus registry metadata and the
/// policy verdict. Only `id`, `severity` and `detail` come from the device.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ResolvedSignal {
    pub id: String,
    pub detector: String,
    pub kind: String,
    pub title: String,
    pub severity: String,
    pub detail: String,
    pub blocking: bool,
    pub attributes: Value,
}

impl ResolvedSignal {
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(|v| v.as_str())
    }
}

/// The layered verdict. REJECT: authenticity failed. COMPROMISED: genuine,
/// but the device (or a signal) is compromised. TRUSTWORTHY: all layers clear.
#[derive(Clone, Debug, serde::Serialize)]
pub struct VerificationResult {
    pub decision: String,
    pub authentic: bool,
    pub device_integrity_ok: bool,
    pub checks: Vec<Check>,
    pub schema_version: Option<i64>,
    pub point: Option<String>,
    pub ts: Option<i64>,
    pub nonce: Option<String>,
    pub device: Option<DeviceInfo>,
    pub signals: Vec<ResolvedSignal>,
}

pub fn as_i64(v: &Value) -> Option<i64> {
    v.as_i64()
}

pub fn as_str(v: &Value) -> Option<&str> {
    v.as_str()
}
