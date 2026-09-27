//! The signal taxonomy: opaque INTEL_ codes resolved to their meaning. The
//! device never ships detector/kind — only the backend holds the table.

use serde_json::Value;

#[derive(Clone, Debug)]
pub struct SignalMeta {
    pub id: String,
    pub detector: String,
    pub kind: String,
    pub severity: String,
    pub title: String,
}

#[derive(Clone, Debug, Default)]
pub struct Registry {
    by_id: std::collections::HashMap<String, SignalMeta>,
}

impl Registry {
    pub fn from_json(text: &str) -> Result<Registry, String> {
        let root: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let mut by_id = std::collections::HashMap::new();
        if let Some(signals) = root["signals"].as_array() {
            for row in signals {
                if row["status"] == "retired" {
                    continue;
                }
                let id = row["id"].as_str().unwrap_or_default().to_string();
                by_id.insert(
                    id.clone(),
                    SignalMeta {
                        detector: row["detector"].as_str().unwrap_or("?").to_string(),
                        kind: row["kind"].as_str().unwrap_or("?").to_string(),
                        severity: row["severity"].as_str().unwrap_or("").to_string(),
                        title: row["title"].as_str().unwrap_or("").to_string(),
                        id,
                    },
                );
            }
        }
        Ok(Registry { by_id })
    }

    pub fn bundled() -> Result<Registry, String> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/signals-registry.json"
        );
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("bundled registry unreadable: {e}"))?;
        Registry::from_json(&text)
    }

    // Nil-safe: unknown codes, null — null back.
    pub fn get(&self, id: Option<&str>) -> Option<&SignalMeta> {
        id.and_then(|id| self.by_id.get(id))
    }

    pub fn size(&self) -> usize {
        self.by_id.len()
    }
}
