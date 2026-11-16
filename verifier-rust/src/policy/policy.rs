//! Server-side policy — the false-positive tuning that lives OFF the device.

#[derive(Clone, Debug)]
pub struct Policy {
    pub block_severities: Vec<String>,
    pub allow: Vec<String>,
    pub block: Vec<String>,
    pub require_strong_box: bool,
    pub max_patch_age_days: i64,
    pub observe_unconfirmed_rwx: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            block_severities: vec!["CRITICAL".into()],
            allow: vec![],
            block: vec![],
            require_strong_box: false,
            max_patch_age_days: 365,
            observe_unconfirmed_rwx: false,
        }
    }
}

impl Policy {
    // The single blocking decision. Order is normative:
    //   1. allow-list wins over everything
    //   2. block-list wins over severity
    //   3. a CONFIRMED RWX hook pool always blocks
    //   4. opting into observe-unconfirmed-RWX downgrades a BARE RWX finding
    //   5. otherwise the severity table decides
    pub fn is_blocking(
        &self,
        id: Option<&str>,
        severity: Option<&str>,
        kind: Option<&str>,
        hook_stub_regions: Option<i64>,
    ) -> bool {
        if let Some(id) = id {
            if self.allow.iter().any(|a| a == id) {
                return false;
            }
            if self.block.iter().any(|b| b == id) {
                return true;
            }
        }
        if kind == Some("rwx_memory_mapping") {
            if (hook_stub_regions.unwrap_or(0)) > 0 {
                return true;
            }
            if self.observe_unconfirmed_rwx {
                return false;
            }
        }
        let severity = severity.unwrap_or("").to_uppercase();
        self.block_severities.iter().any(|s| *s == severity)
    }
}
