use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrAlert {
    pub timestamp: u64,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub details: String,
}

impl EdrAlert {
    pub fn new(rule_id: &str, title: &str, severity: Severity, pid: Option<u32>, process_name: Option<String>, details: &str) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            timestamp: ts,
            rule_id: rule_id.to_string(),
            title: title.to_string(),
            severity,
            pid,
            process_name,
            details: details.to_string(),
        }
    }
}
