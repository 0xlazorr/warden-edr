use crate::alert::{EdrAlert, Severity};
use crate::process::ProcessScanner;
use crate::fim::{FimEngine, FileBaseline};

pub struct WardenEngine;

impl WardenEngine {
    pub fn audit_system_processes() -> Vec<EdrAlert> {
        let mut alerts = Vec::new();
        let anomalies = ProcessScanner::scan_all_processes();

        for proc in anomalies {
            alerts.push(EdrAlert::new(
                "EDR-MEM-001",
                "Unbacked RWX Memory Mapping (Possible Shellcode/Injection)",
                Severity::Critical,
                Some(proc.pid),
                Some(proc.name.clone()),
                &format!("Process '{}' (PID {}) contains {} unbacked RWX memory page(s). Command line: {}", proc.name, proc.pid, proc.suspicious_mappings.len(), proc.cmdline),
            ));
        }

        alerts
    }

    pub fn audit_fim_integrity(baseline: &FileBaseline) -> Vec<EdrAlert> {
        let mut alerts = Vec::new();
        let diffs = FimEngine::verify_baseline(baseline);

        for (path, reason) in diffs {
            alerts.push(EdrAlert::new(
                "EDR-FIM-002",
                "System File Integrity Violation",
                Severity::Critical,
                None,
                None,
                &format!("File '{}' failed baseline verification: {}", path, reason),
            ));
        }

        alerts
    }
}
