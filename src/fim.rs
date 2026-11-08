use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FimVerificationState {
    Baseline,
    Validating,
    VerifiedIntact,
    Tampered,
    Missing,
}

impl Default for FimVerificationState {
    fn default() -> Self {
        FimVerificationState::Baseline
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileBaseline {
    pub files: HashMap<String, String>, // Path -> SHA256
    #[serde(default)]
    pub state: FimVerificationState,
}

pub struct FimEngine;

impl FimEngine {
    pub fn hash_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 { break; }
            hasher.update(&buffer[..count]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn create_baseline(targets: &[PathBuf]) -> FileBaseline {
        let mut files = HashMap::new();
        for target in targets {
            if target.is_file() {
                if let Ok(hash) = Self::hash_file(target) {
                    files.insert(target.to_string_lossy().to_string(), hash);
                }
            }
        }
        FileBaseline {
            files,
            state: FimVerificationState::Baseline,
        }
    }

    pub fn verify_baseline(baseline: &FileBaseline) -> Vec<(String, String)> {
        let mut discrepancies = Vec::new(); // (path, reason)

        for (path_str, expected_hash) in &baseline.files {
            let path = Path::new(path_str);
            if !path.exists() {
                discrepancies.push((path_str.clone(), "File deleted or missing".to_string()));
                continue;
            }

            match Self::hash_file(path) {
                Ok(current_hash) => {
                    if &current_hash != expected_hash {
                        discrepancies.push((path_str.clone(), format!("Hash mismatch: expected {}..., found {}...", &expected_hash[..8], &current_hash[..8])));
                    }
                }
                Err(e) => {
                    discrepancies.push((path_str.clone(), format!("Read error: {}", e)));
                }
            }
        }

        discrepancies
    }
}
