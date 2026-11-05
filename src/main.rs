use clap::{Parser, Subcommand};
use std::path::PathBuf;
use warden_edr::{FimEngine, WardenEngine};

#[derive(Parser)]
#[command(author = "Lazarus Ebi", version = "0.1.0", about = "Warden Linux Endpoint Detection & Response (EDR)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ScanProcesses,
    FimCreate {
        #[arg(short, long)]
        path: PathBuf,
        #[arg(short, long, default_value = "baseline.json")]
        output: PathBuf,
    },
    FimVerify {
        #[arg(short, long, default_value = "baseline.json")]
        baseline: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ScanProcesses => {
            println!("🔍 Warden EDR: Scanning /proc memory mappings for injections...");
            let alerts = WardenEngine::audit_system_processes();
            if alerts.is_empty() {
                println!("✅ Zero unbacked RWX memory injection indicators found.");
            } else {
                for a in alerts {
                    println!("🚨 [{}] {} (PID: {:?})", a.rule_id, a.title, a.pid);
                    println!("   ↳ {}", a.details);
                }
            }
        }
        Commands::FimCreate { path, output } => {
            println!("📁 Generating SHA-256 cryptographic baseline for {:?}...", path);
            let baseline = FimEngine::create_baseline(&[path]);
            let json = serde_json::to_string_pretty(&baseline)?;
            std::fs::write(&output, json)?;
            println!("✅ Baseline recorded to {:?}", output);
        }
        Commands::FimVerify { baseline: b_path } => {
            println!("🛡️ Verifying system file integrity against {:?}...", b_path);
            let content = std::fs::read_to_string(&b_path)?;
            let baseline = serde_json::from_str(&content)?;
            let alerts = WardenEngine::audit_fim_integrity(&baseline);
            if alerts.is_empty() {
                println!("✅ All baseline files verified cryptographically intact.");
            } else {
                for a in alerts {
                    println!("🚨 [{}] {}", a.rule_id, a.title);
                    println!("   ↳ {}", a.details);
                }
            }
        }
    }
    Ok(())
}
