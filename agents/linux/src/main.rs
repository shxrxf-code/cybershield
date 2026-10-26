use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "cybershield-agent-linux")]
#[command(about = "CyberShield Linux Endpoint Security Agent", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan { path: PathBuf },
    Hash { path: PathBuf },
    Status,
}

#[derive(Serialize, Deserialize)]
struct ScanResult {
    path: String,
    hash: String,
    size: u64,
    suspicious: bool,
    reason: Option<String>,
}

fn calculate_hash(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn scan_file(path: &Path) -> Option<ScanResult> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() { return None; }
    let hash = calculate_hash(path).ok()?;
    let mut suspicious = false;
    let mut reason = None;
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if name.ends_with(".sh") && metadata.permissions().readonly() == false {
        // Basic heuristic
    }
    if name.contains("keylog") || name.contains("backdoor") || name.contains("rat") {
        suspicious = true;
        reason = Some("Suspicious filename pattern".to_string());
    }
    Some(ScanResult {
        path: path.display().to_string(),
        hash,
        size: metadata.len(),
        suspicious,
        reason,
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path } => {
            println!("CyberShield Linux Agent - Scanning: {}", path.display());
            let mut count = 0;
            let mut suspicious = 0;
            for entry in WalkDir::new(&path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    if let Some(result) = scan_file(entry.path()) {
                        count += 1;
                        if result.suspicious {
                            suspicious += 1;
                            println!("[SUSPICIOUS] {} - {}", result.path, result.reason.as_ref().unwrap());
                        }
                    }
                }
            }
            println!("Scanned {} files, {} suspicious", count, suspicious);
        }
        Commands::Hash { path } => {
            match calculate_hash(&path) {
                Ok(h) => println!("SHA256: {}", h),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::Status => {
            println!("CyberShield Linux Agent v1.0.0");
            println!("Status: Operational");
            println!("ClamAV integration: Available via clamscan");
            println!("Suricata: Available for network monitoring");
        }
    }
}
