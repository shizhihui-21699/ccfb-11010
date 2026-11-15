//! Runtime configuration and detection thresholds.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Processes that legitimately mass-rewrite files into high-entropy form.
/// Matched against the lsof `command` basename. Extend via config file.
pub const DEFAULT_TRUSTED_PROCESSES: &[&str] = &[
    "tar",
    "gtar",
    "gzip",
    "gunzip",
    "bzip2",
    "bunzip2",
    "xz",
    "unxz",
    "zstd",
    "unzstd",
    "zip",
    "unzip",
    "7z",
    "7za",
    "rsync",
    "ditto",
    "ar",
    "restic",
    "borg",
    "borgbackup",
    "backupd",
    "tmutil",
    "rclone",
];

/// File-name fragments (case-insensitive) that mark a ransom note.
pub const DEFAULT_NOTE_NAME_HINTS: &[&str] = &[
    "readme",
    "decrypt",
    "recover",
    "ransom",
    "restore",
    "how_to",
    "locked",
    "read_me",
    "your_files",
];

/// Content markers inside a candidate note; name + one marker => critical.
pub const DEFAULT_NOTE_CONTENT_MARKERS: &[&str] = &[
    "your files have been encrypted",
    "all your files",
    "bitcoin",
    "btc address",
    "ransom",
    "decryption key",
    "decrypt your files",
    "pay the",
    "wallet",
    "aes-256",
    "rsa-2048",
    "do not attempt",
];

/// Extensions that real ransomware families commonly append.
pub const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    "locked",
    "encrypted",
    "enc",
    "crypto",
    "crypt",
    "cry",
    "locky",
    "ransom",
    "aes",
    "wart",
    "kraken",
    "cerber",
    "zepto",
    "ryk",
    "tesla",
    "ccc",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// Rolling analysis window in seconds.
    pub window_secs: i64,
    /// Files smaller than this are ignored (noise: temp files, lock files...).
    pub min_file_size: u64,
    /// Absolute bits/byte cutoff for high-entropy content.
    pub high_entropy: f64,
    /// Entropy jump versus the on-disk baseline for the same path.
    pub entropy_delta: f64,
    /// Minimum high-entropy rewrites inside the window before it can signal.
    pub entropy_event_count: usize,
    /// Minimum fraction of qualifying writes that must look high-entropy.
    pub entropy_event_ratio: f64,
    /// Minimum extension-changing renames inside the window.
    pub extension_event_count: usize,
    /// Minimum fraction of change events carrying an extension swap.
    pub extension_event_ratio: f64,
    /// Score at/above which an alert is emitted.
    pub score_warning: u32,
    /// Score at/above which the process is suspended (when auto-suspend on).
    pub score_critical: u32,
    /// Re-fire suppression per signal, seconds.
    pub cooldown_secs: i64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            window_secs: 60,
            min_file_size: 256,
            high_entropy: 7.4,
            entropy_delta: 1.5,
            entropy_event_count: 8,
            entropy_event_ratio: 0.6,
            extension_event_count: 6,
            extension_event_ratio: 0.4,
            score_warning: 60,
            score_critical: 80,
            cooldown_secs: 45,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    /// Directories to watch (CLI `--watch` is appended on top).
    pub watch_dirs: Vec<PathBuf>,
    /// Where incidents, canary manifests and logs live.
    pub state_dir: Option<PathBuf>,
    /// Basenames of known-good archiver / backup binaries.
    pub trusted_processes: Vec<String>,
    /// Extra file-name fragments treated as ransom-note name hints.
    pub note_name_hints: Vec<String>,
    /// Extra content markers for ransom-note confirmation.
    pub note_content_markers: Vec<String>,
    /// Canary file names created inside each watched directory.
    pub canary_names: Vec<String>,
    /// Extra canaries supplied by the user (absolute paths).
    pub extra_canaries: Vec<PathBuf>,
    pub thresholds: Thresholds,
}

impl Config {
    pub fn merged_defaults() -> Self {
        Config {
            trusted_processes: DEFAULT_TRUSTED_PROCESSES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            note_name_hints: DEFAULT_NOTE_NAME_HINTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            note_content_markers: DEFAULT_NOTE_CONTENT_MARKERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            canary_names: vec![
                "CANARY_README.txt".into(),
                "quarterly_report_2026.docx".into(),
                "vacation_plan.csv".into(),
                "client_contacts.xlsx".into(),
                "family_photos.jpg".into(),
            ],
            ..Config::default()
        }
    }

    pub fn load(path: &std::path::Path) -> anyhow_lite::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let mut cfg: Config = toml::from_str(&raw)?;
        if cfg.trusted_processes.is_empty() {
            cfg.trusted_processes = DEFAULT_TRUSTED_PROCESSES
                .iter()
                .map(|s| s.to_string())
                .collect();
        }
        if cfg.note_name_hints.is_empty() {
            cfg.note_name_hints = DEFAULT_NOTE_NAME_HINTS
                .iter()
                .map(|s| s.to_string())
                .collect();
        }
        if cfg.note_content_markers.is_empty() {
            cfg.note_content_markers = DEFAULT_NOTE_CONTENT_MARKERS
                .iter()
                .map(|s| s.to_string())
                .collect();
        }
        Ok(cfg)
    }
}

/// Tiny local error alias so the crate does not need an anyhow dependency.
pub mod anyhow_lite {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
}
