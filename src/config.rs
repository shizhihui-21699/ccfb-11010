//! Configuration: defaults, TOML loading, CLI overrides.
//!
//! Every threshold is a field here so an operator can tune per site without
//! rebuilding, and so tests can drive the detector with tight windows.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct Config {
    pub watch: WatchConfig,
    pub entropy: EntropyConfig,
    pub detect: DetectConfig,
    pub decoy: DecoyConfig,
    pub response: ResponseConfig,
    pub trust: TrustConfig,
    pub output: OutputConfig,
}


// ---------------------------------------------------------------------------
// watch
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WatchConfig {
    /// Directories to protect. `~` is expanded.
    pub roots: Vec<PathBuf>,
    /// Path prefixes never inspected (backup repositories, VM images, caches).
    pub exclude_paths: Vec<PathBuf>,
    /// File-name globs ignored inside the roots (`*.tmp`, `~$*`, ...).
    pub exclude_globs: Vec<String>,
    /// Follow directory symlinks while walking. Keep off unless needed: a
    /// symlink loop would otherwise re-walk forever.
    pub follow_symlinks: bool,
    /// Build a pre-existing-content baseline at start so that "this document
    /// used to be text and is now opaque" can be recognised.
    pub scan_on_start: bool,
    /// Upper bound on files touched by the start-up scan.
    pub max_scan_files: usize,
    /// Files larger than this are sampled (head/middle/tail) rather than fully
    /// read; exceeding it does not mean the file is skipped.
    pub max_sample_bytes: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            exclude_paths: vec![
                "~/Library/Caches".into(),
                "/private/var/folders".into(),
                "/System".into(),
            ],
            exclude_globs: vec![
                "*.tmp".into(),
                "*.temp".into(),
                "*.swp".into(),
                "*.swo".into(),
                "*.lock".into(),
                "*.part".into(),
                "*.crdownload".into(),
                "*.download".into(),
                "*.partial".into(),
                "*~".into(),
                ".DS_Store".into(),
                "~$*".into(),
                ".git".into(),
                "*/.git".into(),
            ],
            follow_symlinks: false,
            scan_on_start: true,
            max_scan_files: 200_000,
            max_sample_bytes: 40 * 1024 * 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// entropy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EntropyConfig {
    /// Bytes sampled per file (head + middle + tail when larger).
    pub sample_bytes: usize,
    /// Minimum zero-order entropy before a sample may be called `Opaque`.
    /// AES/ChaCha output over ≥1 KiB lands at 7.9–8.0; the 7.85 gate rejects
    /// text even in dense scripts and CJK encodings (≤6.2).
    pub high_entropy_h0: f64,
    /// Entropy at or above which a sample is "high entropy" even if it also
    /// looks structured (e.g. a container header we failed to recognise).
    pub high_entropy_floor: f64,
    /// Maximum chi-square z-score for `Opaque`. Uniform random ≈ 0 ± a few;
    /// base64/hex stay in the thousands, so this rejects "encoded" text.
    pub uniform_chi2_z_max: f64,
    /// A byte-distribution must hit this many distinct values to be ciphertext.
    pub min_distinct_for_opaque: usize,
    /// Printable-ASCII ratio for text classification.
    pub text_printable_ratio: f64,
    /// Text is never allowed above this H0 (rejects binary that is mostly
    /// printable).
    pub text_max_h0: f64,
    /// Regular files smaller than this are not sampled at all.
    pub min_file_bytes: u64,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            sample_bytes: 64 * 1024,
            high_entropy_h0: 7.85,
            high_entropy_floor: 7.0,
            uniform_chi2_z_max: 12.0,
            min_distinct_for_opaque: 170,
            text_printable_ratio: 0.90,
            text_max_h0: 6.5,
            min_file_bytes: 16,
        }
    }
}

// ---------------------------------------------------------------------------
// detect
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectConfig {
    /// Sliding window over which signals accumulate.
    pub window_secs: u64,
    /// Score at which an incident is raised.
    pub min_score: f64,
    /// Minimum number of distinct files implicated before a content-based
    /// incident can fire. One file being encrypted is not an outbreak.
    pub min_files: usize,
    /// Distinct modified files within `bulk_window_secs` that count as bulk
    /// activity on their own.
    pub bulk_modify_files: usize,
    pub bulk_window_secs: u64,
    /// Distinct renames within `bulk_window_secs` that count as extension churn.
    pub bulk_rename_files: usize,
    /// Files smaller than this are ignored for entropy signalling (they are
    /// still tracked for rename/removal signals).
    pub min_entropy_bytes: usize,
    /// How long a pending rename may wait for its counterpart.
    pub rename_pair_ms: u64,
    /// Per-signal weights. Tuned so no single benign signal can reach
    /// `min_score` (a lone encrypted file scores 5, a lone note 6).
    ///
    /// The two burst weights are counted **once per window**, not per file: a
    /// burst says "something swept many files", which a backup and a `git
    /// checkout` also do, so it may only nudge the score.
    pub weight_opaque_rewrite: f64,
    pub weight_opaque_new_doc: f64,
    /// A document extension stacked under an unknown extension
    /// (`report.docx.locked`) — the canonical ransomware rename pattern.
    pub weight_stacked_ext: f64,
    pub weight_suspicious_rename: f64,
    pub weight_ransom_note: f64,
    pub weight_bulk_rename: f64,
    pub weight_bulk_modify: f64,
    /// Decoys bypass the score entirely.
    pub decoy_immediate: bool,
    /// Do not raise incidents while this many seconds remain before the
    /// start-up scan finishes (avoids a flood of "new file" signals).
    pub warmup_secs: u64,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            window_secs: 30,
            min_score: 8.0,
            min_files: 3,
            bulk_modify_files: 20,
            bulk_window_secs: 10,
            bulk_rename_files: 8,
            min_entropy_bytes: 1024,
            rename_pair_ms: 2000,
            weight_opaque_rewrite: 5.0,
            weight_opaque_new_doc: 3.0,
            weight_stacked_ext: 6.0,
            weight_suspicious_rename: 4.0,
            weight_ransom_note: 6.0,
            weight_bulk_rename: 3.0,
            weight_bulk_modify: 2.0,
            decoy_immediate: true,
            warmup_secs: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// decoy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DecoyConfig {
    pub enabled: bool,
    /// Plant into each root when true. When false, only `paths` are planted.
    pub plant_in_roots: bool,
    /// Sub-directory under each root, relative. Empty string = root itself.
    pub subdir: String,
    pub count: usize,
    /// Explicit paths (already existing) to treat as decoys.
    pub paths: Vec<PathBuf>,
    /// Poll interval for open-file detection. FSEvents does not report reads,
    /// so an open-for-read by an unknown process is only visible via fd scan.
    pub poll_ms: u64,
    /// Interval (ms) of the background open-fd sweep used for attribution. FSEvents
    /// does not report which process wrote a path, so this is how suspects are
    /// found; too slow and a quick encryptor slips between sweeps.
    pub holder_sweep_ms: u64,
    /// Where the decoy manifest lives (kept outside the watched roots so a
    /// rewrite of the directory cannot silently re-baseline decoys).
    pub manifest_dir: PathBuf,
    /// Alert on somebody opening a decoy read-only. Indexers/backups are
    /// allow-listed.
    pub alert_on_read: bool,
    /// Alert when a decoy disappears.
    pub alert_on_remove: bool,
    pub names: Vec<String>,
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            plant_in_roots: true,
            subdir: String::new(),
            count: 6,
            paths: Vec::new(),
            poll_ms: 500,
            holder_sweep_ms: 250,
            manifest_dir: PathBuf::from("~/.ransomwatch/decoys"),
            alert_on_read: true,
            alert_on_remove: true,
            names: vec![
                "Q3-budget-2026.xlsx".into(),
                "客户合同-2026-终稿.docx".into(),
                "payroll-november.xlsx".into(),
                "董事会会议纪要.docx".into(),
                "project-atlas-pricing.xlsx".into(),
                "supplier-list-2026.csv".into(),
                "merger-due-diligence.pdf".into(),
                "员工花名册.xlsx".into(),
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// response
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResponseMode {
    /// Only log and write an incident record.
    Alert,
    /// Record the scene, then SIGSTOP the suspect process tree.
    Suspend,
    /// Nothing but the incident record.
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseConfig {
    pub mode: ResponseMode,
    /// Also suspend descendants of the suspect.
    pub suspend_children: bool,
    /// Never suspend these processes even when they look suspicious
    /// (interactive shells, terminals) unless a decoy was touched.
    pub never_suspend: Vec<String>,
    /// Copy this many of the implicated files into the incident directory.
    pub copy_evidence_files: usize,
    /// Cap on bytes copied per evidence file.
    pub evidence_max_bytes: u64,
    /// Total evidence copy budget.
    pub evidence_total_bytes: u64,
    /// Incident records and evidence live here.
    pub incident_dir: PathBuf,
    /// Optional shell command executed on every incident, after the record is
    /// written. `$RANSOMWATCH_INCIDENT` and `$RANSOMWATCH_SEVERITY` are set.
    pub on_alert_command: Option<String>,
    /// Minimum seconds between two incidents raised by content signals, so a
    /// long-running encryptor does not produce hundreds of records.
    pub cooldown_secs: u64,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            mode: ResponseMode::Suspend,
            suspend_children: true,
            never_suspend: vec![
                "Terminal".into(),
                "iTerm2".into(),
                "Warp".into(),
                "bash".into(),
                "zsh".into(),
                "sh".into(),
                "loginwindow".into(),
                "WindowServer".into(),
                "launchd".into(),
                "kernel_task".into(),
            ],
            copy_evidence_files: 16,
            evidence_max_bytes: 16 * 1024 * 1024,
            evidence_total_bytes: 256 * 1024 * 1024,
            incident_dir: PathBuf::from("~/.ransomwatch/incidents"),
            on_alert_command: None,
            cooldown_secs: 60,
        }
    }
}

// ---------------------------------------------------------------------------
// trust
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustConfig {
    /// Process basenames that are exempt from *suspension* and whose write
    /// activity is suppressed from content scoring. These are the tools that
    /// legitimately produce compressed, archived or copied files.
    pub tools: Vec<String>,
    /// Extra names: treated as trusted only when the written extension is one
    /// of the crypto formats below (so `gpg -c x.docx` is quiet, but an
    /// unknown binary calling itself `gpg` still is not trusted by name alone).
    pub crypto_tools: Vec<String>,
    pub crypto_exts: Vec<String>,
    /// Trust Apple platform-signed binaries (/usr/bin, /bin) that are not
    /// interpreters. Shells are deliberately excluded.
    pub trust_apple_signed: bool,
    /// Never trust these even when Apple-signed.
    pub interpreters: Vec<String>,
    /// Use `codesign` to inspect binaries. Cache per path.
    pub use_codesign: bool,
    /// Suppress signals from processes whose executable lives in these dirs
    /// (backup agents installed under /Applications).
    pub trusted_exe_prefixes: Vec<PathBuf>,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            tools: vec![
                "tar".into(),
                "bsdtar".into(),
                "gtar".into(),
                "gzip".into(),
                "gunzip".into(),
                "bzip2".into(),
                "bunzip2".into(),
                "xz".into(),
                "unxz".into(),
                "zstd".into(),
                "lz4".into(),
                "7z".into(),
                "7za".into(),
                "7zz".into(),
                "zip".into(),
                "unzip".into(),
                "rar".into(),
                "unrar".into(),
                "ditto".into(),
                "cp".into(),
                "mv".into(),
                "rsync".into(),
                "dsync".into(),
                "pax".into(),
                "cpio".into(),
                "tmutil".into(),
                "backupd".into(),
                "backupd-helper".into(),
                "Time Machine".into(),
                "mds".into(),
                "mdworker".into(),
                "mdworker_shared".into(),
                "mds_stores".into(),
                "Spotlight".into(),
                "Arq".into(),
                "Backblaze".into(),
                "Carbon Copy Cloner".into(),
                "restic".into(),
                "borg".into(),
                "duplicacy".into(),
                "duplicati".into(),
                "rclone".into(),
                "shasum".into(),
                "md5".into(),
                "fs_usage".into(),
                "sandboxd".into(),
            ],
            crypto_tools: vec![
                "gpg".into(),
                "gpg2".into(),
                "openssl".into(),
                "age".into(),
                "enc".into(),
                "7z".into(),
            ],
            crypto_exts: vec![
                "gpg".into(),
                "pgp".into(),
                "age".into(),
                "asc".into(),
                "enc".into(),
                "crypt".into(),
            ],
            trust_apple_signed: true,
            interpreters: vec![
                "bash".into(),
                "zsh".into(),
                "sh".into(),
                "dash".into(),
                "ksh".into(),
                "csh".into(),
                "tcsh".into(),
                "fish".into(),
                "python".into(),
                "python3".into(),
                "ruby".into(),
                "perl".into(),
                "node".into(),
                "php".into(),
                "osascript".into(),
                "swift".into(),
                "ruby2.6".into(),
                "java".into(),
            ],
            use_codesign: true,
            trusted_exe_prefixes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutputConfig {
    /// Append each incident as one JSON line here.
    pub jsonl: Option<PathBuf>,
    /// Human-readable log level: error | warn | info | debug.
    pub level: String,
    /// Colourise console output.
    pub color: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            jsonl: Some(PathBuf::from("~/.ransomwatch/incidents/incidents.jsonl")),
            level: "info".into(),
            color: true,
        }
    }
}

// ---------------------------------------------------------------------------

impl Config {
    /// Load defaults, then overlay a TOML file if given, then expand paths.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut cfg = match path {
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("reading config {}", p.display()))?;
                let c: Config = toml::from_str(&text)
                    .with_context(|| format!("parsing config {}", p.display()))?;
                c
            }
            None => Config::default(),
        };
        cfg.expand_paths();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn expand_paths(&mut self) {
        self.watch.roots = self.watch.roots.iter().map(|p| crate::util::expand_home(p)).collect();
        self.watch.exclude_paths =
            self.watch.exclude_paths.iter().map(|p| crate::util::expand_home(p)).collect();
        self.decoy.paths = self.decoy.paths.iter().map(|p| crate::util::expand_home(p)).collect();
        self.decoy.manifest_dir = crate::util::expand_home(&self.decoy.manifest_dir);
        self.response.incident_dir = crate::util::expand_home(&self.response.incident_dir);
        self.output.jsonl = self.output.jsonl.as_ref().map(|p| crate::util::expand_home(p));
        self.trust.trusted_exe_prefixes =
            self.trust.trusted_exe_prefixes.iter().map(|p| crate::util::expand_home(p)).collect();
    }

    pub fn validate(&self) -> Result<()> {
        // Roots are deliberately not checked here: `--root` is applied after the
        // file is loaded, and several subcommands need no roots at all.
        for (name, v) in [
            ("entropy.sample_bytes", self.entropy.sample_bytes as f64),
            ("detect.window_secs", self.detect.window_secs as f64),
        ] {
            if v <= 0.0 {
                anyhow::bail!("{} must be > 0", name);
            }
        }
        if self.entropy.high_entropy_floor > self.entropy.high_entropy_h0 {
            anyhow::bail!("entropy.high_entropy_floor must be <= entropy.high_entropy_h0");
        }
        if !(0.0..=1.0).contains(&self.entropy.text_printable_ratio) {
            anyhow::bail!("entropy.text_printable_ratio must be within 0..=1");
        }
        Ok(())
    }

    pub fn defaults_toml() -> String {
        let c = Config::default();
        toml::to_string_pretty(&c).unwrap_or_else(|_| String::from("# unavailable\n"))
    }

    /// Roots that actually exist, canonicalised.
    pub fn existing_roots(&self) -> Vec<PathBuf> {
        self.watch
            .roots
            .iter()
            .filter_map(|r| std::fs::canonicalize(r).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_roundtrip() {
        let s = Config::defaults_toml();
        let c: Config = toml::from_str(&s).expect("defaults must parse");
        assert_eq!(c.detect.min_score, 8.0);
        assert!(c.decoy.enabled);
        assert_eq!(c.response.mode, ResponseMode::Suspend);
    }

    #[test]
    fn rejects_unknown_keys() {
        let bad = "[detect]\nmin_scroe = 4.0\n";
        assert!(toml::from_str::<Config>(bad).is_err());
    }

    #[test]
    fn validates_entropy_ordering() {
        let mut c = Config::default();
        c.entropy.high_entropy_floor = 8.0;
        c.entropy.high_entropy_h0 = 7.5;
        assert!(c.validate().is_err());
    }
}
