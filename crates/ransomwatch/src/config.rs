//! Configuration: defaults, TOML file loading, and CLI overrides.

use crate::entropy::SampleConfig;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::path::PathBuf;
use std::time::Duration;

/// A `Duration` written as a human string ("500ms", "10s", "5m") rather than a
/// `{secs, nanos}` table, so a config file stays readable and editable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HumanDuration(pub Duration);

impl From<Duration> for HumanDuration {
    fn from(d: Duration) -> Self {
        HumanDuration(d)
    }
}

impl From<HumanDuration> for Duration {
    fn from(h: HumanDuration) -> Self {
        h.0
    }
}

impl std::fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format_duration(self.0))
    }
}

impl HumanDuration {
    pub fn secs(n: u64) -> Self {
        HumanDuration(Duration::from_secs(n))
    }
    pub fn millis(n: u64) -> Self {
        HumanDuration(Duration::from_millis(n))
    }
    pub fn get(self) -> Duration {
        self.0
    }
}

pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("empty duration".into());
    }
    // Split the numeric prefix from the unit suffix.
    let idx = t
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(idx);
    let value: f64 = num
        .parse()
        .map_err(|_| format!("invalid duration {text:?}: no leading number"))?;
    if value < 0.0 || !value.is_finite() {
        return Err(format!("invalid duration {text:?}"));
    }
    let unit = unit.trim().to_ascii_lowercase();
    let secs = match unit.as_str() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => value,
        "ms" | "milli" | "millis" | "millisecond" | "milliseconds" => value / 1000.0,
        "us" | "micro" | "micros" => value / 1_000_000.0,
        "ns" | "nano" | "nanos" => value / 1_000_000_000.0,
        "m" | "min" | "mins" | "minute" | "minutes" => value * 60.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => value * 3600.0,
        other => return Err(format!("unknown duration unit {other:?} in {text:?}")),
    };
    if secs < 0.0 || secs > 86_400.0 * 365.0 {
        return Err(format!("duration {text:?} out of range"));
    }
    Ok(Duration::from_secs_f64(secs))
}

pub fn format_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms == 0 {
        return "0s".into();
    }
    if ms % 1000 == 0 {
        let secs = ms / 1000;
        if secs % 3600 == 0 && secs >= 3600 {
            format!("{}h", secs / 3600)
        } else if secs % 60 == 0 && secs >= 60 {
            format!("{}m", secs / 60)
        } else {
            format!("{secs}s")
        }
    } else {
        format!("{ms}ms")
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&format_duration(self.0))
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        parse_duration(&s).map(HumanDuration).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub watch: WatchConfig,
    pub detection: DetectionConfig,
    pub decoy: DecoyConfig,
    pub response: ResponseConfig,
    pub scan: ScanConfig,
    pub log: LogConfig,
    /// Process names that are never treated as suspicious writers: backup and
    /// archive tooling that legitimately rewrites many files.  Matched as
    /// case-insensitive substrings against the executable basename.
    pub allow_processes: Vec<String>,
    /// Directory names never descended into (matched on the path component).
    pub ignore_dirs: Vec<String>,
    /// Glob-ish suffix rules: never evaluate a file whose path ends with one
    /// of these suffixes.
    pub ignore_suffixes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct WatchConfig {
    /// Directories to monitor recursively.
    pub paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionConfig {
    /// Entropy (bits/byte) at or above which a complete rewrite counts as
    /// "high entropy".  Compressed output sits at ~7.95-8.0; source code and
    /// prose sit well below 5.0.  7.2 leaves room for small samples.
    pub high_entropy: f64,
    /// Entropy at or below which the *previous* content counts as plaintext.
    pub plain_entropy: f64,
    /// Entropy on a small sample is noisy, so a file at or below this size is
    /// not classified high-entropy on its own; breadth signals still catch it.
    pub min_size_for_entropy: u64,
    /// Existing files whose content changed within the window.
    pub rewrite_burst_files: usize,
    /// New header-less high-entropy files within the window.
    pub create_burst_files: usize,
    /// High-entropy creations that, together with removals, indicate
    /// encrypt-then-delete rather than bulk creation.
    pub replacement_creates: usize,
    pub replacement_deletes: usize,
    /// Aggregate score at which an incident is opened.
    pub incident_score: i32,
    /// Seconds between incidents; signals still fire during the cool-down.
    pub cooldown_secs: u64,
    /// Sliding window used for "many files in a short time".
    pub window: HumanDuration,
    /// Distinct files rewritten to high entropy within `window` that make a
    /// burst suspicious.
    pub entropy_burst_files: usize,
    /// Distinct files renamed to a new extension within `window`.
    pub rename_burst_files: usize,
    /// Distinct files touched (any write/create/rename) within `window`
    /// before the mass-modification detector raises.
    pub mass_touch_files: usize,
    /// Distinct ransomware extensions observed within `window`.
    pub ransom_ext_files: usize,
    /// Files deleted/removed within `window`.
    pub delete_burst_files: usize,
    /// A single extension must cover at least this fraction of the renamed
    /// set to count as "bulk extension change" (random renames don't).
    pub extension_dominance: f64,
    /// Do not fire on a burst when the number of files touched is smaller
    /// than this absolute floor (avoids firing on a 3-file edit).
    pub burst_floor: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DecoyConfig {
    pub enabled: bool,
    /// Number of decoy files placed into each watched root on startup.
    pub count_per_root: usize,
    /// Filenames are drawn from this list (with a numeric suffix) so they look
    /// like ordinary business documents.
    pub names: Vec<String>,
    /// Populate decoys with this much recognisable content so their entropy
    /// is unambiguously plaintext.
    pub file_bytes: usize,
    /// Treat *any* of these on a decoy as a trip: read (atime bump), open for
    /// write, write, rename or delete.
    pub trip_on_read: bool,
    pub trip_on_write: bool,
    pub trip_on_rename: bool,
    pub trip_on_delete: bool,
    /// Polling period for decoy integrity (belt-and-braces behind FSEvents).
    pub poll_interval: HumanDuration,
    /// Seconds to let the filesystem settle after creation before we start
    /// trusting atime changes as real reads.
    pub arm_after: HumanDuration,
    /// Subdirectory (relative to each watch root) decoys are placed in.
    pub subdir: String,
    /// Ignore filesystem events on a decoy for this long after we (re)wrote
    /// it ourselves, so our own writes cannot look like a trip.
    pub self_write_quiet: HumanDuration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseConfig {
    /// Actually suspend (SIGSTOP) a blamed process.
    pub suspend: bool,
    /// Detect, log and attribute, but write no evidence and send no signals.
    pub dry_run: bool,
    /// Never suspend these pids / executables even if blamed.
    pub never_suspend: Vec<String>,
    /// Maximum time a suspend decision may take (attribution scan budget).
    pub attribution_deadline_ms: u64,
    /// Where forensic bundles are written.  One directory per incident.
    pub evidence_dir: Option<PathBuf>,
    /// Also run a user-supplied script on incident (receives incident JSON on
    /// stdin).  Kept as an explicit escape hatch for real deployments.
    pub on_incident_command: Option<String>,
    /// FSEvents coalescing latency in seconds.  Small values give faster
    /// detection; the kernel caps how small this can be.
    pub fsevent_latency: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    /// Initial recursive walk at startup to establish baselines.
    pub baseline_on_start: bool,
    /// Hard cap on files baselined at startup (large trees should raise it).
    pub baseline_max_files: usize,
    /// Ignore files larger than this for *content* sampling (metadata-only).
    pub max_sample_bytes: u64,
    /// How often to reconcile against a full walk (catches missed events).
    pub reconcile_interval: HumanDuration,
    /// Take a cheap (8 KiB) sample on open-for-write, a full sample on close.
    pub small_sample_bytes: usize,
    pub full_sample_bytes: usize,
    /// Shrink the comm window for short-lived writers: pids seen within this
    /// period are candidates for attribution even after they exit.
    pub pid_memory: HumanDuration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    pub path: Option<PathBuf>,
    pub jsonl: bool,
    /// Print every detected event to stderr, not just incidents.
    pub verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            watch: WatchConfig::default(),
            detection: DetectionConfig::default(),
            decoy: DecoyConfig::default(),
            response: ResponseConfig::default(),
            scan: ScanConfig::default(),
            log: LogConfig::default(),
            allow_processes: default_allow_processes(),
            ignore_dirs: default_ignore_dirs(),
            ignore_suffixes: default_ignore_suffixes(),
        }
    }
}

fn default_allow_processes() -> Vec<String> {
    // Backup / sync / archiving tools.  These legitimately rewrite or create
    // many high-entropy files.  Matched against the process basename.
    [
        "time machine",
        "tmutil",
        "backupd",
        "backupd-helper",
        "mds",
        "mds_stores",
        "mdworker",
        "spotlight",
        "fseventsd",
        "rsync",
        "restic",
        "borg",
        "duplicity",
        "rdiff-backup",
        "rclone",
        "unison",
        "syncthing",
        "dropbox",
        "onedrive",
        "google drive",
        "googledrive",
        "box",
        "sharepoint",
        "carbon copy cloner",
        "ccc",
        "superduper",
        "chronosync",
        "arq",
        "backblaze",
        "crashplan",
        "veeam",
        "acronis",
        "tar",
        "gtar",
        "bsdtar",
        "zip",
        "unzip",
        "7z",
        "p7zip",
        "gzip",
        "gunzip",
        "bzip2",
        "xz",
        "zstd",
        "ditto",
        "openssl",
        "gpg",
        "gpg2",
        "age",
        "rage",
        "veracrypt",
        "encfs",
        "gocryptfs",
        "cryptomator",
        "keka",
        "betterzip",
        "archiver",
        "unarchiver",
        "stuffit",
        "expander",
        "pax",
        "cpio",
        "hdiutil",
        "installer",
        "softwareupdate",
        "pkgutil",
        "xcodebuild",
        "git",
        "hg",
        "svn",
        "docker",
        "containerd",
        "podman",
        "com.docker",
        "utm",
        "qemu",
        "virtualbox",
        "vmware",
        "parallels",
        "sourcetree",
        "tower",
        "github desktop",
        "node",
        "npm",
        "yarn",
        "pnpm",
        "cargo",
        "rustc",
        "go",
        "python",
        "python3",
        "java",
        "mvn",
        "gradle",
        "dotnet",
        "make",
        "cmake",
        "ninja",
        "cc",
        "clang",
        "ld",
        "swift",
        "swiftc",
        "ldid",
        "codesign",
        "notarytool",
        "stapler",
        "ffmpeg",
        "avconvert",
        "handbrake",
        "imagemagick",
        "magick",
        "sips",
        "convert",
        "photoshop",
        "lightroom",
        "final cut",
        "premiere",
        "logic pro",
        "ableton",
        "audacity",
        "transmission",
        "qbittorrent",
        "deluge",
        "aria2",
        "wget",
        "curl",
        "steam",
        "epicgames",
        "itch",
        "blender",
        "unity",
        "unreal",
        "xcode",
        "simulator",
        "emulator",
        "android",
        "adb",
        "simctl",
        "xcrun",
        "fastlane",
        "pkgbuild",
        "productbuild",
        "create-dmg",
        "appdmg",
        "electron",
        "chromium",
        "chrome",
        "firefox",
        "safari",
        "webkit",
        "webcontent",
        "preview",
        "quicklookd",
        "quicklook",
        "diskimages-helper",
        "kernel_task",
        "launchd",
        "logd",
        "syslogd",
        "configd",
        "powerd",
        "coreduetd",
        "biometrickitd",
        "secinitd",
        "tccd",
        "amfid",
        "trustd",
        "cloudd",
        "bird",
        "fileproviderd",
        "filecoordinationd",
        "nsurlsessiond",
        "nsurlstoraged",
        "cfprefsd",
        "distnoted",
        "opendirectoryd",
        "securityd",
        "authd",
        "loginwindow",
        "windowserver",
        "dock",
        "finder",
        "screensharingd",
        "rapportd",
        "sharingd",
        "airportd",
        "bluetoothd",
        "wifi",
        "sandboxd",
        "watchdogd",
        "spindump",
        "symptomd",
        "diagnosticd",
        "analyticsd",
        "sysdiagnose",
        "crashpad",
        "reportcrash",
        "corespeechd",
        "triald",
        "secd",
        "trustd",
        "osanalyticshelper",
        "powerlogd",
        "systemstats",
        "thermald",
        "warmd",
        "useractivityd",
        "siriactionsd",
        "siriknowledged",
        "assistantd",
        "parsec-fbf",
        "knowledged",
        "mediaremoted",
        "nowplayingd",
        "controlcenter",
        "notificationcenter",
        "usernoted",
        "cmd",
        "powershell",
        "bash",
        "zsh",
        "sh",
        "fish",
        "tmux",
        "screen",
        "ssh",
        "sshd",
        "vim",
        "nvim",
        "emacs",
        "code",
        "code helper",
        "cursor",
        "zed",
        "sublime",
        "atom",
        "textmate",
        "bbedit",
        "nano",
        "pico",
        "man",
        "less",
        "more",
        "cat",
        "sed",
        "awk",
        "grep",
        "find",
        "mdfind",
        "mdls",
        "xattr",
        "ditto",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn default_ignore_dirs() -> Vec<String> {
    [
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "target",
        "build",
        "dist",
        ".build",
        "DerivedData",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".next",
        ".nuxt",
        ".cache",
        ".gradle",
        ".m2",
        "Caches",
        "Cache",
        "CacheStorage",
        ".Trash",
        "Trashes",
        "$RECYCLE.BIN",
        "System Volume Information",
        ".DocumentRevisions-V100",
        ".Spotlight-V100",
        ".fseventsd",
        ".TemporaryItems",
        "Library",
        ".localized",
        "bundle",
        "vendor",
        ".terraform",
        ".yarn",
        ".pnpm-store",
        ".npm",
        ".cargo",
        ".rustup",
        "Pods",
        ".idea",
        ".vscode",
        "venv3",
        "site-packages",
        ".venv3",
        ".gradle-cache",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn default_ignore_suffixes() -> Vec<String> {
    [
        ".crdownload",
        ".download",
        ".part",
        ".partial",
        ".tmp",
        ".temp",
        ".swp",
        ".swx",
        ".swo",
        ".lockfile",
        ".~lock",
        ".DS_Store",
        ".localized",
        "Icon\r",
        ".sock",
        ".pid",
        ".vscode-test",
        ".pyc",
        ".pyo",
        ".o",
        ".a",
        ".dylib",
        ".so",
        ".rlib",
        ".rmeta",
        ".pdb",
        ".ilk",
        ".git/index",
        ".git/ORIG_HEAD",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}


impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            high_entropy: 7.20,
            plain_entropy: 6.20,
            min_size_for_entropy: 1_024,
            window: HumanDuration::secs(10),
            entropy_burst_files: 5,
            rename_burst_files: 8,
            mass_touch_files: 25,
            ransom_ext_files: 3,
            delete_burst_files: 15,
            rewrite_burst_files: 10,
            create_burst_files: 12,
            replacement_creates: 3,
            replacement_deletes: 3,
            extension_dominance: 0.60,
            burst_floor: 4,
            incident_score: 50,
            cooldown_secs: 30,
        }
    }
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            count_per_root: 4,
            names: [
                "annual_financial_report",
                "employee_records_2024",
                "client-contracts-summary",
                "payroll_details_Q3",
                "board_meeting_minutes",
                "passwords_and_codes",
                "budget_forecast_2025",
                "quarterly_tax_filing",
                "invoices_pending",
                "customer_database_export",
                "insurance_policy_documents",
                "legal_settlement_draft",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            file_bytes: 48 * 1024,
            trip_on_read: true,
            trip_on_write: true,
            trip_on_rename: true,
            trip_on_delete: true,
            poll_interval: HumanDuration::secs(2),
            arm_after: HumanDuration::secs(3),
            subdir: "__rw_decoys".to_string(),
            self_write_quiet: HumanDuration::millis(750),
        }
    }
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            suspend: true,
            dry_run: false,
            never_suspend: vec![
                "launchd".into(),
                "kernel_task".into(),
                "WindowServer".into(),
                "loginwindow".into(),
                "sshd".into(),
                "Finder".into(),
                "Dock".into(),
                "mds".into(),
                "mds_stores".into(),
                "fseventsd".into(),
                "rsync".into(),
                "backupd".into(),
                "tmutil".into(),
                "tar".into(),
                "zip".into(),
                "gzip".into(),
                "ditto".into(),
                "cp".into(),
                "mv".into(),
                "rm".into(),
                "sh".into(),
                "bash".into(),
                "zsh".into(),
                "python3".into(),
                "python".into(),
                "node".into(),
                "cargo".into(),
                "git".into(),
            ],
            attribution_deadline_ms: 1_500,
            evidence_dir: None,
            on_incident_command: None,
            fsevent_latency: 0.05,
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            baseline_on_start: true,
            baseline_max_files: 200_000,
            max_sample_bytes: 4 * 1024 * 1024 * 1024,
            reconcile_interval: HumanDuration::secs(300),
            small_sample_bytes: 8 * 1024,
            full_sample_bytes: 16 * 1024,
            pid_memory: HumanDuration::secs(60),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            path: None,
            jsonl: true,
            verbose: false,
        }
    }
}

impl Config {
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", path.display()))?;
        let mut cfg: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("invalid config {}: {e}", path.display()))?;
        // Paths in the file are relative to the config file's directory, which
        // is friendlier for deployment.
        if let Some(dir) = path.parent() {
            for p in &mut cfg.watch.paths {
                if p.is_relative() {
                    *p = dir.join(&*p);
                }
            }
            if let Some(ev) = &mut cfg.response.evidence_dir {
                if ev.is_relative() {
                    *ev = dir.join(&*ev);
                }
            }
            if let Some(lp) = &mut cfg.log.path {
                if lp.is_relative() {
                    *lp = dir.join(&*lp);
                }
            }
        }
        Ok(cfg)
    }

    pub fn sample_config_full(&self) -> SampleConfig {
        let n = self.scan.full_sample_bytes;
        SampleConfig {
            head_bytes: n,
            mid_bytes: n,
            tail_bytes: n,
        }
    }

    pub fn sample_config_small(&self) -> SampleConfig {
        let n = self.scan.small_sample_bytes;
        SampleConfig {
            head_bytes: n,
            mid_bytes: 0,
            tail_bytes: n,
        }
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_else(|_| String::new())
    }

    /// Does this path look ignorable (build outputs, temp files, etc.)?
    pub fn is_ignored_path(&self, path: &std::path::Path) -> bool {
        self.is_ignored_relative(path, path)
    }

    /// Like [`Config::is_ignored_path`], but only the components *below* `root`
    /// are checked.  This stops a watch root that happens to be called
    /// "build" or "Library" from being ignored in its entirety.
    pub fn is_ignored_relative(&self, root: &std::path::Path, path: &std::path::Path) -> bool {
        let rel = path.strip_prefix(root).unwrap_or(path);
        let s = path.to_string_lossy();
        for suffix in &self.ignore_suffixes {
            if s.ends_with(suffix.as_str()) {
                return true;
            }
        }
        for comp in rel.components() {
            if let std::path::Component::Normal(part) = comp {
                if let Some(part) = part.to_str() {
                    if self.ignore_dirs.iter().any(|d| d == part) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn is_allowed_process(&self, exe_name: &str) -> bool {
        let lower = exe_name.to_ascii_lowercase();
        self.allow_processes
            .iter()
            .any(|a| lower.contains(&a.to_ascii_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert!(c.detection.high_entropy > c.detection.plain_entropy);
        assert!(c.detection.plain_entropy < 8.0);
        assert!(c.decoy.enabled);
    }

    #[test]
    fn parses_partial_toml() {
        let text = r#"
[watch]
paths = ["/tmp/x"]

[detection]
entropy_burst_files = 9
"#;
        let c: Config = toml::from_str(text).unwrap();
        assert_eq!(c.watch.paths, vec![PathBuf::from("/tmp/x")]);
        assert_eq!(c.detection.entropy_burst_files, 9);
        // untouched fields keep their defaults
        assert_eq!(c.detection.high_entropy, 7.20);
    }

    #[test]
    fn rejects_unknown_keys() {
        let text = "[detection]\nnot_a_key = 1\n";
        assert!(toml::from_str::<Config>(text).is_err());
    }

    #[test]
    fn ignored_paths() {
        let c = Config::default();
        let root = std::path::Path::new("/a");
        assert!(c.is_ignored_relative(root, std::path::Path::new("/a/node_modules/b/file.js")));
        assert!(c.is_ignored_relative(root, std::path::Path::new("/a/b/x.part")));
        assert!(!c.is_ignored_relative(root, std::path::Path::new("/a/b/report.docx")));
    }

    #[test]
    fn watch_root_named_like_ignored_dir_is_still_watched() {
        // A root called "build" must not cause everything under it to be ignored.
        let c = Config::default();
        let root = std::path::Path::new("/Users/me/build");
        assert!(!c.is_ignored_relative(root, std::path::Path::new("/Users/me/build/src/main.rs")));
        assert!(c.is_ignored_relative(
            root,
            std::path::Path::new("/Users/me/build/node_modules/x.js")
        ));
    }

    #[test]
    fn durations_parse_and_round_trip() {
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("2").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration(" 1.5s ").unwrap(), Duration::from_millis(1500));
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("-3s").is_err());
        assert!(parse_duration("3 lightyears").is_err());
        for d in [
            Duration::from_secs(10),
            Duration::from_millis(750),
            Duration::from_secs(300),
            Duration::from_secs(3600),
        ] {
            assert_eq!(parse_duration(&format_duration(d)).unwrap(), d);
        }
    }

    #[test]
    fn toml_uses_human_durations() {
        let c = Config::default();
        let text = c.to_toml();
        assert!(text.contains("window = \"10s\""), "{text}");
        assert!(text.contains("poll_interval = \"2s\""), "{text}");
        // and it parses back to the same values
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.detection.window.get(), Duration::from_secs(10));
        assert_eq!(back.decoy.self_write_quiet.get(), Duration::from_millis(750));
        assert!((back.detection.high_entropy - 7.2).abs() < 1e-9);
    }

    #[test]
    fn f32_rounding_no_longer_leaks() {
        let c = Config::default();
        assert!((c.detection.high_entropy - 7.2).abs() < 1e-12);
        assert!((c.detection.extension_dominance - 0.6).abs() < 1e-12);
    }

    #[test]
    fn allowed_processes() {
        let c = Config::default();
        assert!(c.is_allowed_process("rsync"));
        assert!(c.is_allowed_process("mds_stores"));
        assert!(!c.is_allowed_process("ransom_sim"));
    }
}
