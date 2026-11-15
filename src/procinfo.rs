//! Process metadata and the trust model that keeps compression/backup tools
//! from producing false alarms.
//!
//! Trust is intentionally narrow and evidence-based:
//!
//! * **Name list** — a curated set of archivers, copiers, backup agents and
//!   indexers (`tar`, `gzip`, `ditto`, `rsync`, `backupd`, `restic`, ...). These
//!   are quiet for content signals because compressing a document is exactly
//!   what they do; they are *not* quiet for decoy touches.
//! * **Crypto-tool rule** — `gpg`/`openssl`/`age` are only trusted when the file
//!   they produced carries a cryptographic container (`*.gpg`, `*.age`, ...). A
//!   binary merely *named* `openssl` that rewrites `report.docx` into
//!   `report.docx.locked` is not trusted.
//! * **Platform signature** — binaries signed by Apple's platform identity
//!   (shipped in `/usr/bin`, `/bin`, `/System`) are trusted unless they are interpreters.
//! * **Basename is never enough on its own** for the second and third rules:
//!   `cp /path/to/malware /tmp/rsync` must not inherit trust. So a name-list hit
//!   is cross-checked against the executable's location and, when a signature
//!   exists, against its signing identity.
//!
//! The upshot: an unprevileged attacker can copy a signed tool and run it, and
//! that will be trusted — which is correct, because the tool only ever produces
//! legitimately-compressed output that the entropy layer does not flag.

use crate::config::TrustConfig;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// Nothing known; suspicion applies.
    Untrusted,
    /// Trusted by name list, with the observed executable path.
    NameListed,
    /// Apple platform-signed and not an interpreter.
    PlatformSigned,
    /// Trusted only because the output extension is a crypto container.
    CryptoContainer,
    /// The binary itself is our own process (never suspend ourselves).
    SelfProcess,
}

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: i32,
    pub ppid: Option<i32>,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub cmdline: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub start_time: u64,
    pub status: String,
    pub uid: Option<u32>,
    pub trust: Trust,
    /// Signature facts, when inspected.
    pub signing: Option<Signing>,
}

#[derive(Debug, Clone, Default)]
pub struct Signing {
    pub identifier: Option<String>,
    pub team: Option<String>,
    pub authorities: Vec<String>,
    pub is_platform: bool,
    pub is_adhoc: bool,
    pub signed: bool,
}

impl ProcInfo {
    pub fn is_trusted(&self) -> bool {
        !matches!(self.trust, Trust::Untrusted)
    }

    pub fn short(&self) -> String {
        match &self.exe {
            Some(e) => format!("{} ({})", self.name, e.display()),
            None => self.name.clone(),
        }
    }
}

/// Reads process metadata and caches code-signing results.
pub struct ProcTable {
    sys: sysinfo::System,
    /// exe path -> signing facts. Code signatures do not change under us during
    /// a run in any way that matters, so this is a cheap memo.
    signing: Mutex<HashMap<PathBuf, Option<Signing>>>,
    cfg: TrustConfig,
}

impl ProcTable {
    pub fn new(cfg: TrustConfig) -> Self {
        let mut sys = sysinfo::System::new();
        let _ = sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        Self {
            sys,
            signing: Mutex::new(HashMap::new()),
            cfg,
        }
    }

    pub fn refresh(&mut self) {
        self.sys
            .refresh_processes_sysinfo_refresh(sysinfo::ProcessesToUpdate::All, true);
    }

    pub fn lookup(&self, pid: i32) -> Option<ProcInfo> {
        let p = self.sys.process(sysinfo::Pid::from_u32(pid as u32))?;
        let exe = p.exe().map(|e| e.to_path_buf());
        let signing = match (&exe, self.cfg.use_codesign) {
            (Some(path), true) => self.signing_of(path),
            _ => None,
        };
        let name = p.name().to_string_lossy().into_owned();
        let cmdline: Vec<String> = p.cmd().iter().map(|c| c.to_string_lossy().into_owned()).collect();
        let trust = self.classify(pid, &name, exe.as_deref(), signing.as_ref(), None);
        Some(ProcInfo {
            pid,
            ppid: p.parent().map(|x| x.as_u32() as i32),
            name,
            exe,
            cmdline,
            cwd: p.cwd().map(|c| c.to_path_buf()),
            start_time: p.start_time(),
            status: format!("{:?}", p.status()),
            uid: p.user_id().map(|u| **u),
            trust,
            signing,
        })
    }

    /// Classify trust. `io_ext` is the extension of the file being written,
    /// which decides the crypto-tool rule.
    pub fn classify(
        &self,
        pid: i32,
        name: &str,
        exe: Option<&Path>,
        signing: Option<&Signing>,
        io_ext: Option<&str>,
    ) -> Trust {
        if pid == std::process::id() as i32 {
            return Trust::SelfProcess;
        }
        let lower = name.to_ascii_lowercase();

        // Interpreters are never trusted, no matter which list they appear in.
        if self.cfg.interpreters.iter().any(|i| i.eq_ignore_ascii_case(&lower)) {
            return Trust::Untrusted;
        }

        // Rule 2: crypto tools, only for crypto containers.
        if self.cfg.crypto_tools.iter().any(|t| t.eq_ignore_ascii_case(&lower)) {
            let ext_ok = io_ext
                .map(|e| self.cfg.crypto_exts.iter().any(|c| c.eq_ignore_ascii_case(e)))
                .unwrap_or(false);
            if ext_ok {
                return Trust::CryptoContainer;
            }
            return Trust::Untrusted;
        }

        // Rule 1: curated archiver/copier/backup list. Beyond the list, require
        // one of: a signature that is not ad-hoc, a path under a system tool
        // directory, or an explicit trusted prefix. A copied binary in a
        // temporary directory does not qualify.
        if self.cfg.tools.iter().any(|t| t.eq_ignore_ascii_case(&lower)) {
            if let Some(exe) = exe {
                if self.cfg.trusted_exe_prefixes.iter().any(|p| exe.starts_with(p)) {
                    return Trust::NameListed;
                }
                let in_system = exe.starts_with("/usr/bin")
                    || exe.starts_with("/bin")
                    || exe.starts_with("/usr/sbin")
                    || exe.starts_with("/sbin")
                    || exe.starts_with("/System/")
                    || exe.starts_with("/Applications/")
                    || exe.starts_with("/opt/homebrew/")
                    || exe.starts_with("/usr/local/");
                // A signed copy still has to live somewhere an operator installed
                // it. Anything under a writable scratch directory is not trusted
                // by name, signature or not: that is the classic "copy a signed
                // binary and reuse its trust" move.
                let risky_location = is_writable_scratch(exe);
                let signed_ok = signing.map(|s| s.signed && !s.is_adhoc).unwrap_or(false);
                if !risky_location && (in_system || signed_ok) {
                    return Trust::NameListed;
                }
            }
        }

        // Rule 3: platform-signed, non-interpreter binaries — but never one
        // that has been copied into a writable scratch directory.
        if self.cfg.trust_apple_signed {
            let risky = exe.map(is_writable_scratch).unwrap_or(true);
            if let Some(s) = signing {
                if s.is_platform && !s.is_adhoc && !risky {
                    return Trust::PlatformSigned;
                }
            }
            // Ad-hoc-signed binaries under /usr/bin are Apple's own tools too
            // (gzip, tar). Those already matched the name list, so nothing more
            // is granted here: an ad-hoc copy is not trustworthy.
        }
        Trust::Untrusted
    }

    pub fn is_trusted_name(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.cfg.tools.iter().any(|t| t.eq_ignore_ascii_case(&lower))
            || self.cfg.crypto_tools.iter().any(|t| t.eq_ignore_ascii_case(&lower))
    }

    fn signing_of(&self, exe: &Path) -> Option<Signing> {
        let mut cache = match self.signing.lock() {
            Ok(c) => c,
            Err(e) => e.into_inner(),
        };
        if let Some(v) = cache.get(exe) {
            return v.clone();
        }
        let s = inspect_signature(exe);
        cache.insert(exe.to_path_buf(), s.clone());
        s
    }

    /// All live processes whose parent is `pid`, transitively.
    pub fn descendants(&self, pid: i32) -> Vec<i32> {
        let mut out = Vec::new();
        let mut frontier = vec![pid];
        while let Some(cur) = frontier.pop() {
            for (p, proc_) in self.sys.processes() {
                let pp = proc_.parent().map(|x| x.as_u32() as i32);
                if pp == Some(cur) {
                    let c = p.as_u32() as i32;
                    if !out.contains(&c) {
                        out.push(c);
                        frontier.push(c);
                    }
                }
            }
        }
        out
    }
}

// `refresh_processes` is gated behind the right signature in 0.37; provide a
// tiny wrapper so call sites stay readable.
trait SysRefreshExt {
    fn refresh_processes_sysinfo_refresh(
        &mut self,
        update: sysinfo::ProcessesToUpdate<'_>,
        remove_dead: bool,
    );
}

impl SysRefreshExt for sysinfo::System {
    fn refresh_processes_sysinfo_refresh(
        &mut self,
        update: sysinfo::ProcessesToUpdate<'_>,
        remove_dead: bool,
    ) {
        let _ = self.refresh_processes(update, remove_dead);
    }
}

/// Parse `codesign -dv --verbose=4` output into [`Signing`].
pub fn inspect_signature(exe: &Path) -> Option<Signing> {
    let out = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4"])
        .arg(exe)
        .output()
        .ok()?;
    if !out.status.success() {
        // "code object is not signed at all" is reported on stderr with exit 0
        // on some versions and non-zero on others; treat both as unsigned.
        return Some(Signing::default());
    }
    let text = String::from_utf8_lossy(&out.stderr);
    let mut s = Signing {
        signed: true,
        ..Default::default()
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Identifier=") {
            s.identifier = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("TeamIdentifier=") {
            s.team = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Authority=") {
            s.authorities.push(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Platform identifier=") {
            s.is_platform = v.trim().parse::<u32>().map(|n| n > 0).unwrap_or(false);
        } else if let Some(v) = line.strip_prefix("CodeDirectory ") {
            if v.contains("adhoc") {
                s.is_adhoc = true;
            }
        }
    }
    // Ad-hoc signatures usually carry no Authority lines and flags mark adhoc.
    if s.authorities.is_empty() {
        s.is_adhoc = s.is_adhoc || text.contains("adhoc");
    }
    Some(s)
}

/// Native `kill(2)` wrappers, kept here so the response layer does not have to
/// know about libc.
pub fn suspend(pid: i32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid, libc::SIGSTOP) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

pub fn resume(pid: i32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid, libc::SIGCONT) == 0 }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// Directories where anyone can drop a file: trust by name must not survive a
/// copy into one of these.
pub fn is_writable_scratch(exe: &Path) -> bool {
    const SCRATCH: &[&str] = &[
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "/private/var/tmp/",
        "/private/var/folders/",
        "/var/folders/",
        "/dev/shm/",
        "/Users/Shared/",
        "/Downloads/",
    ];
    let s = exe.to_string_lossy();
    SCRATCH.iter().any(|p| s.starts_with(p) || s.contains(p))
}

/// Newest executable paths are the ones most likely to be malware; used only
/// for ranking, never for verdicts.
pub fn exe_is_recent(exe: &Path, within_secs: i64) -> bool {
    let meta = match std::fs::metadata(exe) {
        Ok(m) => m,
        Err(_) => return false,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mtime = meta.mtime();
        let now = crate::util::now_unix();
        now - mtime <= within_secs
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> ProcTable {
        ProcTable::new(TrustConfig::default())
    }

    #[test]
    fn interpreters_never_trusted() {
        let t = table();
        for name in ["bash", "python3", "node", "osascript"] {
            assert_eq!(t.classify(999, name, Some(Path::new("/usr/bin/bash")), None, None), Trust::Untrusted);
        }
    }

    #[test]
    fn name_listed_only_in_system_dir() {
        let t = table();
        assert_eq!(
            t.classify(999, "gzip", Some(Path::new("/usr/bin/gzip")), None, None),
            Trust::NameListed
        );
        // A copy in a temp dir does not inherit the name's trust.
        assert_eq!(
            t.classify(999, "gzip", Some(Path::new("/tmp/evil/gzip")), None, None),
            Trust::Untrusted
        );
    }

    #[test]
    fn crypto_tool_needs_crypto_ext() {
        let t = table();
        assert_eq!(
            t.classify(999, "gpg", Some(Path::new("/usr/local/bin/gpg")), None, Some("gpg")),
            Trust::CryptoContainer
        );
        assert_eq!(
            t.classify(999, "gpg", Some(Path::new("/usr/local/bin/gpg")), None, Some("docx")),
            Trust::Untrusted
        );
    }

    #[test]
    fn parses_codesign_output() {
        let s = inspect_signature(Path::new("/usr/bin/gzip")).unwrap_or_default();
        if s.signed {
            assert!(s.is_platform, "gzip should be platform-signed: {s:?}");
            assert!(!s.is_adhoc);
        }
    }

    #[test]
    fn unsigned_copies_look_unsigned() {
        let dir = std::env::temp_dir().join(format!("rw-sig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("copy");
        std::fs::copy("/usr/bin/gzip", &p).unwrap();
        let s = inspect_signature(&p).unwrap_or_default();
        // Copying a signed binary preserves the embedded signature, so this may
        // still be signed; what must never happen is being treated as trusted.
        let t = table();
        assert_eq!(
            t.classify(999, "gzip", Some(&p), Some(&s), None),
            Trust::Untrusted,
            "a copied tool in a temp dir must not be trusted: {s:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
