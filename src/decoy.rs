//! Canary ("decoy") files.
//!
//! A decoy is a document that looks valuable but is touched by nothing
//! legitimate. Any change, rename, removal or open-for-read by a process that is
//! not on the trust list raises a critical incident immediately, with no
//! scoring: an encryptor walking the directory will rewrite it, and that is
//! about as unambiguous as a signal gets.
//!
//! Two facts drove the design:
//!
//! 1. **FSEvents does not report reads.** Opening a file for reading produces no
//!    event at all on macOS (verified), so "somebody opened the decoy" can only
//!    be seen by polling open file descriptors. [`DecoySet::poll_openers`] does
//!    that with the in-process libproc sweep in [`crate::attr`].
//! 2. **A rewrite is indistinguishable from a legitimate write by content**, so
//!    the decoy's identity is its *inode* plus a canary token embedded in its
//!    bytes. If the bytes change at all, or the inode changes, the decoy has been
//!    tampered with — no entropy judgement required.
//!
//! The decoy manifest is stored *outside* the watched roots (default
//! `~/.ransomwatch/decoys`) so that an encryptor sweeping the directory cannot
//! silently re-baseline it.

use crate::attr;
use crate::config::DecoyConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// One planted decoy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decoy {
    pub path: PathBuf,
    /// Random hex embedded in the file body; proves the file is ours and lets a
    /// rewrite be detected even when the mtime was forged back.
    pub canary: String,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    /// SHA-256 of the exact bytes we wrote.
    pub digest: String,
    pub planted_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Manifest {
    pub version: u32,
    pub decoys: Vec<Decoy>,
}

/// Why a decoy raised an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoyViolation {
    /// Bytes changed, were truncated, or the digest no longer matches.
    Modified,
    /// The file vanished.
    Removed,
    /// The inode changed: the original was deleted and something else replaced
    /// it at the same path.
    Replaced,
    /// A process not on the trust list holds the file open for reading.
    OpenedForRead,
    /// A process not on the trust list holds the file open for writing.
    OpenedForWrite,
}

impl DecoyViolation {
    pub fn as_str(self) -> &'static str {
        match self {
            DecoyViolation::Modified => "decoy_modified",
            DecoyViolation::Removed => "decoy_removed",
            DecoyViolation::Replaced => "decoy_replaced",
            DecoyViolation::OpenedForRead => "decoy_opened_read",
            DecoyViolation::OpenedForWrite => "decoy_opened_write",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecoyAlert {
    pub decoy: Decoy,
    pub violation: DecoyViolation,
    pub detail: String,
    /// Pids seen holding the decoy, if any.
    pub pids: Vec<i32>,
}

pub struct DecoySet {
    cfg: DecoyConfig,
    decoys: HashMap<PathBuf, Decoy>,
    manifest_path: PathBuf,
    /// Pids already alerted on for read access, so the 500 ms poller does not
    /// re-alert on the same holder.
    alerted_readers: HashMap<PathBuf, std::collections::HashSet<i32>>,
    /// Last tamper alert per decoy, with the violation it reported. One tamper
    /// event produces several observations (digest mismatch, then the write fd,
    /// then removal), so those must fold into one record — but a *different*
    /// violation later (say the recreated decoy is deleted again) is new evidence
    /// and must alert.
    last_tamper_alert: HashMap<PathBuf, (std::time::Instant, DecoyViolation)>,
    /// Window during which a decoy's further tamper alerts are folded into the
    /// first one.
    dedupe_window: std::time::Duration,
}

impl DecoySet {
    /// Load a previous manifest (if any) and plant the configured number of
    /// decoys into every root. Existing decoys from the manifest are reused when
    /// they are still intact.
    pub fn setup(
        cfg: &DecoyConfig,
        roots: &[PathBuf],
        watch_cfg: &crate::config::WatchConfig,
    ) -> std::io::Result<Self> {
        let manifest_path = cfg.manifest_dir.join("manifest.json");
        let mut set = Self {
            cfg: cfg.clone(),
            decoys: HashMap::new(),
            manifest_path,
            alerted_readers: HashMap::new(),
            last_tamper_alert: HashMap::new(),
            dedupe_window: std::time::Duration::from_secs(30),
        };
        if !cfg.enabled {
            return Ok(set);
        }
        let mut existing = set.load_manifest();
        // Keep only decoys that are still byte-identical; anything else is
        // re-planted under a new name and reported by the caller's first poll.
        existing.retain(|d| set.decoy_intact(d).is_ok());

        if cfg.plant_in_roots {
            let n = cfg.count.max(1);
            for root in roots {
                let dir = if cfg.subdir.is_empty() {
                    root.clone()
                } else {
                    root.join(&cfg.subdir)
                };
                if std::fs::create_dir_all(&dir).is_err() {
                    continue;
                }
                // Prefer reusing intact decoys already in this directory.
                let mut have: usize = existing
                    .iter()
                    .filter(|d| d.path.parent() == Some(dir.as_path()))
                    .count();
                for reused in existing.iter().filter(|d| d.path.parent() == Some(dir.as_path())) {
                    set.decoys.insert(reused.path.clone(), reused.clone());
                }
                while have < n {
                    let idx = have;
                    match plant_one(&dir, &cfg.names, idx, watch_cfg) {
                        Ok(d) => {
                            set.decoys.insert(d.path.clone(), d);
                            have += 1;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        for p in &cfg.paths {
            if let Ok(d) = adopt_existing(p) {
                set.decoys.insert(d.path.clone(), d);
            }
        }
        set.save_manifest();
        Ok(set)
    }

    fn load_manifest(&self) -> Vec<Decoy> {
        let text = match std::fs::read_to_string(&self.manifest_path) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        serde_json::from_str::<Manifest>(&text)
            .map(|m| m.decoys)
            .unwrap_or_default()
    }

    fn save_manifest(&self) {
        let m = Manifest {
            version: 1,
            decoys: self.decoys.values().cloned().collect(),
        };
        if let Ok(s) = serde_json::to_vec_pretty(&m) {
            let _ = crate::util::write_atomic(&self.manifest_path, &s);
        }
    }

    pub fn decoys(&self) -> impl Iterator<Item = &Decoy> {
        self.decoys.values()
    }

    pub fn len(&self) -> usize {
        self.decoys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.decoys.is_empty()
    }

    pub fn get(&self, path: &Path) -> Option<&Decoy> {
        self.decoys.get(path)
    }

    /// Pattern that the event layer can use to short-circuit: decoy paths are
    /// always interesting regardless of exclusions.
    pub fn contains(&self, path: &Path) -> bool {
        self.decoys.contains_key(path)
    }

    /// Check one decoy for tampering. Returns an alert if it changed.
    ///
    /// A single tamper event can be observed several ways in quick succession
    /// (digest mismatch, an open write fd, then the file vanishing). Only the
    /// first observation inside `dedupe_window` becomes an alert; the rest are
    /// folded into it, so one act of vandalism yields one incident.
    pub fn check(&mut self, path: &Path) -> Option<DecoyAlert> {
        let d = self.decoys.get(path)?.clone();
        match self.decoy_intact(&d) {
            Ok(()) => {
                // A restored/renamed-back decoy clears the memo.
                self.last_tamper_alert.remove(path);
                None
            }
            Err(v) => {
                let violation = match v {
                    IntactError::Missing => DecoyViolation::Removed,
                    IntactError::Replaced => DecoyViolation::Replaced,
                    IntactError::Modified => DecoyViolation::Modified,
                };
                if let Some((t, prev)) = self.last_tamper_alert.get(path) {
                    if *prev == violation && t.elapsed() < self.dedupe_window {
                        return None;
                    }
                }
                self.last_tamper_alert
                    .insert(path.to_path_buf(), (std::time::Instant::now(), violation));
                Some(match v {
                IntactError::Missing => DecoyAlert {
                    decoy: d,
                    violation: DecoyViolation::Removed,
                    detail: "decoy file is gone".into(),
                    pids: Vec::new(),
                },
                IntactError::Replaced => DecoyAlert {
                    decoy: d,
                    violation: DecoyViolation::Replaced,
                    detail: "decoy inode changed: original was deleted and replaced".into(),
                    pids: Vec::new(),
                },
                IntactError::Modified => DecoyAlert {
                    decoy: d,
                    violation: DecoyViolation::Modified,
                    detail: "decoy content changed (digest mismatch)".into(),
                    pids: Vec::new(),
                },
                })
            }
        }
    }

    fn decoy_intact(&self, d: &Decoy) -> Result<(), IntactError> {
        let meta = std::fs::symlink_metadata(&d.path).map_err(|_| IntactError::Missing)?;
        let (dev, ino) = crate::detect::dev_ino(&meta);
        if ino != d.ino || dev != d.dev {
            return Err(IntactError::Replaced);
        }
        if meta.len() != d.size {
            return Err(IntactError::Modified);
        }
        let bytes = match std::fs::read(&d.path) {
            Ok(b) => b,
            Err(_) => return Err(IntactError::Missing),
        };
        if crate::util::sha256_hex(&bytes) != d.digest {
            return Err(IntactError::Modified);
        }
        Ok(())
    }

    /// Poll the process table for holders of any decoy. Read access is only
    /// visible this way: FSEvents does not report opens.
    ///
    /// `trusted(pid, name, exe, ext)` decides whether a holder is legitimate.
    pub fn poll_openers(
        &mut self,
        mut trusted: impl FnMut(i32) -> Option<(bool, String)>,
    ) -> Vec<DecoyAlert> {
        if !self.cfg.enabled || self.decoys.is_empty() {
            return Vec::new();
        }
        let mut alerts = Vec::new();
        let holders = attr::holders_by_pid();
        // Invert: path -> holders.
        let mut by_path: HashMap<PathBuf, Vec<attr::OpenHolder>> = HashMap::new();
        for holds in holders.into_values() {
            for h in holds {
                by_path.entry(h.path.clone()).or_default().push(h);
            }
        }
        for (path, d) in &self.decoys {
            let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
            let holds = by_path.get(&key).or_else(|| by_path.get(path));
            let holds = match holds {
                Some(h) => h,
                None => continue,
            };
            let mut readers = Vec::new();
            let mut writers = Vec::new();
            for h in holds {
                match trusted(h.pid) {
                    Some((true, _)) => continue,
                    Some((false, name)) => {
                        if h.writable {
                            writers.push((h.pid, name));
                        } else {
                            readers.push((h.pid, name));
                        }
                    }
                    None => {}
                }
            }
            if !writers.is_empty() {
                // Fold only when the same decoy already reported a write-open
                // recently; any other violation is separate evidence.
                let folded = self
                    .last_tamper_alert
                    .get(path)
                    .map(|(t, prev)| {
                        *prev == DecoyViolation::OpenedForWrite && t.elapsed() < self.dedupe_window
                    })
                    .unwrap_or(false);
                let pids: Vec<i32> = writers.iter().map(|(p, _)| *p).collect();
                if !folded {
                    self.last_tamper_alert.insert(
                        path.clone(),
                        (std::time::Instant::now(), DecoyViolation::OpenedForWrite),
                    );
                }
                if !folded {
                    alerts.push(DecoyAlert {
                    decoy: d.clone(),
                    violation: DecoyViolation::OpenedForWrite,
                        detail: format!(
                            "opened for write by {}",
                            writers
                                .iter()
                                .map(|(p, n)| format!("{}[{}]", n, p))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        pids,
                    });
                }
            } else if self.cfg.alert_on_read && !readers.is_empty() {
                // Key the reader memo by the *canonical* path, the same form the
                // holder sweep reports, so the cleanup pass below can match it.
                let seen = self.alerted_readers.entry(key.clone()).or_default();
                let fresh: Vec<(i32, String)> = readers
                    .into_iter()
                    .filter(|(p, _)| !seen.contains(p))
                    .collect();
                if !fresh.is_empty() {
                    for (p, _) in &fresh {
                        seen.insert(*p);
                    }
                    let pids: Vec<i32> = fresh.iter().map(|(p, _)| *p).collect();
                    alerts.push(DecoyAlert {
                        decoy: d.clone(),
                        violation: DecoyViolation::OpenedForRead,
                        detail: format!(
                            "opened for read by {}",
                            fresh
                                .iter()
                                .map(|(p, n)| format!("{}[{}]", n, p))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        pids,
                    });
                }
            }
        }
        // Forget readers that no longer hold anything, so a legitimate viewer
        // that comes back is noticed afresh.
        let live: std::collections::HashSet<PathBuf> = by_path.keys().cloned().collect();
        self.alerted_readers.retain(|p, _| live.contains(p));
        alerts
    }
}

enum IntactError {
    Missing,
    Replaced,
    Modified,
}

/// Decoy body: a plausible-looking document with an embedded canary token.
///
/// The body is ordinary low-entropy text so that it is not itself mistaken for
/// ciphertext, and so that an encryptor treats it like any other document.
fn body_for(name: &str, canary: &str, index: usize) -> Vec<u8> {
    let text = format!(
        "{name}\n\
         =====================================================\n\
         Confidential internal document. Distribution restricted.\n\
         Document reference: {canary}\n\
         Prepared by the finance office for internal planning.\n\
         \n\
         Section 1. Summary\n\
         Revenue for the period is recorded in the attached schedules and\n\
         reconciled against the general ledger at month end. Any variance\n\
         larger than the materiality threshold requires sign-off.\n\
         \n\
         Section 2. Notes\n\
         Figures are unaudited and subject to revision. This file is generated\n\
         for planning purposes only and must not be circulated externally.\n\
         \n\
         canary:{canary}\n\
         index:{index}\n"
    );
    text.into_bytes()
}

fn plant_one(
    dir: &Path,
    names: &[String],
    index: usize,
    watch_cfg: &crate::config::WatchConfig,
) -> std::io::Result<Decoy> {
    let base = names
        .get(index % names.len().max(1))
        .cloned()
        .unwrap_or_else(|| format!("statements-{}.xlsx", index));
    // Never overwrite a real file.
    let mut name = base.clone();
    let mut n = 1;
    while dir.join(&name).exists() {
        let ext = crate::util::ext_lower(Path::new(&name)).unwrap_or_default();
        let stem = crate::util::stem(Path::new(&name));
        name = if ext.is_empty() {
            format!("{}-{}", stem, n)
        } else {
            format!("{}-{}.{}", stem, n, ext)
        };
        n += 1;
        if n > 100 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "cannot find a free decoy name",
            ));
        }
    }
    let path = dir.join(&name);
    let canary = crate::util::random_hex(16);
    let bytes = body_for(&name, &canary, index);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    f.write_all(&bytes)?;
    f.sync_all().ok();
    drop(f);
    // Make it look ordinary: default permissions are fine; avoid touching mtime.
    let meta = std::fs::metadata(&path)?;
    let (dev, ino) = crate::detect::dev_ino(&meta);
    let _ = watch_cfg;
    Ok(Decoy {
        path,
        canary,
        dev,
        ino,
        size: bytes.len() as u64,
        digest: crate::util::sha256_hex(&bytes),
        planted_at: crate::util::now_unix(),
    })
}

/// Adopt an existing file as a decoy by recording its current bytes as the
/// expected state.
fn adopt_existing(path: &Path) -> std::io::Result<Decoy> {
    let bytes = std::fs::read(path)?;
    let meta = std::fs::metadata(path)?;
    let (dev, ino) = crate::detect::dev_ino(&meta);
    Ok(Decoy {
        path: path.to_path_buf(),
        canary: crate::util::sha256_hex(&bytes)[..32].to_string(),
        dev,
        ino,
        size: bytes.len() as u64,
        digest: crate::util::sha256_hex(&bytes),
        planted_at: crate::util::now_unix(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &Path) -> DecoyConfig {
        DecoyConfig {
            enabled: true,
            plant_in_roots: true,
            subdir: String::new(),
            count: 3,
            paths: Vec::new(),
            poll_ms: 10,
            holder_sweep_ms: 50,
            manifest_dir: dir.join("manifest"),
            alert_on_read: true,
            alert_on_remove: true,
            names: vec!["a.xlsx".into(), "b.docx".into()],
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rw-decoy-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn plants_distinct_files_and_reuses_them() {
        let base = tmpdir("plant");
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let c = cfg(&base);
        let w = crate::config::WatchConfig::default();
        let set = DecoySet::setup(&c, std::slice::from_ref(&root), &w).unwrap();
        assert_eq!(set.len(), 3);
        let paths: std::collections::HashSet<_> = set.decoys().map(|d| d.path.clone()).collect();
        assert_eq!(paths.len(), 3);
        for d in set.decoys() {
            let body = std::fs::read(&d.path).unwrap();
            assert!(String::from_utf8_lossy(&body).contains(&d.canary));
            assert_eq!(crate::util::sha256_hex(&body), d.digest);
        }
        drop(set);
        // A second setup must not duplicate or overwrite.
        let set2 = DecoySet::setup(&c, std::slice::from_ref(&root), &w).unwrap();
        assert_eq!(set2.len(), 3);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn detects_rewrite_and_removal_and_replacement() {
        let base = tmpdir("tamper");
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let c = cfg(&base);
        let w = crate::config::WatchConfig::default();
        let mut set = DecoySet::setup(&c, std::slice::from_ref(&root), &w).unwrap();
        let targets: Vec<PathBuf> = set.decoys().map(|d| d.path.clone()).collect();
        assert_eq!(targets.len(), 3);

        assert!(set.check(&targets[0]).is_none());
        // Rewrite bytes, preserving size and forging mtime back.
        let meta = std::fs::metadata(&targets[0]).unwrap();
        let mut bytes = std::fs::read(&targets[0]).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&targets[0], &bytes).unwrap();
        let t = filetime_of(&meta);
        set_mtime(&targets[0], t);
        let a = set.check(&targets[0]).expect("rewrite must alert");
        assert_eq!(a.violation, DecoyViolation::Modified);

        std::fs::remove_file(&targets[1]).unwrap();
        let a = set.check(&targets[1]).expect("removal must alert");
        assert_eq!(a.violation, DecoyViolation::Removed);

        // Replace via delete+create at the same path.
        let orig = std::fs::read(&targets[2]).unwrap();
        std::fs::remove_file(&targets[2]).unwrap();
        std::fs::write(&targets[2], &orig).unwrap();
        let a = set.check(&targets[2]).expect("replacement must alert");
        assert_eq!(a.violation, DecoyViolation::Replaced);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn repeated_different_violations_each_alert() {
        let base = tmpdir("repeat");
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let c = cfg(&base);
        let w = crate::config::WatchConfig::default();
        let mut set = DecoySet::setup(&c, std::slice::from_ref(&root), &w).unwrap();
        let target = set.decoys().next().unwrap().path.clone();
        let _ = &target;

        // 1. Rewrite -> Modified, alerts once.
        std::fs::write(&target, b"tampered").unwrap();
        assert_eq!(
            set.check(&target).map(|a| a.violation),
            Some(DecoyViolation::Modified)
        );
        // 2. Same violation again inside the window -> folded.
        std::fs::write(&target, b"tampered twice").unwrap();
        assert!(set.check(&target).is_none(), "same violation must fold");
        // 3. Delete it -> a *different* violation, must alert despite the window.
        std::fs::remove_file(&target).unwrap();
        assert_eq!(
            set.check(&target).map(|a| a.violation),
            Some(DecoyViolation::Removed),
            "a second, different act of tampering is new evidence"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn detects_open_for_read_by_untrusted() {
        let base = tmpdir("open");
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let c = cfg(&base);
        let w = crate::config::WatchConfig::default();
        let mut set = DecoySet::setup(&c, std::slice::from_ref(&root), &w).unwrap();
        if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
            return;
        }
        let d = set.decoys().next().unwrap().clone();
        let f = std::fs::File::open(&d.path).unwrap();
        // One poll to learn the holder set; our own pid must count as untrusted
        // here because the closure says so explicitly.
        let alerts = set.poll_openers(|pid| Some((false, format!("proc{}", pid))));
        assert!(
            alerts
                .iter()
                .any(|a| a.violation == DecoyViolation::OpenedForRead && a.decoy.path == d.path),
            "expected a read alert for {}, got {alerts:?}",
            d.path.display()
        );
        // The second poll must not repeat an alert for the *same* decoy and the
        // same holder. Other decoys in this test process may be held open by
        // concurrently-running tests, so the assertion is scoped to this decoy.
        let again = set.poll_openers(|pid| Some((false, format!("proc{}", pid))));
        assert!(
            !again
                .iter()
                .any(|a| a.violation == DecoyViolation::OpenedForRead && a.decoy.path == d.path),
            "duplicate alert for {}: {again:?}",
            d.path.display()
        );
        drop(f);
        let _ = d;
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn trusted_holders_do_not_alert() {
        let base = tmpdir("trusted");
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let c = cfg(&base);
        let w = crate::config::WatchConfig::default();
        let mut set = DecoySet::setup(&c, std::slice::from_ref(&root), &w).unwrap();
        if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
            return;
        }
        let d = set.decoys().next().unwrap().clone();
        let f = std::fs::File::open(&d.path).unwrap();
        let alerts = set.poll_openers(|_| Some((true, "backupd".into())));
        assert!(alerts.is_empty(), "{alerts:?}");
        drop(f);
        std::fs::remove_dir_all(&base).ok();
    }

    fn filetime_of(m: &std::fs::Metadata) -> (i64, i64) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            (m.atime(), m.mtime())
        }
        #[cfg(not(unix))]
        {
            let _ = m;
            (0, 0)
        }
    }

    fn set_mtime(p: &Path, (atime, mtime): (i64, i64)) {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
            let times = [
                libc::timeval { tv_sec: atime, tv_usec: 0 },
                libc::timeval { tv_sec: mtime, tv_usec: 0 },
            ];
            unsafe {
                libc::utimes(c.as_ptr(), times.as_ptr());
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (p, atime, mtime);
        }
    }
}
