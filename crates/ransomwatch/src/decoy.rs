//! Decoy ("honeytoken") files.
//!
//! Placement
//! ---------
//! A handful of files with plausible business names are created under each
//! watched root.  Their content is recognisable plaintext so both entropy and
//! content-hash checks are decisive.
//!
//! Detection
//! ---------
//! The kernel gives us three independent tripwires:
//!
//! 1. **FSEvents** reports create/modify/rename/remove on the decoy paths.
//!    This is the primary mechanism and catches writes, renames and deletes.
//! 2. **atime** catches *reads* — which FSEvents does not report.  APFS bumps
//!    atime on read when `atime < mtime`, which is exactly the state we put a
//!    decoy in at creation.  A poller re-stats each decoy and compares.
//! 3. **Content hash** catches a rewrite that preserved size and mtime (some
//!    encryptors try), because the digest will differ.
//!
//! Reads also produce incidental atime bumps from backup tools and
//! Spotlight.  A read of a decoy is therefore reported as a *trip* but is
//! attributed before any process is suspended (see engine/respond); the
//! decoy's own directory is excluded from Spotlight via an xattr, and the
//! poller ignores our own reads.

use crate::detect::DecoyAction;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Debug)]
pub struct DecoyFile {
    pub path: PathBuf,
    pub root: PathBuf,
    /// Sample digest at placement time.
    pub digest: [u8; 16],
    pub size: u64,
    pub placed_at: SystemTime,
    pub placed_instant: Instant,
    /// atime as we last saw it, in nanoseconds.
    pub atime_ns: i128,
    pub mtime_ns: i128,
    pub armed: bool,
    /// Debounce for "touched but nothing observable changed" trips.
    pub last_soft_trip: Option<Instant>,
    /// The decoy was renamed/deleted and needs re-creation.
    pub consumed: bool,
}

pub struct DecoySet {
    pub files: Vec<DecoyFile>,
    by_path: HashMap<PathBuf, usize>,
    /// Extra directory names that should be recognised as decoy paths even if
    /// the file itself is unknown (e.g. an encryptor renamed it already).
    pub decoy_dirs: Vec<PathBuf>,
}

fn atime_mtime(p: &Path) -> Option<(i128, i128, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(p).ok()?;
    Some((
        (m.atime() as i128) * 1_000_000_000 + m.atime_nsec() as i128,
        (m.mtime() as i128) * 1_000_000_000 + m.mtime_nsec() as i128,
        m.size(),
    ))
}

/// Set the macOS "exclude from backup / Spotlight" xattr on a path so the
/// system indexer does not read decoys and trip the atime detector.
pub fn exclude_from_backup_and_indexing(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let Some(c) = std::ffi::CString::new(path.as_os_str().as_bytes()).ok() else {
            return;
        };
        let value = b"com.apple.backupd";
        unsafe {
            libc::setxattr(
                c.as_ptr(),
                c"com.apple.metadata:com_apple_backup_excludeItem".as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
                0,
            );
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
    }
}

/// Backdate atime so that a later read is observable: APFS only refreshes
/// atime when it is older than mtime.
pub fn backdate_atime(path: &Path, days: u64) {
    use filetime::{set_file_times, FileTime};
    let now = SystemTime::now();
    let atime = now - Duration::from_secs(days * 86_400);
    let mtime = now - Duration::from_secs(3 * 86_400);
    let _ = set_file_times(path, FileTime::from_system_time(atime), FileTime::from_system_time(mtime));
}

fn decoy_body(name: &str, bytes: usize) -> Vec<u8> {
    let mut body = String::new();
    body.push_str(&format!(
        "CONFIDENTIAL - {name}\nGenerated for the finance shared drive.\n\n"
    ));
    let lines = [
        "Record ID,Date,Department,Account,Description,Amount,Currency,Approved",
        "1001,2024-01-04,Finance,4100,Quarterly reconciliation,12450.00,USD,yes",
        "1002,2024-01-09,Operations,5200,Vendor invoice,3380.75,USD,yes",
        "1003,2024-01-15,Finance,4100,Payroll accrual,88210.40,USD,no",
        "1004,2024-02-02,Legal,6100,Outside counsel retainer,15000.00,USD,yes",
        "1005,2024-02-11,Finance,4100,Travel reimbursement,842.10,USD,yes",
    ];
    let mut i = 0u64;
    while body.len() < bytes {
        let line = lines[(i as usize) % lines.len()];
        body.push_str(line);
        body.push('\n');
        i += 1;
    }
    body.truncate(bytes);
    body.push('\n');
    body.into_bytes()
}

pub struct PlacementConfig<'a> {
    pub roots: &'a [PathBuf],
    pub count_per_root: usize,
    pub names: &'a [String],
    pub file_bytes: usize,
    pub subdir: &'a str,
    /// Existing decoys from a previous run are adopted rather than recreated.
    pub adopt_existing: bool,
}

/// Create decoys under every root.  Returns the set of files now under guard.
pub fn place(cfg: &PlacementConfig<'_>) -> std::io::Result<DecoySet> {
    let now = Instant::now();
    let mut files = Vec::new();
    let mut decoy_dirs = Vec::new();
    let mut counter = 0usize;

    for root in cfg.roots {
        let dir = if cfg.subdir.is_empty() {
            root.clone()
        } else {
            root.join(cfg.subdir)
        };
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!(
                "ransomwatch: cannot create decoy directory {}: {e}",
                dir.display()
            );
            continue;
        }
        exclude_from_backup_and_indexing(&dir);
        decoy_dirs.push(dir.clone());

        for _ in 0..cfg.count_per_root {
            let name = &cfg.names[counter % cfg.names.len()];
            counter += 1;
            let ext = if counter.is_multiple_of(3) { "csv" } else { "txt" };
            let path = dir.join(format!("{name}.{ext}"));
            if !cfg.adopt_existing || !path.exists() {
                let body = decoy_body(name, cfg.file_bytes.max(1024));
                if let Err(e) = std::fs::write(&path, &body) {
                    eprintln!("ransomwatch: cannot write decoy {}: {e}", path.display());
                    continue;
                }
            }
            exclude_from_backup_and_indexing(&path);
            // Order matters: hashing reads the file, which advances atime, so
            // the digest must be computed *before* the atime snapshot is taken
            // and before the atime is backdated.
            let digest = digest_of(&path).unwrap_or([0u8; 16]);
            backdate_atime(&path, 40);
            let Some((atime_ns, mtime_ns, size)) = atime_mtime(&path) else {
                continue;
            };
            files.push(DecoyFile {
                path,
                root: root.clone(),
                digest,
                size,
                placed_at: SystemTime::now(),
                placed_instant: now,
                atime_ns,
                mtime_ns,
                armed: false,
                last_soft_trip: None,
                consumed: false,
            });
        }
    }

    let mut by_path = HashMap::new();
    for (i, f) in files.iter().enumerate() {
        by_path.insert(f.path.clone(), i);
    }
    Ok(DecoySet {
        files,
        by_path,
        decoy_dirs,
    })
}

fn digest_of(path: &Path) -> Option<[u8; 16]> {
    // Decoys are small; read them fully rather than sampling.
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let d = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    Some(out)
}

/// A single decoy trip.
#[derive(Clone, Debug)]
pub struct Trip {
    pub path: PathBuf,
    pub action: DecoyAction,
    pub detail: String,
    /// A read is an intrusion signal but not proof of encryption; it must be
    /// correlated with other signals before an incident is opened (the
    /// detector encodes this as a `DecoyRead` rather than an immediate trip).
    pub read_only: bool,
}

impl DecoySet {
    pub fn empty() -> Self {
        Self {
            files: Vec::new(),
            by_path: HashMap::new(),
            decoy_dirs: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn contains(&self, path: &Path) -> bool {
        self.by_path.contains_key(path)
            || self
                .decoy_dirs
                .iter()
                .any(|d| path.starts_with(d))
    }

    /// Is this path a decoy file (not just inside the decoy directory)?
    pub fn is_decoy_file(&self, path: &Path) -> bool {
        self.by_path.contains_key(path)
    }

    /// Arm decoys once they have existed for `after`, so filesystem settling
    /// right after creation cannot look like a trip.
    pub fn mark_armed(&mut self, now: Instant, after: Duration) {
        for f in &mut self.files {
            if !f.armed && now.duration_since(f.placed_instant) >= after {
                f.armed = true;
            }
        }
    }

    /// Check a decoy for out-of-band modification.  Called for every FSEvents
    /// touch of a decoy path AND from the poller.
    ///
    /// Returns a trip describing what changed, exactly once per change: the
    /// stored snapshot is updated, so repeated events do not re-fire.
    pub fn check(&mut self, path: &Path, fsevent_says_touched: bool) -> Option<Trip> {
        let idx = *self.by_path.get(path)?;
        let d = &self.files[idx];
        if !d.armed {
            return None;
        }
        let snapshot = (d.digest, d.size, d.atime_ns, d.mtime_ns);
        let Some((atime_ns, mtime_ns, size)) = atime_mtime(path) else {
            // File is gone.
            if fsevent_says_touched {
                let d = &mut self.files[idx];
                d.armed = false;
                d.consumed = true;
                return Some(Trip {
                    path: path.to_path_buf(),
                    action: DecoyAction::Deleted,
                    detail: "decoy file disappeared".into(),
                    read_only: false,
                });
            }
            return None;
        };

        // ── Decide what happened from metadata alone ─────────────────────
        let mut action: Option<(DecoyAction, String)> = None;
        if size != snapshot.1 {
            action = Some((
                DecoyAction::Written,
                format!("size {} -> {} bytes", snapshot.1, size),
            ));
        } else if mtime_ns != snapshot.3 {
            action = Some((
                DecoyAction::Written,
                "mtime changed without size change".into(),
            ));
        } else if fsevent_says_touched {
            // Same size and mtime: to catch a rewrite that preserved both we
            // must hash.  Only do that when the event system told us to look,
            // never on a routine poll, because hashing itself bumps atime.
            if let Some(now_digest) = digest_of(path) {
                if now_digest != snapshot.0 {
                    action = Some((
                        DecoyAction::ContentChanged,
                        "content hash changed with preserved size and mtime".into(),
                    ));
                }
            }
        }
        if action.is_none() && atime_ns > snapshot.2 {
            action = Some((DecoyAction::Read, "atime advanced (file was read)".into()));
        }
        // Note: a bare filesystem event with no observable change is *not*
        // reported.  macOS indexers, antivirus and our own hashing all touch
        // files; treating a touch as a trip is a false-positive machine.  Real
        // writes change size/mtime/digest (above); real reads are caught by
        // the atime rule and attributed before anything is suspended.

        // ── Refresh the snapshot ─────────────────────────────────────────
        // If we hashed, do it *before* re-reading atime, so the atime our own
        // hash advanced is captured as the new baseline and is not seen as a
        // read on the next poll.
        let mut new_digest = snapshot.0;
        if fsevent_says_touched || size != snapshot.1 || mtime_ns != snapshot.3 {
            if let Some(dg) = digest_of(path) {
                new_digest = dg;
            }
        }
        let (final_atime, final_mtime, final_size) =
            atime_mtime(path).unwrap_or((atime_ns, mtime_ns, size));
        {
            let d = &mut self.files[idx];
            d.digest = new_digest;
            d.atime_ns = final_atime;
            d.mtime_ns = final_mtime;
            d.size = final_size;
            if matches!(
                action.as_ref().map(|(a, _)| *a),
                Some(DecoyAction::Deleted) | Some(DecoyAction::Renamed)
            ) {
                d.armed = false;
                d.consumed = true;
            }
        }

        let (action, detail) = action?;
        Some(Trip {
            path: path.to_path_buf(),
            read_only: action == DecoyAction::Read,
            action,
            detail,
        })
    }

    /// Poll every decoy.  This is the only way reads are detected, since the
    /// kernel does not report reads through FSEvents.
    pub fn poll(&mut self) -> Vec<Trip> {
        let mut trips = Vec::new();
        let paths: Vec<PathBuf> = self.files.iter().map(|f| f.path.clone()).collect();
        for p in paths {
            if let Some(t) = self.check(&p, false) {
                trips.push(t);
            }
        }
        trips
    }

    /// Restore decoys that tripped and were disabled, so monitoring continues.
    /// Returns the paths that were reset.
    ///
    /// Decoys that merely age past the arm delay are left alone: rewriting
    /// them on every poll would itself be an endless write loop.
    pub fn restore_tripped(&mut self) -> Vec<PathBuf> {
        let mut reset = Vec::new();
        let now = Instant::now();
        for d in self.files.iter_mut().filter(|d| d.consumed) {
            let name = d
                .path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let body = decoy_body(&name, 48 * 1024);
            if std::fs::write(&d.path, &body).is_err() {
                continue;
            }
            exclude_from_backup_and_indexing(&d.path);
            // Hash before backdating, for the same reason as in place().
            if let Some(dg) = digest_of(&d.path) {
                d.digest = dg;
            }
            backdate_atime(&d.path, 40);
            if let Some((a, m, s)) = atime_mtime(&d.path) {
                d.atime_ns = a;
                d.mtime_ns = m;
                d.size = s;
            }
            d.placed_instant = now;
            d.armed = false;
            d.consumed = false;
            reset.push(d.path.clone());
        }
        reset
    }
}

/// Is this path inside the decoy subdirectory of any watched root?
pub fn looks_like_decoy_dir(path: &Path, subdir: &str) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| s == subdir)
            .unwrap_or(false)
    })
}
