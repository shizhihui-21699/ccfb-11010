//! Detection logic: turn per-path observations into scored signals.
//!
//! The detector is deliberately pure (no I/O): the engine feeds it
//! `Observation`s and it returns `Signal`s and, when the score crosses the
//! incident threshold, an `Incident`.  That makes thresholds and false-positive
//! behaviour directly unit-testable.
//!
//! Design notes
//! ------------
//! * Every burst signal counts *distinct* paths inside a sliding window, so a
//!   single file written in a loop cannot inflate a count.
//! * Burst signals about rewriting only consider files we had a prior record
//!   for.  A bulk *creation* (git clone, unzip) therefore does not look like
//!   bulk *rewriting*.
//! * High-entropy creations are recognised only when the bytes carry no known
//!   container header, and are weighted lower than plaintext->ciphertext
//!   transitions on existing files.
//! * Compression is structurally excluded: output with a known compressed
//!   header is classified `CompressedContainer` and never enters an entropy
//!   counter.  This is what keeps `gzip`/`zip`/`ditto`/Time Machine from
//!   tripping the detector even though their output is ~8 bits/byte.
//! * Encryption *in place* can be observed twice for one file: an early
//!   partial write classified "opaque" and the completed file classified
//!   high entropy.  A file is credited as ciphertext at most once per
//!   incarnation; `ciphertext_credit_until` tracks that.

use crate::format;
use crate::state::ContentClass;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Observation {
    pub at: Instant,
    pub path: PathBuf,
    pub kind: ObsKind,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ObsKind {
    /// Existing file content changed, with old and new classification.
    ContentChanged {
        old_class: ContentClass,
        new_class: ContentClass,
        old_entropy: Option<f32>,
        new_entropy: Option<f32>,
        /// Size of the file after the change (0 if unknown).
        new_size: u64,
    },
    /// A brand-new path appeared.
    Created {
        class: ContentClass,
        entropy: Option<f32>,
        size: u64,
    },
    /// A path's name changed (paired by inode) to a different extension.
    Renamed {
        from: PathBuf,
        new_ext: Option<String>,
        old_class: ContentClass,
        new_class: ContentClass,
    },
    /// A path was removed / moved out of the tree without a paired rename.
    Removed,
    /// The file's bytes or name match ransom-note language.
    RansomNote {
        name_matched: bool,
        body_matched: bool,
    },
    /// A decoy file was read/written/renamed/deleted.
    DecoyTouched {
        action: DecoyAction,
    },
    /// The extension matches a known ransomware family suffix.
    RansomwareExtension {
        ext: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum DecoyAction {
    Read,
    OpenedForWrite,
    Written,
    Renamed,
    Deleted,
    ContentChanged,
}

impl DecoyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            DecoyAction::Read => "read",
            DecoyAction::OpenedForWrite => "opened-for-write",
            DecoyAction::Written => "written",
            DecoyAction::Renamed => "renamed",
            DecoyAction::Deleted => "deleted",
            DecoyAction::ContentChanged => "content-changed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum SignalKind {
    /// An existing plaintext file became high-entropy bytes (in place).
    PlaintextToCiphertext,
    /// An existing file was rewritten to high-entropy content.
    HighEntropyRewrite,
    /// Many existing files rewritten to high entropy in the window.
    EntropyBurst,
    /// Many new high-entropy, header-less files appeared in the window.
    HighEntropyCreateBurst,
    /// High-entropy creations *plus* removals of the files they replace.
    ReplaceWithCiphertext,
    /// Many existing files had their content changed in the window.
    RewriteBurst,
    /// Many files renamed and the new extensions are dominated by one value.
    BulkExtensionChange,
    /// Many known-ransomware extensions appeared.
    RansomwareExtensionBurst,
    /// Many files deleted/removed in the window.
    DeleteBurst,
    /// A very large number of paths touched at all in the window.
    MassModification,
    /// A ransom note (name and/or body).
    RansomNote,
    /// A decoy file was written, renamed or deleted: direct evidence.
    DecoyTrip,
    /// A decoy file was read by a process that could not be ruled out as an
    /// indexer/backup tool.  Corroborating only.
    DecoyRead,
}

impl SignalKind {
    pub fn weight(&self) -> i32 {
        match self {
            SignalKind::PlaintextToCiphertext => 30,
            SignalKind::HighEntropyRewrite => 20,
            SignalKind::EntropyBurst => 55,
            SignalKind::HighEntropyCreateBurst => 30,
            SignalKind::ReplaceWithCiphertext => 45,
            SignalKind::RewriteBurst => 20,
            SignalKind::BulkExtensionChange => 45,
            SignalKind::RansomwareExtensionBurst => 50,
            SignalKind::DeleteBurst => 10,
            SignalKind::MassModification => 10,
            SignalKind::RansomNote => 50,
            // A written/renamed/deleted decoy is decisive.
            SignalKind::DecoyTrip => 500,
            // A read alone is not; it needs corroboration (see verdict()).
            SignalKind::DecoyRead => 25,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SignalKind::PlaintextToCiphertext => "plaintext_to_ciphertext",
            SignalKind::HighEntropyRewrite => "high_entropy_rewrite",
            SignalKind::EntropyBurst => "entropy_burst",
            SignalKind::HighEntropyCreateBurst => "high_entropy_create_burst",
            SignalKind::ReplaceWithCiphertext => "ciphertext_replacement_burst",
            SignalKind::RewriteBurst => "rewrite_burst",
            SignalKind::BulkExtensionChange => "bulk_extension_change",
            SignalKind::RansomwareExtensionBurst => "ransomware_extension_burst",
            SignalKind::DeleteBurst => "delete_burst",
            SignalKind::MassModification => "mass_modification",
            SignalKind::RansomNote => "ransom_note",
            SignalKind::DecoyTrip => "decoy_trip",
            SignalKind::DecoyRead => "decoy_read",
        }
    }

    /// Signals strong enough on their own to open an incident immediately.
    pub fn is_immediate(&self) -> bool {
        matches!(self, SignalKind::DecoyTrip)
    }

    /// Does this signal count as corroboration for opening an incident?
    pub fn is_primary(&self) -> bool {
        matches!(
            self,
            SignalKind::EntropyBurst
                | SignalKind::RewriteBurst
                | SignalKind::BulkExtensionChange
                | SignalKind::RansomwareExtensionBurst
                | SignalKind::ReplaceWithCiphertext
                | SignalKind::RansomNote
                | SignalKind::DecoyTrip
        )
    }

    /// Is this a per-file detail signal (not worth printing at INFO)?
    pub fn is_detail(&self) -> bool {
        matches!(
            self,
            SignalKind::PlaintextToCiphertext | SignalKind::HighEntropyRewrite
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Signal {
    pub kind: SignalKind,
    #[serde(skip)]
    pub at: Instant,
    /// Human-readable detail, e.g. "37 files -> .locked in 4.2s".
    pub detail: String,
    /// Paths that exemplify the signal (bounded).
    pub sample_paths: Vec<PathBuf>,
    pub count: usize,
}

impl Signal {
    pub fn score(&self) -> i32 {
        let base = self.kind.weight();
        if self.kind.is_immediate() {
            return base;
        }
        // Scale mildly with breadth, saturating at 2x.
        let extra = ((self.count as f32).sqrt() * 2.0) as i32;
        (base + extra).min(base * 2)
    }
}

#[derive(Clone, Debug)]
pub struct Thresholds {
    pub window: Duration,
    pub entropy_burst_files: usize,
    pub rename_burst_files: usize,
    pub mass_touch_files: usize,
    pub ransom_ext_files: usize,
    pub delete_burst_files: usize,
    pub rewrite_burst_files: usize,
    pub create_burst_files: usize,
    /// High-entropy creations that, together with removals, indicate
    /// encrypt-then-delete rather than bulk creation.
    pub replacement_creates: usize,
    pub replacement_deletes: usize,
    pub extension_dominance: f32,
    pub burst_floor: usize,
    pub incident_score: i32,
    pub cooldown: Duration,
    /// Plaintext->ciphertext transitions inside ONE directory that promotes
    /// the burst signal early.
    pub single_rewrite_needs: usize,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(10),
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
            cooldown: Duration::from_secs(30),
            single_rewrite_needs: 3,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Incident {
    #[serde(skip)]
    pub at: Instant,
    pub score: i32,
    pub signals: Vec<Signal>,
    pub top_paths: Vec<PathBuf>,
    /// Rough total size of the files implicated in the incident.  Used to
    /// scale the "who is writing this much" test so a 500 KiB burst can be
    /// attributed just as well as a 5 GiB one.
    pub observed_bytes: u64,
}

struct WindowSet {
    window: Duration,
    /// All touch timestamps per path (for mass-modification counting).
    touches: VecDeque<(Instant, PathBuf)>,
    /// Content rewrites of *existing* files.
    rewrites: VecDeque<(Instant, PathBuf)>,
    /// Plaintext -> high entropy transitions of existing files.
    ciphertext: VecDeque<(Instant, PathBuf)>,
    /// Newly created header-less high-entropy files.
    create_he: VecDeque<(Instant, PathBuf)>,
    /// Renames with their new extension.
    renames: VecDeque<(Instant, PathBuf, Option<String>)>,
    /// Removals.
    removes: VecDeque<(Instant, PathBuf)>,
    /// Ransomware-extension observations.
    ransom_ext: VecDeque<(Instant, PathBuf, String)>,
    /// Running total of implicated file sizes.
    volume: u64,
}

impl WindowSet {
    fn new(window: Duration) -> Self {
        Self {
            window,
            touches: VecDeque::new(),
            rewrites: VecDeque::new(),
            ciphertext: VecDeque::new(),
            create_he: VecDeque::new(),
            renames: VecDeque::new(),
            removes: VecDeque::new(),
            ransom_ext: VecDeque::new(),
            volume: 0,
        }
    }

    fn prune(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window);
        // Volume is a rough magnitude for threshold scaling, not exact
        // accounting: it only needs to stay the same order of magnitude as the
        // burst currently in the window.
        if self.touches.is_empty() {
            self.volume = 0;
        }
        macro_rules! trim {
            ($q:expr) => {
                if let Some(c) = cutoff {
                    while let Some(front) = $q.front() {
                        if front.0 < c {
                            $q.pop_front();
                        } else {
                            break;
                        }
                    }
                }
            };
        }
        trim!(self.touches);
        trim!(self.rewrites);
        trim!(self.ciphertext);
        trim!(self.create_he);
        trim!(self.renames);
        trim!(self.removes);
        trim!(self.ransom_ext);
    }
}

/// Distinct paths from a window queue, bounded to `cap`.
fn collect_distinct<'a>(iter: impl Iterator<Item = &'a PathBuf>, cap: usize) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for p in iter {
        if seen.insert(p) && out.len() < cap {
            out.push(p.clone());
        }
    }
    out
}

struct ActiveSignal {
    signal: Signal,
    refreshed: Instant,
}

pub struct Detector {
    pub thresholds: Thresholds,
    windows: WindowSet,
    /// Latest signal instance per kind, kept for incident aggregation.
    active: HashMap<SignalKind, ActiveSignal>,
    last_incident: Option<Instant>,
    /// Per-directory plaintext->ciphertext timestamps.
    dir_ciphertext: HashMap<PathBuf, VecDeque<(Instant, PathBuf)>>,
    /// When each file's ciphertext credit expires (so a *second* genuine
    /// encryption of the same path much later still counts).
    ciphertext_credit_until: HashMap<PathBuf, Instant>,
    /// Last time each burst kind was raised, to avoid re-emitting every event.
    latched: HashMap<SignalKind, Instant>,
    pub observed: u64,
}

impl Detector {
    pub fn new(thresholds: Thresholds) -> Self {
        let window = thresholds.window;
        Self {
            thresholds,
            windows: WindowSet::new(window),
            active: HashMap::new(),
            last_incident: None,
            dir_ciphertext: HashMap::new(),
            ciphertext_credit_until: HashMap::new(),
            latched: HashMap::new(),
            observed: 0,
        }
    }

    /// Feed one observation.  Returns any signals raised as a side effect.
    pub fn observe(&mut self, obs: &Observation) -> Vec<Signal> {
        self.observed += 1;
        let now = obs.at;
        self.windows.prune(now);
        self.expire(now);
        let mut out = Vec::new();
        self.windows.touches.push_back((now, obs.path.clone()));

        match &obs.kind {
            ObsKind::ContentChanged {
                old_class,
                new_class,
                old_entropy,
                new_entropy,
                new_size,
            } => {
                self.windows.volume = self.windows.volume.saturating_add(*new_size);
                self.windows.rewrites.push_back((now, obs.path.clone()));
                if *new_class == ContentClass::HighEntropy {
                    let was_low = match old_class {
                        ContentClass::Plain => true,
                        ContentClass::Opague => old_entropy.map(|e| e < 6.0).unwrap_or(true),
                        ContentClass::Unsampled => true,
                        _ => false,
                    };
                    if was_low && self.credit_ciphertext(&obs.path, now) {
                        self.windows.ciphertext.push_back((now, obs.path.clone()));
                        self.push_dir(now, &obs.path);
                        out.push(Signal {
                            kind: SignalKind::PlaintextToCiphertext,
                            at: now,
                            detail: format!(
                                "plaintext rewritten to high entropy ({} -> {} bits/byte)",
                                fmt_e(*old_entropy),
                                fmt_e(*new_entropy)
                            ),
                            sample_paths: vec![obs.path.clone()],
                            count: 1,
                        });
                    } else if !was_low {
                        out.push(Signal {
                            kind: SignalKind::HighEntropyRewrite,
                            at: now,
                            detail: format!("rewritten to high entropy ({})", fmt_e(*new_entropy)),
                            sample_paths: vec![obs.path.clone()],
                            count: 1,
                        });
                    }
                }
            }
            ObsKind::Created { class, size, .. } => {
                if *class == ContentClass::HighEntropy {
                    self.windows.volume = self.windows.volume.saturating_add(*size);
                    self.windows.create_he.push_back((now, obs.path.clone()));
                }
            }
            ObsKind::Renamed {
                new_ext,
                old_class,
                new_class,
                ..
            } => {
                // A rename to a new extension is extension-change evidence.
                self.windows
                    .renames
                    .push_back((now, obs.path.clone(), new_ext.clone()));
                // A rename is also a rewrite when the inode was renamed only
                // after its content was replaced by the encryptor.
                if *old_class == ContentClass::Plain && *new_class == ContentClass::HighEntropy {
                    self.windows.rewrites.push_back((now, obs.path.clone()));
                    if self.credit_ciphertext(&obs.path, now) {
                        self.windows.ciphertext.push_back((now, obs.path.clone()));
                        self.push_dir(now, &obs.path);
                    }
                }
            }
            ObsKind::Removed => {
                self.windows.removes.push_back((now, obs.path.clone()));
                self.ciphertext_credit_until.remove(&obs.path);
            }
            ObsKind::RansomNote { .. } => {
                out.push(Signal {
                    kind: SignalKind::RansomNote,
                    at: now,
                    detail: "file matches ransom-note patterns".into(),
                    sample_paths: vec![obs.path.clone()],
                    count: 1,
                });
            }
            ObsKind::DecoyTouched { action } => {
                let kind = if *action == DecoyAction::Read {
                    SignalKind::DecoyRead
                } else {
                    SignalKind::DecoyTrip
                };
                out.push(Signal {
                    kind,
                    at: now,
                    detail: format!("decoy {} ({})", action.as_str(), obs.path.display()),
                    sample_paths: vec![obs.path.clone()],
                    count: 1,
                });
            }
            ObsKind::RansomwareExtension { ext } => {
                self.windows
                    .ransom_ext
                    .push_back((now, obs.path.clone(), ext.clone()));
            }
        }

        out.extend(self.evaluate(now));
        for sig in &out {
            self.record_active(sig.clone(), now);
        }
        out
    }

    /// Credit one path as ciphertext once per incarnation.
    fn credit_ciphertext(&mut self, path: &Path, now: Instant) -> bool {
        match self.ciphertext_credit_until.get(path) {
            Some(&until) if now < until => false,
            _ => {
                self.ciphertext_credit_until
                    .insert(path.to_path_buf(), now + self.thresholds.window);
                true
            }
        }
    }

    fn push_dir(&mut self, now: Instant, path: &Path) {
        if let Some(dir) = path.parent() {
            self.dir_ciphertext
                .entry(dir.to_path_buf())
                .or_default()
                .push_back((now, path.to_path_buf()));
        }
    }

    fn expire(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.thresholds.window);
        self.ciphertext_credit_until
            .retain(|_, until| now < *until);
        self.dir_ciphertext.retain(|_, q| {
            if let Some(c) = cutoff {
                while let Some(front) = q.front() {
                    if front.0 < c {
                        q.pop_front();
                    } else {
                        break;
                    }
                }
            }
            !q.is_empty()
        });
        let keep = self.thresholds.window * 3;
        self.active
            .retain(|_, a| now.duration_since(a.refreshed) < keep);
        self.latched.retain(|_, t| now.duration_since(*t) <= keep);
    }

    fn evaluate(&mut self, now: Instant) -> Vec<Signal> {
        let mut out = Vec::new();
        let cap = 20;

        // --- entropy burst of plaintext -> ciphertext -----------------------
        let cipher_count = distinct_count(&self.windows.ciphertext);
        if cipher_count >= self.thresholds.entropy_burst_files
            && !self.is_latched(SignalKind::EntropyBurst, now)
        {
            out.push(Signal {
                kind: SignalKind::EntropyBurst,
                at: now,
                detail: format!(
                    "{cipher_count} plaintext files rewritten to high entropy in {:.1}s",
                    time_span(&self.windows.ciphertext)
                ),
                sample_paths: collect_distinct(
                    self.windows.ciphertext.iter().map(|(_, p)| p),
                    cap,
                ),
                count: cipher_count,
            });
        }

        // A tight cluster inside one directory: encryptors walk a folder.
        let mut dir_hot: Option<(PathBuf, usize)> = None;
        for (d, q) in &self.dir_ciphertext {
            let n = q.len();
            if n > self.thresholds.single_rewrite_needs
                && dir_hot.as_ref().map(|(_, m)| n > *m).unwrap_or(true)
            {
                dir_hot = Some((d.clone(), n));
            }
        }
        if let Some((dir, n)) = dir_hot {
            if !self.is_latched(SignalKind::EntropyBurst, now) && n >= 4 {
                out.push(Signal {
                    kind: SignalKind::EntropyBurst,
                    at: now,
                    detail: format!(
                        "{n} plaintext files in {} became high entropy",
                        dir.display()
                    ),
                    sample_paths: vec![dir],
                    count: n,
                });
            }
        }

        // --- mass rewrite of existing files ---------------------------------
        let rewrite_count = distinct_count(&self.windows.rewrites);
        if rewrite_count >= self.thresholds.rewrite_burst_files
            && !self.is_latched(SignalKind::RewriteBurst, now)
        {
            out.push(Signal {
                kind: SignalKind::RewriteBurst,
                at: now,
                detail: format!(
                    "{rewrite_count} existing files rewritten in {:.1}s",
                    time_span(&self.windows.rewrites)
                ),
                sample_paths: collect_distinct(self.windows.rewrites.iter().map(|(_, p)| p), cap),
                count: rewrite_count,
            });
        }

        // --- high-entropy creation burst ------------------------------------
        let create_count = distinct_count(&self.windows.create_he);
        if create_count >= self.thresholds.create_burst_files
            && !self.is_latched(SignalKind::HighEntropyCreateBurst, now)
        {
            out.push(Signal {
                kind: SignalKind::HighEntropyCreateBurst,
                at: now,
                detail: format!(
                    "{create_count} new high-entropy files with no recognised container header"
                ),
                sample_paths: collect_distinct(self.windows.create_he.iter().map(|(_, p)| p), cap),
                count: create_count,
            });
        }

        // --- encrypt-then-delete replacement ---------------------------------
        let del_so_far = distinct_count(&self.windows.removes);
        if create_count >= self.thresholds.replacement_creates
            && del_so_far >= self.thresholds.replacement_deletes
            && !self.is_latched(SignalKind::ReplaceWithCiphertext, now)
        {
            out.push(Signal {
                kind: SignalKind::ReplaceWithCiphertext,
                at: now,
                detail: format!(
                    "{create_count} new high-entropy files and {del_so_far} removals in {:.1}s \
                     (encrypt-then-delete pattern)",
                    time_span(&self.windows.removes)
                ),
                sample_paths: collect_distinct(
                    self.windows
                        .create_he
                        .iter()
                        .map(|(_, p)| p)
                        .chain(self.windows.removes.iter().map(|(_, p)| p)),
                    cap,
                ),
                count: create_count.min(del_so_far),
            });
        }

        // --- bulk extension change ------------------------------------------
        if let Some(ext) = self.dominant_rename_extension() {
            let renamed: Vec<PathBuf> = self
                .windows
                .renames
                .iter()
                .filter(|(_, _, e)| e.as_deref() == Some(ext.as_str()))
                .map(|(_, p, _)| p.clone())
                .collect();
            let count = renamed.len();
            let total = distinct_count_paths_ext(&self.windows.renames);
            if count >= self.thresholds.rename_burst_files
                && !self.is_latched(SignalKind::BulkExtensionChange, now)
            {
                out.push(Signal {
                    kind: SignalKind::BulkExtensionChange,
                    at: now,
                    detail: format!(
                        "{count} of {total} renamed files took .{ext} in {:.1}s",
                        time_span_renames(&self.windows.renames)
                    ),
                    sample_paths: renamed.into_iter().take(cap).collect(),
                    count,
                });
            }
        }

        // --- ransomware extensions ------------------------------------------
        let re_count = distinct_count_paths_ext3(&self.windows.ransom_ext);
        if re_count >= self.thresholds.ransom_ext_files
            && !self.is_latched(SignalKind::RansomwareExtensionBurst, now)
        {
            let exts: Vec<String> = self
                .windows
                .ransom_ext
                .iter()
                .map(|(_, _, e)| e.clone())
                .collect();
            out.push(Signal {
                kind: SignalKind::RansomwareExtensionBurst,
                at: now,
                detail: format!(
                    "{re_count} files appeared with ransomware-like extensions ({})",
                    summarize_exts(&exts)
                ),
                sample_paths: collect_distinct(
                    self.windows.ransom_ext.iter().map(|(_, p, _)| p),
                    cap,
                ),
                count: re_count,
            });
        }

        // --- delete burst ----------------------------------------------------
        let del_count = distinct_count(&self.windows.removes);
        if del_count >= self.thresholds.delete_burst_files
            && !self.is_latched(SignalKind::DeleteBurst, now)
        {
            out.push(Signal {
                kind: SignalKind::DeleteBurst,
                at: now,
                detail: format!(
                    "{del_count} files removed in {:.1}s",
                    time_span(&self.windows.removes)
                ),
                sample_paths: collect_distinct(self.windows.removes.iter().map(|(_, p)| p), cap),
                count: del_count,
            });
        }

        // --- mass modification ----------------------------------------------
        let touch_count = distinct_count(&self.windows.touches);
        if touch_count >= self.thresholds.mass_touch_files
            && !self.is_latched(SignalKind::MassModification, now)
        {
            out.push(Signal {
                kind: SignalKind::MassModification,
                at: now,
                detail: format!(
                    "{touch_count} distinct paths modified in {:.1}s",
                    time_span(&self.windows.touches)
                ),
                sample_paths: collect_distinct(self.windows.touches.iter().map(|(_, p)| p), cap),
                count: touch_count,
            });
        }

        out
    }

    fn dominant_rename_extension(&self) -> Option<String> {
        let total = distinct_count_paths_ext(&self.windows.renames);
        if total < self.thresholds.burst_floor {
            return None;
        }
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for (_, _, ext) in &self.windows.renames {
            if let Some(e) = ext {
                *counts.entry(e.as_str()).or_insert(0) += 1;
            }
        }
        let (ext, n) = counts.into_iter().max_by_key(|(_, n)| *n)?;
        let frac = n as f32 / total as f32;
        if frac >= self.thresholds.extension_dominance {
            Some(ext.to_string())
        } else {
            None
        }
    }

    fn is_latched(&self, kind: SignalKind, now: Instant) -> bool {
        match self.latched.get(&kind) {
            Some(t) => now.duration_since(*t) < self.thresholds.window,
            None => false,
        }
    }

    fn record_active(&mut self, sig: Signal, now: Instant) {
        // Burst signals latch for a window; per-file detail signals are
        // recorded but do not reset the burst latches.
        if !sig.kind.is_detail() && !sig.kind.is_immediate() {
            self.latched.insert(sig.kind.clone(), now);
        }
        let kind = sig.kind.clone();
        self.active.insert(
            kind,
            ActiveSignal {
                signal: sig,
                refreshed: now,
            },
        );
    }

    /// Aggregate the currently active signals and decide whether they warrant
    /// an incident.
    pub fn verdict(&self, now: Instant) -> Option<Incident> {
        if self.active.is_empty() {
            return None;
        }
        let mut signals: Vec<Signal> = self.active.values().map(|a| a.signal.clone()).collect();
        signals.sort_by_key(|a| std::cmp::Reverse(a.score()));
        let score: i32 = signals.iter().map(|s| s.score()).sum();
        let immediate = signals.iter().any(|s| s.kind.is_immediate());
        let primary = signals.iter().any(|s| s.kind.is_primary());
        let note_plus_one =
            signals.iter().any(|s| s.kind == SignalKind::RansomNote) && signals.len() >= 2;
        // A decoy *read* is an intrusion signal on its own, but any indexer or
        // backup job can read files.  It opens an incident only together with
        // at least one other signal (typically the encryption burst that
        // follows the probe).  A decoy *write* is immediate.
        let read_plus_one = signals.iter().any(|s| s.kind == SignalKind::DecoyRead)
            && signals.iter().any(|s| s.kind.is_primary());
        if !immediate
            && !note_plus_one
            && !read_plus_one
            && !(primary && score >= self.thresholds.incident_score)
        {
            return None;
        }
        if let Some(last) = self.last_incident {
            if now.duration_since(last) < self.thresholds.cooldown {
                return None;
            }
        }
        let mut top_paths = Vec::new();
        let mut seen = HashSet::new();
        'outer: for s in &signals {
            for p in &s.sample_paths {
                if seen.insert(p.clone()) {
                    top_paths.push(p.clone());
                }
                if top_paths.len() >= 20 {
                    break 'outer;
                }
            }
        }
        Some(Incident {
            at: now,
            score,
            signals,
            top_paths,
            observed_bytes: self.windows.volume,
        })
    }

    /// Mark that an incident was emitted (starts the cool-down).
    pub fn note_incident(&mut self, at: Instant) {
        self.last_incident = Some(at);
        self.active.clear();
    }

    pub fn window_counts(&self) -> WindowCounts {
        WindowCounts {
            touches: distinct_count(&self.windows.touches),
            rewrites: distinct_count(&self.windows.rewrites),
            ciphertext: distinct_count(&self.windows.ciphertext),
            creates_high_entropy: distinct_count(&self.windows.create_he),
            renames: distinct_count_paths_ext(&self.windows.renames),
            removes: distinct_count(&self.windows.removes),
            ransom_extensions: distinct_count_paths_ext3(&self.windows.ransom_ext),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowCounts {
    pub touches: usize,
    pub rewrites: usize,
    pub ciphertext: usize,
    pub creates_high_entropy: usize,
    pub renames: usize,
    pub removes: usize,
    pub ransom_extensions: usize,
}

fn distinct_count(q: &VecDeque<(Instant, PathBuf)>) -> usize {
    q.iter().map(|(_, p)| p).collect::<HashSet<_>>().len()
}

fn distinct_count_paths_ext(q: &VecDeque<(Instant, PathBuf, Option<String>)>) -> usize {
    q.iter().map(|(_, p, _)| p).collect::<HashSet<_>>().len()
}

fn distinct_count_paths_ext3(q: &VecDeque<(Instant, PathBuf, String)>) -> usize {
    q.iter().map(|(_, p, _)| p).collect::<HashSet<_>>().len()
}

fn time_span(q: &VecDeque<(Instant, PathBuf)>) -> f64 {
    match (q.front(), q.back()) {
        (Some(a), Some(b)) => b.0.duration_since(a.0).as_secs_f64(),
        _ => 0.0,
    }
}

fn time_span_renames(q: &VecDeque<(Instant, PathBuf, Option<String>)>) -> f64 {
    match (q.front(), q.back()) {
        (Some(a), Some(b)) => b.0.duration_since(a.0).as_secs_f64(),
        _ => 0.0,
    }
}

fn summarize_exts(exts: &[String]) -> String {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for e in exts {
        *counts.entry(e.as_str()).or_insert(0) += 1;
    }
    let mut v: Vec<(&str, usize)> = counts.into_iter().collect();
    v.sort_by_key(|a| std::cmp::Reverse(a.1));
    v.iter()
        .take(4)
        .map(|(e, n)| format!(".{e} x{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn fmt_e(e: Option<f32>) -> String {
    match e {
        Some(v) => format!("{v:.2}"),
        None => "?".to_string(),
    }
}

/// Convenience: build the classification for freshly sampled content.
pub fn classify(
    format: Option<format::KnownFormat>,
    entropy: f32,
    high_entropy: f32,
) -> ContentClass {
    use format::KnownFormat as F;
    match format {
        Some(f) if f.is_compressed_container() => ContentClass::CompressedContainer,
        Some(F::Utf8Text) | Some(F::Utf16Text) => ContentClass::Plain,
        Some(_) => ContentClass::Binary,
        None => {
            if entropy >= high_entropy {
                ContentClass::HighEntropy
            } else {
                ContentClass::Opague
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: u64) -> Instant {
        // A fixed base instant keeps tests independent of wall-clock.
        static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        *BASE.get_or_init(Instant::now) + Duration::from_millis(n)
    }

    fn det() -> Detector {
        Detector::new(Thresholds::default())
    }

    fn obs(at: Instant, path: &str, kind: ObsKind) -> Observation {
        Observation {
            at,
            path: PathBuf::from(path),
            kind,
        }
    }

    fn rewrite(at: Instant, path: &str) -> Observation {
        obs(
            at,
            path,
            ObsKind::ContentChanged {
                old_class: ContentClass::Plain,
                new_class: ContentClass::HighEntropy,
                old_entropy: Some(4.1),
                new_entropy: Some(7.95),
                new_size: 20_000,
            },
        )
    }

    #[test]
    fn single_rewrite_is_not_an_incident() {
        let mut d = det();
        let sigs = d.observe(&rewrite(t(0), "/w/a.txt"));
        assert!(sigs
            .iter()
            .any(|s| s.kind == SignalKind::PlaintextToCiphertext));
        assert!(d.verdict(t(0)).is_none());
    }

    #[test]
    fn entropy_burst_over_existing_plaintext_fires() {
        let mut d = det();
        for i in 0..8 {
            d.observe(&rewrite(t(i * 100), &format!("/w/dir/note{i}.txt")));
        }
        let inc = d.verdict(t(1000)).expect("incident");
        assert!(inc.score >= 50);
        assert!(inc
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::EntropyBurst));
    }

    #[test]
    fn one_file_written_repeatedly_counts_once() {
        let mut d = det();
        for i in 0..40 {
            d.observe(&rewrite(t(i * 100), "/w/one.txt"));
        }
        assert_eq!(d.window_counts().ciphertext, 1);
        assert!(d.verdict(t(4000)).is_none());
    }

    #[test]
    fn bulk_extension_change_fires() {
        let mut d = det();
        for i in 0..12 {
            d.observe(&obs(
                t(i * 100),
                &format!("/w/doc{i}.txt.locked"),
                ObsKind::Renamed {
                    from: PathBuf::from(format!("/w/doc{i}.txt")),
                    new_ext: Some("locked".into()),
                    old_class: ContentClass::Plain,
                    new_class: ContentClass::HighEntropy,
                },
            ));
        }
        let inc = d.verdict(t(2000)).expect("incident");
        assert!(inc
            .signals
            .iter()
            .any(|s| s.kind == SignalKind::BulkExtensionChange));
    }

    #[test]
    fn scattered_legitimate_renames_do_not_fire() {
        let mut d = det();
        let exts = ["bak", "tmp", "old", "orig", "save", "prev", "v1", "v2"];
        for i in 0..16u64 {
            let ext = exts[(i as usize) % exts.len()];
            d.observe(&obs(
                t(i * 100),
                &format!("/w/x{i}.{ext}"),
                ObsKind::Renamed {
                    from: PathBuf::from(format!("/w/x{i}")),
                    new_ext: Some(ext.into()),
                    old_class: ContentClass::Plain,
                    new_class: ContentClass::Plain,
                },
            ));
        }
        assert!(d.verdict(t(3000)).is_none());
    }

    #[test]
    fn decoy_write_is_immediate() {
        let mut d = det();
        d.observe(&obs(
            t(0),
            "/w/__rw_decoys/payroll.csv",
            ObsKind::DecoyTouched {
                action: DecoyAction::Written,
            },
        ));
        let inc = d.verdict(t(0)).expect("incident");
        assert!(inc.signals.iter().any(|s| s.kind == SignalKind::DecoyTrip));
    }

    #[test]
    fn decoy_read_alone_is_not_an_incident() {
        let mut d = det();
        d.observe(&obs(
            t(0),
            "/w/__rw_decoys/payroll.csv",
            ObsKind::DecoyTouched {
                action: DecoyAction::Read,
            },
        ));
        assert!(d.verdict(t(0)).is_none());
    }

    #[test]
    fn decoy_read_with_encryption_is_an_incident() {
        let mut d = det();
        d.observe(&obs(
            t(0),
            "/w/__rw_decoys/payroll.csv",
            ObsKind::DecoyTouched {
                action: DecoyAction::Read,
            },
        ));
        for i in 0..8 {
            d.observe(&rewrite(t(100 + i * 50), &format!("/w/doc{i}.txt")));
        }
        let inc = d.verdict(t(1000)).expect("incident");
        assert!(inc.signals.iter().any(|s| s.kind == SignalKind::DecoyRead));
    }

    #[test]
    fn ransom_note_opens_incident() {
        let mut d = det();
        d.observe(&obs(
            t(0),
            "/w/HOW_TO_DECRYPT.txt",
            ObsKind::RansomNote {
                name_matched: true,
                body_matched: true,
            },
        ));
        let inc = d.verdict(t(0)).expect("note incident");
        assert!(inc.signals.iter().any(|s| s.kind == SignalKind::RansomNote));
    }

    #[test]
    fn pure_creation_of_many_plaintext_files_is_not_an_incident() {
        // Unzipping a source tree: many plaintext creations, nothing rewritten.
        let mut d = det();
        for i in 0..60 {
            d.observe(&obs(
                t(i * 20),
                &format!("/w/src/file{i}.rs"),
                ObsKind::Created {
                    class: ContentClass::Plain,
                    entropy: Some(4.6),
                    size: 2_000,
                },
            ));
        }
        assert!(
            d.verdict(t(1300)).is_none(),
            "mass creation must not open an incident"
        );
    }

    #[test]
    fn bulk_compressed_output_is_not_an_incident() {
        // gzip/zip/ditto and Time Machine output: high entropy, known header.
        let mut d = det();
        for i in 0..40 {
            d.observe(&obs(
                t(i * 20),
                &format!("/w/archive{i}.gz"),
                ObsKind::Created {
                    class: ContentClass::CompressedContainer,
                    entropy: Some(7.99),
                    size: 10_000,
                },
            ));
            d.observe(&obs(
                t(i * 20 + 5),
                &format!("/w/archive{i}.gz"),
                ObsKind::ContentChanged {
                    old_class: ContentClass::CompressedContainer,
                    new_class: ContentClass::CompressedContainer,
                    old_entropy: Some(7.99),
                    new_entropy: Some(7.99),
                    new_size: 10_000,
                },
            ));
        }
        assert!(d.verdict(t(1000)).is_none());
    }

    #[test]
    fn cooldown_suppresses_repeat_incidents() {
        let mut d = det();
        for i in 0..8 {
            d.observe(&rewrite(t(i * 100), &format!("/w/n{i}.txt")));
        }
        let inc = d.verdict(t(1000)).expect("first incident");
        d.note_incident(inc.at);
        for i in 8..16 {
            d.observe(&rewrite(t(1000 + i * 50), &format!("/w/n{i}.txt")));
        }
        assert!(d.verdict(t(2000)).is_none());
    }

    #[test]
    fn classify_respects_format_headers() {
        assert_eq!(
            classify(Some(format::KnownFormat::Gzip), 7.99, 7.2),
            ContentClass::CompressedContainer
        );
        assert_eq!(
            classify(Some(format::KnownFormat::Utf8Text), 4.5, 7.2),
            ContentClass::Plain
        );
        assert_eq!(classify(None, 7.9, 7.2), ContentClass::HighEntropy);
        assert_eq!(classify(None, 3.0, 7.2), ContentClass::Opague);
    }
}
