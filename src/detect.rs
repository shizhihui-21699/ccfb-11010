//! The detection engine.
//!
//! Every observation reduces to a *signal* with a known weight. An incident is
//! raised only when the accumulated score inside a sliding window clears
//! `min_score` **and** enough distinct files are involved. That conjunction is
//! what keeps a legitimate backup from alarming: it may compress thousands of
//! files in one second, but those outputs are recognised container formats (not
//! `Opaque`), their originals are still present, and no ransom note appears, so
//! the weighted score never accumulates.
//!
//! Signal weights (defaults; see [`crate::config::DetectConfig`]):
//!
//! | signal                                                     | weight |
//! |------------------------------------------------------------|--------|
//! | existing low-entropy file replaced by ciphertext (whole or part) |  5.0 |
//! | document extension stacked under an unknown one (`a.docx.locked`) |  6.0 |
//! | new ciphertext file with a document extension               |  3.0 |
//! | document extension renamed to an unusual extension         |  4.0 |
//! | ransom-note name and/or note language                      |  6.0 |
//! | bulk rename burst (**once per window**)                     |  3.0 |
//! | bulk modify burst (**once per window**)                     |  2.0 |
//!
//! With `min_score = 8.0` no single signal suffices: a lone encrypted document
//! (5.0) needs corroboration, and so does a lone ransom note (6.0) — correct,
//! because real ransomware always produces more than one of these.
//!
//! Burst signals are deliberately counted **once per window, not per file**. A
//! backup, a `git checkout` or a build all rewrite hundreds of files; only the
//! per-file content signals distinguish them, so a burst may nudge the score
//! but can never reach the threshold by itself.
//!
//! Attribution of paths to renames is done with `(device, inode)` rather than
//! trusting the event stream: macOS FSEvents frequently reports a rename as two
//! unrelated events (old name, then new name), so the engine remembers recently
//! vanished `(dev, ino)` pairs and recognises the new name by inode.

use crate::config::{Config, DetectConfig, EntropyConfig};
use crate::entropy::{self, ContentClass, Sample};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalKind {
    /// A decoy file was touched. Weight is `DECOY_WEIGHT`, a sentinel above any
    /// threshold; decoy incidents do not rely on scoring and are always critical.
    DecoyTouch,
    OpaqueRewrite,
    OpaqueNewDocument,
    StackedExtension,
    SuspiciousRename,
    RansomNote,
    BulkRename,
    BulkModify,
}

impl SignalKind {
    /// Burst signals describe the *shape* of activity, not one file. They are
    /// counted once per window and never towards the distinct-file requirement,
    /// because "many files changed" is by itself what a backup and a `git
    /// checkout` also look like.
    pub fn is_burst(self) -> bool {
        matches!(self, SignalKind::BulkRename | SignalKind::BulkModify)
    }

    /// Decoy signals short-circuit scoring entirely.
    pub fn is_decoy(self) -> bool {
        matches!(self, SignalKind::DecoyTouch)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SignalKind::DecoyTouch => "decoy_touch",
            SignalKind::OpaqueRewrite => "opaque_rewrite",
            SignalKind::OpaqueNewDocument => "opaque_new_document",
            SignalKind::StackedExtension => "stacked_extension",
            SignalKind::SuspiciousRename => "suspicious_rename",
            SignalKind::RansomNote => "ransom_note",
            SignalKind::BulkRename => "bulk_rename",
            SignalKind::BulkModify => "bulk_modify",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Signal {
    pub kind: SignalKind,
    pub weight: f64,
    pub path: PathBuf,
    pub detail: String,
}

/// Sentinel weight/score for a decoy trip: comfortably above any threshold and
/// small enough to print without scientific notation.
pub const DECOY_WEIGHT: f64 = 100.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// A decoy was touched: fires immediately, no scoring.
    Decoy,
    /// Accumulated score cleared the threshold with enough distinct files.
    Score,
}

#[derive(Debug, Clone)]
pub struct IncidentDraft {
    pub severity: Severity,
    pub trigger: Trigger,
    pub reason: String,
    pub signals: Vec<Signal>,
    pub distinct_files: usize,
    pub score: f64,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FileState {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime: i64,
    pub h0: f64,
    pub class: ContentClass,
}

#[derive(Debug, Clone)]
struct Vanished {
    at: Instant,
    path: PathBuf,
    dev: u64,
    ino: u64,
    was_textish: bool,
    old_ext: String,
}

pub struct Detector {
    cfg: DetectConfig,
    ent: EntropyConfig,
    /// Prior content state, populated from the start-up scan.
    baseline: HashMap<PathBuf, FileState>,
    /// Live per-path state as observed during the run.
    files: HashMap<PathBuf, FileState>,
    vanished: VecDeque<Vanished>,
    /// Content changes within the bulk window (distinct paths).
    modified: VecDeque<(Instant, PathBuf)>,
    /// Rename events within the bulk window.
    renames: VecDeque<(Instant, PathBuf, String, String)>,
    /// Signals inside the scoring window.
    window: Vec<(Instant, Signal)>,
    /// Extension histogram taken from the baseline; used to judge "unusual here".
    known_exts: HashMap<String, usize>,
}

impl Detector {
    pub fn new(cfg: DetectConfig, ent: EntropyConfig) -> Self {
        Self {
            cfg,
            ent,
            baseline: HashMap::new(),
            files: HashMap::new(),
            vanished: VecDeque::new(),
            modified: VecDeque::new(),
            renames: VecDeque::new(),
            window: Vec::new(),
            known_exts: HashMap::new(),
        }
    }

    pub fn baseline(&self) -> &HashMap<PathBuf, FileState> {
        &self.baseline
    }

    pub fn known_exts(&self) -> &HashMap<String, usize> {
        &self.known_exts
    }

    pub fn record_baseline(&mut self, path: PathBuf, st: FileState) {
        if let Some(ext) = crate::util::ext_lower(&path) {
            *self.known_exts.entry(ext).or_insert(0) += 1;
        }
        self.baseline.insert(path, st);
    }

    // -- window bookkeeping -------------------------------------------------

    fn prune(&mut self, now: Instant) {
        let win = Duration::from_secs(self.cfg.window_secs);
        self.window.retain(|(t, _)| now.saturating_duration_since(*t) <= win);

        let bulk = Duration::from_secs(self.cfg.bulk_window_secs);
        prune_queue(&mut self.modified, now, bulk);
        prune_queue3(&mut self.renames, now, bulk);

        let pair = Duration::from_millis(self.cfg.rename_pair_ms);
        while let Some(v) = self.vanished.front() {
            if now.saturating_duration_since(v.at) > pair {
                self.vanished.pop_front();
            } else {
                break;
            }
        }

        // Bound the per-path map so a long run over a huge tree does not grow
        // without limit. Under pressure the oldest-seen paths are dropped; a
        // dropped path simply looks like a new file if it changes again, which
        // is the safer failure mode (it re-reads content instead of trusting a
        // stale baseline).
        if self.files.len() > 500_000 {
            let mut ages: Vec<(i64, PathBuf)> =
                self.files.iter().map(|(p, s)| (s.mtime, p.clone())).collect();
            ages.sort_by_key(|(m, _)| *m);
            for (_, p) in ages.into_iter().take(self.files.len() - 400_000) {
                self.files.remove(&p);
            }
        }
    }

    fn push_signal(&mut self, now: Instant, sig: Signal) {
        // One instance per (kind, path) per window: repeated FSEvents for the
        // same write must not inflate the score. Burst signals collapse to one
        // instance per kind for the whole window.
        let dup = if sig.kind.is_burst() {
            self.window.iter().position(|(_, s)| s.kind == sig.kind)
        } else {
            self.window
                .iter()
                .position(|(_, s)| s.kind == sig.kind && s.path == sig.path)
        };
        if let Some(i) = dup {
            self.window[i].0 = now;
            self.window[i].1 = sig;
            return;
        }
        self.window.push((now, sig));
    }

    pub fn score(&self) -> f64 {
        let mut per_file: HashMap<&PathBuf, f64> = HashMap::new();
        let mut burst = 0.0f64;
        for (_, s) in &self.window {
            if s.kind.is_burst() || s.kind.is_decoy() {
                burst += s.weight;
                continue;
            }
            let e = per_file.entry(&s.path).or_insert(0.0);
            *e = f64::max(*e, s.weight);
        }
        per_file.values().sum::<f64>() + burst
    }

    pub fn distinct_files(&self) -> usize {
        self.window
            .iter()
            .filter(|(_, s)| !s.kind.is_burst() && !s.kind.is_decoy())
            .map(|(_, s)| &s.path)
            .collect::<HashSet<_>>()
            .len()
    }

    /// A ransom note is a declaration of intent: it lowers the number of files
    /// needed to corroborate, because the note *is* the corroboration. A note on
    /// its own still cannot fire (6.0 < min_score).
    fn has_note(&self) -> bool {
        self.window.iter().any(|(_, s)| s.kind == SignalKind::RansomNote)
    }

    pub fn window_signals(&self) -> Vec<Signal> {
        self.window.iter().map(|(_, s)| s.clone()).collect()
    }

    pub fn recent_modified(&self) -> Vec<PathBuf> {
        self.modified.iter().map(|(_, p)| p.clone()).collect()
    }

    pub fn recent_renames(&self) -> Vec<(String, String, PathBuf)> {
        self.renames
            .iter()
            .map(|(_, p, old, new)| (old.clone(), new.clone(), p.clone()))
            .collect()
    }

    // -- observation --------------------------------------------------------

    /// Observe the current on-disk state of `path`.
    ///
    /// Returns an incident when the window clears the threshold. `now` is passed
    /// in so tests can drive a deterministic clock.
    pub fn observe(&mut self, now: Instant, path: &Path) -> Option<IncidentDraft> {
        self.prune(now);
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => {
                self.on_missing(now, path);
                return None;
            }
        };
        if !meta.file_type().is_file() {
            return None;
        }
        let (dev, ino) = dev_ino(&meta);
        let size = meta.len();
        let mtime = mtime_of(&meta);

        if size < self.ent.min_file_bytes {
            // Too small to judge; still track its identity so a later growth is
            // seen as a change rather than a new file.
            self.files.insert(
                path.to_path_buf(),
                FileState {
                    dev,
                    ino,
                    size,
                    mtime,
                    h0: 0.0,
                    class: ContentClass::Empty,
                },
            );
            return None;
        }

        // Dedupe: identical (dev, ino, size, mtime) means nothing changed since
        // we last looked. This collapses the Create+Modify+Metadata bursts that
        // FSEvents emits for a single write.
        let prior = self.files.get(path).cloned();
        let baseline = self.baseline.get(path).cloned();
        if let Some(p) = &prior {
            if p.dev == dev && p.ino == ino && p.size == size && p.mtime == mtime {
                return None;
            }
        }

        // Sample content. Region-aware so partially-encrypted files are seen.
        let (bytes, _len, regions) = match entropy::read_sample_regions(path, &self.ent) {
            Ok(v) => v,
            Err(_) => return None,
        };
        let sample = entropy::analyze_regions(&bytes, &regions, &self.ent);

        // Was this path just renamed from somewhere else? Match by inode.
        let rename_from = self
            .vanished
            .iter()
            .position(|v| v.dev == dev && v.ino == ino)
            .map(|i| self.vanished.remove(i).expect("index from position"));

        let ext = crate::util::ext_lower(path).unwrap_or_default();
        let mut signals: Vec<Signal> = Vec::new();
        let eligible = sample.bytes >= self.cfg.min_entropy_bytes;

        // Note language is only meaningful for small text files.
        let note_text_hits = if size <= 512 * 1024
            && matches!(sample.class, ContentClass::TextLike | ContentClass::Structured)
            && sample.printable > 0.70
        {
            entropy::note_content_hits(&String::from_utf8_lossy(&bytes))
        } else {
            0
        };

        if let Some(old) = &rename_from {
            self.evaluate_rename(
                &mut signals,
                path,
                &ext,
                old,
                &sample,
                eligible,
                note_text_hits,
            );
        } else {
            self.evaluate_content_change(
                &mut signals,
                path,
                &ext,
                prior.as_ref().or(baseline.as_ref()),
                &sample,
                eligible,
                note_text_hits,
            );
        }

        // Bulk accounting.
        if self.modified.iter().all(|(_, p)| p != path) {
            self.modified.push_back((now, path.to_path_buf()));
        }
        if let Some(old) = &rename_from {
            self.renames
                .push_back((now, old.path.clone(), old.old_ext.clone(), ext.clone()));
            self.push_bulk_signals(now, path, &ext, &old.old_ext, &mut signals);
        } else {
            self.push_bulk_modify(now, path, &mut signals);
        }

        for s in signals {
            self.push_signal(now, s);
        }

        self.files.insert(
            path.to_path_buf(),
            FileState {
                dev,
                ino,
                size,
                mtime,
                h0: sample.h0,
                class: sample.class,
            },
        );

        self.maybe_incident(now)
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_content_change(
        &self,
        signals: &mut Vec<Signal>,
        path: &Path,
        ext: &str,
        prior: Option<&FileState>,
        sample: &Sample,
        eligible: bool,
        note_text_hits: usize,
    ) {
        // 1. An existing low-entropy file replaced by ciphertext.
        let was_low = prior
            .map(|p| p.class.is_textish() && p.h0 < 7.0)
            .unwrap_or(false);
        // A file that is now wholly or partly ciphertext counts; partial
        // encryption is a real ransomware tactic and used to be invisible here.
        if was_low && sample.class.has_ciphertext() && eligible {
            let p = prior.unwrap();
            signals.push(Signal {
                kind: SignalKind::OpaqueRewrite,
                weight: self.cfg.weight_opaque_rewrite,
                path: path.to_path_buf(),
                detail: format!(
                    "was {} (H0={:.2}, {} B) now {} (H0={:.2}, {} B)",
                    p.class.label(),
                    p.h0,
                    p.size,
                    sample.class.label(),
                    sample.h0,
                    sample.bytes
                ),
            });
        }

        // 2. A brand-new file that is opaque and wears a document extension.
        if prior.is_none()
            && sample.class.has_ciphertext()
            && eligible
            && (entropy::is_document_ext(ext) || self.ext_is_novel_here(ext))
        {
            signals.push(Signal {
                kind: SignalKind::OpaqueNewDocument,
                weight: self.cfg.weight_opaque_new_doc,
                path: path.to_path_buf(),
                detail: format!(
                "new {} content (H0={:.2}) under .{}",
                sample.class.label(),
                sample.h0,
                ext
            ),
            });
        }

        // 3. Document extension stacked under an unknown one. This fires on
        //    appearance and on rename, because it is the naming pattern itself
        //    that matters — a backup writes `.gz`, never `report.docx.locked`.
        if let Some((inner, outer)) = entropy::stacked_document_ext(&crate::util::file_name(path))
        {
            signals.push(Signal {
                kind: SignalKind::StackedExtension,
                weight: self.cfg.weight_stacked_ext,
                path: path.to_path_buf(),
                detail: format!(".{} stacked under unknown .{}", inner, outer),
            });
        }

        // 4. Ransom note.
        if let Some(detail) = self.note_signal(path, note_text_hits) {
            signals.push(Signal {
                kind: SignalKind::RansomNote,
                weight: self.cfg.weight_ransom_note,
                path: path.to_path_buf(),
                detail,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_rename(
        &self,
        signals: &mut Vec<Signal>,
        path: &Path,
        new_ext: &str,
        old: &Vanished,
        sample: &Sample,
        eligible: bool,
        note_text_hits: usize,
    ) {
        let old_ext = old.old_ext.as_str();
        let suspicious_target = entropy::is_suspicious_new_ext(new_ext)
            || !entropy::is_known_ext(new_ext);
        let doc_source = entropy::is_document_ext(old_ext);
        let now_opaque = sample.class.has_ciphertext() && eligible;
        // A strong rename: a document leaving its own extension for an unknown
        // one, or a rename that produced ciphertext. A `.docx -> .bak` rename of
        // still-text content is quiet on purpose.
        let strong = (doc_source && suspicious_target)
            || (doc_source && now_opaque)
            || (old.was_textish && now_opaque);
        if strong {
            signals.push(Signal {
                kind: SignalKind::SuspiciousRename,
                weight: self.cfg.weight_suspicious_rename,
                path: path.to_path_buf(),
                detail: format!(
                    ".{} -> .{} (opaque={}, source_textish={})",
                    old_ext, new_ext, now_opaque, old.was_textish
                ),
            });
        }
        // A rename that also encrypted the content earns the rewrite weight on
        // the *new* path, which is a different file identity from any baseline.
        if old.was_textish && now_opaque {
            signals.push(Signal {
                kind: SignalKind::OpaqueRewrite,
                weight: self.cfg.weight_opaque_rewrite,
                path: path.to_path_buf(),
                detail: format!(
                    "rename landed on {} (H0={:.2})",
                    sample.class.label(),
                    sample.h0
                ),
            });
        }
        if let Some(detail) = self.note_signal(path, note_text_hits) {
            signals.push(Signal {
                kind: SignalKind::RansomNote,
                weight: self.cfg.weight_ransom_note,
                path: path.to_path_buf(),
                detail,
            });
        }
    }

    fn push_bulk_modify(&self, now: Instant, path: &Path, signals: &mut Vec<Signal>) {
        let distinct = self
            .modified
            .iter()
            .filter(|(_, p)| p != path)
            .map(|(_, p)| p)
            .collect::<HashSet<_>>()
            .len()
            + 1;
        if distinct >= self.cfg.bulk_modify_files {
            signals.push(Signal {
                kind: SignalKind::BulkModify,
                weight: self.cfg.weight_bulk_modify,
                path: path.to_path_buf(),
                detail: format!(
                    "{} distinct files modified within {}s",
                    distinct, self.cfg.bulk_window_secs
                ),
            });
        }
        let _ = now;
    }

    fn push_bulk_signals(
        &self,
        _now: Instant,
        path: &Path,
        new_ext: &str,
        old_ext: &str,
        signals: &mut Vec<Signal>,
    ) {
        if !entropy::is_document_ext(old_ext) {
            return;
        }
        let distinct = self
            .renames
            .iter()
            .map(|(_, p, _, _)| p)
            .collect::<HashSet<_>>()
            .len();
        if distinct >= self.cfg.bulk_rename_files {
            signals.push(Signal {
                kind: SignalKind::BulkRename,
                weight: self.cfg.weight_bulk_rename,
                path: path.to_path_buf(),
                detail: format!(
                    "{} distinct renames within {}s (latest .{} -> .{})",
                    distinct, self.cfg.bulk_window_secs, old_ext, new_ext
                ),
            });
        }
    }

    fn note_signal(&self, path: &Path, text_hits: usize) -> Option<String> {
        let name = crate::util::file_name(path);
        let name_strength = entropy::note_name_strength(&name);
        // Strong when the name alone is unambiguous, or the name hints and the
        // text confirms, or the text is overwhelming on its own.
        let strong = name_strength >= 2
            || (name_strength >= 1 && text_hits >= 2)
            || text_hits >= 5;
        if !strong {
            return None;
        }
        Some(format!(
            "note-like file {:?}: name_strength={} language_hits={}",
            name, name_strength, text_hits
        ))
    }

    fn ext_is_novel_here(&self, ext: &str) -> bool {
        !entropy::is_known_ext(ext) && self.known_exts.get(ext).copied().unwrap_or(0) == 0
    }

    fn on_missing(&mut self, now: Instant, path: &Path) {
        let prior = self.files.remove(path);
        let base = self.baseline.get(path).cloned();
        if let Some(p) = prior.or(base) {
            let old_ext = crate::util::ext_lower(path).unwrap_or_default();
            self.vanished.push_back(Vanished {
                at: now,
                path: path.to_path_buf(),
                dev: p.dev,
                ino: p.ino,
                was_textish: p.class.is_textish() && p.h0 < 7.0,
                old_ext,
            });
        }
    }

    // -- verdict ------------------------------------------------------------

    fn maybe_incident(&mut self, now: Instant) -> Option<IncidentDraft> {
        let score = self.score();
        let files = self.distinct_files();
        let needed = if self.has_note() { 1 } else { self.cfg.min_files };
        if score < self.cfg.min_score || files < needed {
            return None;
        }
        let severity = severity_for(score, files);
        let signals = self.window_signals();
        let kinds: Vec<&str> = signals.iter().map(|s| s.kind.as_str()).collect();
        let reason = format!(
            "{} signals across {} distinct file(s) within {}s ({:.1} points): {}",
            signals.len(),
            files,
            self.cfg.window_secs,
            score,
            kinds.join(", ")
        );
        // Consume the window: the next incident must rest on new evidence.
        self.window.clear();
        let _ = now;
        Some(IncidentDraft {
            severity,
            trigger: Trigger::Score,
            reason,
            signals,
            distinct_files: files,
            score,
        })
    }
}

fn severity_for(score: f64, files: usize) -> Severity {
    if score >= 20.0 || files >= 10 {
        Severity::Critical
    } else if score >= 12.0 || files >= 5 {
        Severity::High
    } else {
        Severity::Low
    }
}

fn prune_queue(q: &mut VecDeque<(Instant, PathBuf)>, now: Instant, max: Duration) {
    while let Some((t, _)) = q.front() {
        if now.saturating_duration_since(*t) > max {
            q.pop_front();
        } else {
            break;
        }
    }
}

fn prune_queue3(q: &mut VecDeque<(Instant, PathBuf, String, String)>, now: Instant, max: Duration) {
    while let Some((t, _, _, _)) = q.front() {
        if now.saturating_duration_since(*t) > max {
            q.pop_front();
        } else {
            break;
        }
    }
}

pub fn dev_ino(meta: &std::fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        (0, 0)
    }
}

/// Modification time in nanoseconds.
///
/// Nanoseconds, not seconds, because APFS reports true nanosecond mtimes (verified
/// on this machine) and the dedupe key is `(dev, ino, size, mtime)`. With second
/// resolution, two writes inside the same second look identical and the second
/// one is dropped as a duplicate — which would silently skip exactly the rapid
/// rewrites an encryptor produces.
pub fn mtime_of(meta: &std::fs::Metadata) -> i64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let secs = meta.mtime() as i128;
        let nanos = meta.mtime_nsec() as i128;
        (secs * 1_000_000_000 + nanos) as i64
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

// ---------------------------------------------------------------------------
// Baseline scan
// ---------------------------------------------------------------------------

/// Build the prior-content baseline for every root.
pub fn scan_baseline(
    cfg: &Config,
    roots: &[PathBuf],
    det: &mut Detector,
    mut progress: impl FnMut(usize, &Path),
) -> usize {
    let mut scanned = 0usize;
    for root in roots {
        for path in walk_files(root, cfg) {
            if scanned >= cfg.watch.max_scan_files {
                return scanned;
            }
            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() < cfg.entropy.min_file_bytes {
                continue;
            }
            let (dev, ino) = dev_ino(&meta);
            let size = meta.len();
            let mtime = mtime_of(&meta);
            let sample = match entropy::inspect_file(&path, &cfg.entropy) {
                Ok((s, _)) => s,
                Err(_) => continue,
            };
            det.record_baseline(
                path.clone(),
                FileState {
                    dev,
                    ino,
                    size,
                    mtime,
                    h0: sample.h0,
                    class: sample.class,
                },
            );
            scanned += 1;
            if scanned.is_multiple_of(5000) {
                progress(scanned, &path);
            }
        }
    }
    scanned
}

/// Regular files under `root`, honouring exclusions and the scan cap.
pub fn walk_files(root: &Path, cfg: &Config) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for e in rd.flatten() {
            if out.len() >= cfg.watch.max_scan_files {
                return out;
            }
            let path = e.path();
            if is_excluded(&path, cfg) {
                continue;
            }
            let ft = match e.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                if let Ok(m) = e.metadata() {
                    if m.len() >= cfg.entropy.min_file_bytes {
                        out.push(path);
                    }
                }
            }
        }
    }
    out
}

pub fn is_excluded(path: &Path, cfg: &Config) -> bool {
    // An exclusion applies only when it sits inside a configured root. The
    // defaults exclude `/private/var/folders`, and an operator who points
    // --root into a temp directory means it: silently skipping their whole
    // root would be a surprising, invisible failure. An exclusion placed inside
    // a root the operator also configured is honoured, which is the normal
    // case (excluding `~/Documents/Archive` while watching `~/Documents`).
    let applies = |ex: &PathBuf| {
        path.starts_with(ex) && cfg.watch.roots.iter().any(|r| ex.starts_with(r) && ex != r)
    };
    if cfg.watch.exclude_paths.iter().any(applies) {
        return true;
    }
    let name = crate::util::file_name(path);
    cfg.watch
        .exclude_globs
        .iter()
        .any(|g| crate::util::glob_match(g, &name))
}



// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const T0: Duration = Duration::from_secs(1_000_000);

    fn detector() -> Detector {
        let mut d = Detector::new(DetectConfig::default(), EntropyConfig::default());

        d.cfg.min_entropy_bytes = 256;
        d
    }

    fn opaque(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut x: u64 = 0x243f_6a88_85a3_08d3;
        while v.len() < n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.truncate(n);
        v
    }

    fn text(n: usize) -> Vec<u8> {
        let unit = b"the quarterly report records revenue and expenses per department. ";
        let mut v = Vec::with_capacity(n + unit.len());
        while v.len() < n {
            v.extend_from_slice(unit);
        }
        v.truncate(n);
        v
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rw-detect-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn single_encrypted_file_is_not_an_incident() {
        let d = tmpdir("single");
        let p = d.join("a.docx");
        write(&p, &text(4096));
        let mut det = detector();
        // Seed baseline.
        let m = std::fs::metadata(&p).unwrap();
        det.record_baseline(
            p.clone(),
            FileState {
                dev: dev_ino(&m).0,
                ino: dev_ino(&m).1,
                size: m.len(),
                mtime: mtime_of(&m),
                h0: 4.2,
                class: ContentClass::TextLike,
            },
        );
        write(&p, &opaque(4096));
        std::thread::sleep(Duration::from_millis(1100)); // mtime resolution
        let inc = det.observe(Instant::now() + T0, &p);
        assert!(inc.is_none(), "one file must not clear min_files");
        assert!(det.score() >= 5.0);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn mass_encryption_fires_and_classifies() {
        let d = tmpdir("mass");
        let mut det = detector();
        let mut paths = Vec::new();
        for i in 0..6 {
            let p = d.join(format!("doc{i}.docx"));
            write(&p, &text(4096));
            let m = std::fs::metadata(&p).unwrap();
            det.record_baseline(
                p.clone(),
                FileState {
                    dev: dev_ino(&m).0,
                    ino: dev_ino(&m).1,
                    size: m.len(),
                    mtime: mtime_of(&m),
                    h0: 4.0,
                    class: ContentClass::TextLike,
                },
            );
            paths.push(p);
        }
        std::thread::sleep(Duration::from_millis(1100));
        let mut incident = None;
        for (i, p) in paths.iter().enumerate() {
            write(p, &opaque(4096));
            if let Some(inc) = det.observe(Instant::now() + T0 + Duration::from_millis(i as u64 * 10), p) {
                incident = Some(inc);
            }
        }
        let inc = incident.expect("mass encryption must raise an incident");
        assert!(inc.score >= 8.0);
        assert!(inc.distinct_files >= 3);
        assert!(inc.signals.iter().any(|s| s.kind == SignalKind::OpaqueRewrite));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn compression_and_backup_stay_quiet() {
        let d = tmpdir("backup");
        let mut det = detector();
        // Original documents remain, and the tool writes .gz files whose bytes
        // start with the gzip header — exactly what a backup produces.
        for i in 0..12 {
            let src = d.join(format!("doc{i}.txt"));
            write(&src, &text(8192));
            let m = std::fs::metadata(&src).unwrap();
            det.record_baseline(
                src.clone(),
                FileState {
                    dev: dev_ino(&m).0,
                    ino: dev_ino(&m).1,
                    size: m.len(),
                    mtime: mtime_of(&m),
                    h0: 4.4,
                    class: ContentClass::TextLike,
                },
            );
        }
        std::thread::sleep(Duration::from_millis(1100));
        let mut any = None;
        for i in 0..12 {
            let gz = d.join(format!("doc{i}.txt.gz"));
            let mut bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
            bytes.extend_from_slice(&opaque(4096));
            write(&gz, &bytes);
            if let Some(inc) = det.observe(
                Instant::now() + T0 + Duration::from_millis(i * 20),
                &gz,
            ) {
                any = Some(inc);
            }
        }
        assert!(any.is_none(), "a backup writing .gz files must not alarm");
        assert!(det.score() < 8.0, "score was {}", det.score());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn rename_to_unknown_extension_scores() {
        let d = tmpdir("rename");
        let mut det = detector();
        let mut originals = Vec::new();
        for i in 0..8 {
            let p = d.join(format!("report{i}.docx"));
            write(&p, &text(4096));
            let m = std::fs::metadata(&p).unwrap();
            det.record_baseline(
                p.clone(),
                FileState {
                    dev: dev_ino(&m).0,
                    ino: dev_ino(&m).1,
                    size: m.len(),
                    mtime: mtime_of(&m),
                    h0: 4.0,
                    class: ContentClass::TextLike,
                },
            );
            originals.push(p);
        }
        let mut incident = None;
        for (i, p) in originals.iter().enumerate() {
            let to = d.join(format!("report{i}.docx.a1b2c3"));
            // Real rename: the inode survives, which is how the engine pairs the
            // two FSEvents reports.
            std::fs::rename(p, &to).unwrap();
            let now = Instant::now() + T0 + Duration::from_millis(i as u64 * 10);
            det.observe(now, p);
            if let Some(inc) = det.observe(now + Duration::from_millis(1), &to) {
                incident = Some(inc);
            }
        }
        let inc = incident.expect("extension churn + ciphertext must fire");
        assert!(inc.signals.iter().any(|s| s.kind == SignalKind::SuspiciousRename));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn ransom_note_plus_one_encrypted_file_fires() {
        let d = tmpdir("note");
        let mut det = detector();
        let doc = d.join("contract.docx");
        write(&doc, &text(4096));
        let m = std::fs::metadata(&doc).unwrap();
        det.record_baseline(
            doc.clone(),
            FileState {
                dev: dev_ino(&m).0,
                ino: dev_ino(&m).1,
                size: m.len(),
                mtime: mtime_of(&m),
                h0: 4.0,
                class: ContentClass::TextLike,
            },
        );
        std::thread::sleep(Duration::from_millis(1100));
        write(&doc, &opaque(4096));
        let t = Instant::now() + T0;
        det.observe(t, &doc);
        let note = d.join("HOW_TO_RECOVER_FILES.txt");
        write(
            &note,
            b"All your files have been encrypted. Send 2 bitcoin to wallet x. \
              Visit the .onion address for the decryption tool. Do not contact police.",
        );
        let inc = det.observe(t + Duration::from_millis(20), &note);
        let inc = inc.expect("note + encrypted file must fire");
        assert!(inc.signals.iter().any(|s| s.kind == SignalKind::RansomNote));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn plain_note_name_alone_does_not_fire() {
        let d = tmpdir("note-only");
        let mut det = detector();
        // A "readme" file and a few legitimate text edits.
        for name in ["readme.md", "notes.txt", "todo.txt"] {
            write(&d.join(name), b"ordinary documentation text here");
            det.observe(Instant::now() + T0, &d.join(name));
        }
        assert!(det.score() < 8.0, "score {}", det.score());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn text_edits_never_raise_an_incident() {
        let d = tmpdir("edits");
        let mut det = detector();
        let mut incidents = 0;
        for i in 0..40 {
            let p = d.join(format!("note{i}.md"));
            write(&p, format!("# note {i}\nsome prose with words.\n").as_bytes());
            if det.observe(Instant::now() + T0 + Duration::from_millis(i), &p).is_some() {
                incidents += 1;
            }
        }
        // Writing forty text files in quick succession is a burst, so the burst
        // signal may be present, but it must never reach `min_score`.
        assert_eq!(incidents, 0);
        assert!(
            det.score() < det.cfg.min_score,
            "text writes scored {}",
            det.score()
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn explicit_root_beats_default_exclusion() {
        let mut cfg = crate::config::Config::default();
        // Defaults exclude /private/var/folders; a root inside it must still be
        // walked.
        cfg.watch.roots = vec![PathBuf::from("/private/var/folders/x/docs")];
        assert!(!is_excluded(Path::new("/private/var/folders/x/docs/a.txt"), &cfg));
        // An exclusion *inside* the root is still honoured.
        cfg.watch.exclude_paths = vec![PathBuf::from("/private/var/folders/x/docs/Archive")];
        assert!(is_excluded(Path::new("/private/var/folders/x/docs/Archive/a.txt"), &cfg));
        // Exclusions above the root never apply.
        cfg.watch.exclude_paths = vec![PathBuf::from("/private/var/folders")];
        assert!(!is_excluded(Path::new("/private/var/folders/x/docs/a.txt"), &cfg));
        // Globs always apply.
        assert!(is_excluded(Path::new("/private/var/folders/x/docs/a.tmp"), &cfg));
    }

    #[test]
    fn severity_scales() {
        assert_eq!(severity_for(8.0, 3), Severity::Low);
        assert_eq!(severity_for(12.0, 5), Severity::High);
        assert_eq!(severity_for(25.0, 12), Severity::Critical);
        assert_eq!(severity_for(9.0, 10), Severity::Critical);
    }
}
