//! The engine: reconcile filesystem notifications into classified changes,
//! feed them to the detector, and act on incidents.
//!
//! FSEvents is noisy, batched and lossy, and it reports the two halves of a
//! rename as unrelated paths in arbitrary order.  Instead of interpreting
//! event kinds we treat each notification as "this path is dirty" and
//! reconcile it against the knowledge base:
//!
//! ```text
//! dirty path ──stat──▶ exists?
//!                       │ yes ──▶ known? ──no──▶ defer 120ms, then:
//!                       │            │           inode in graveyard?
//!                       │            │             │ yes        │ no
//!                       │            │             ▼            ▼
//!                       │            │          Renamed      Created
//!                       │            └──yes──▶ stat same? ─no─▶ ContentChanged
//!                       │                          │ yes
//!                       │                          ▼
//!                       │                 re-sample; digest changed?
//!                       └ no ──▶ known? ──yes──▶ Removed (grave kept for pairing)
//! ```
//!
//! Deferring unknown inodes is what makes rename pairing order-independent:
//! the rename source's removal arrives during the deferral and buries the
//! inode, so the second pass sees the grave and reports `Renamed` instead of
//! `Created` + `Removed`.

use crate::config::Config;
use crate::decoy::{self, DecoySet, Trip};
use crate::detect::{
    classify, DecoyAction, Detector, Observation, ObsKind, Signal, Thresholds,
};
use crate::entropy::sample_file;
use crate::format;
use crate::respond::{self, ProcSampler, ResponseReport};
use crate::state::{stat, ContentClass, FileMeta, FileRecord, FileStore};
use crate::sys;
use crate::util::display_path;
use crate::watch;
use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// A path queued for reconciliation.
struct Dirty {
    last_event: Instant,
}

/// A new inode we have not yet decided about: `Created`, or the new half of a
/// rename whose source has not been reported yet.
struct Pending {
    seen_at: Instant,
}

pub struct Engine {
    cfg: Config,
    roots: Vec<PathBuf>,
    store: FileStore,
    detector: Detector,
    decoys: DecoySet,
    dirty: HashMap<PathBuf, Dirty>,
    pending: HashMap<PathBuf, Pending>,
    /// Files still being written; re-sampled after they settle.
    settle: HashMap<PathBuf, Instant>,
    /// Decoy paths we rewrote ourselves, and until when events on them are
    /// ours, not an attacker's.
    self_write_quiet: HashMap<PathBuf, Instant>,
    log: EventLog,
    running: Arc<AtomicBool>,
    incidents: u64,
    started: Instant,
    sampler: ProcSampler,
    decoy_trips: Vec<(PathBuf, DecoyAction)>,
    /// Paths we do not want to re-read for a while (huge files).
    sample_backoff: HashMap<PathBuf, Instant>,
    /// Stop after the first incident (scripted testing).
    exit_after_incident: bool,
}

pub struct EventLog {
    file: Option<std::fs::File>,
    jsonl: bool,
    verbose: bool,
}

impl EventLog {
    fn open(cfg: &Config) -> std::io::Result<Self> {
        let file = match &cfg.log.path {
            Some(p) => {
                if let Some(dir) = p.parent() {
                    if !dir.as_os_str().is_empty() {
                        std::fs::create_dir_all(dir)?;
                    }
                }
                Some(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(p)?,
                )
            }
            None => None,
        };
        Ok(Self {
            file,
            jsonl: cfg.log.jsonl,
            verbose: cfg.log.verbose,
        })
    }

    pub fn line(&mut self, level: &str, msg: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z");
        if self.jsonl {
            let v = serde_json::json!({
                "ts": ts.to_string(),
                "level": level,
                "msg": msg,
            });
            if let Some(f) = self.file.as_mut() {
                let _ = writeln!(f, "{}", v);
            }
        } else if let Some(f) = self.file.as_mut() {
            let _ = writeln!(f, "{ts} {level:<7} {msg}");
        }
        let loud = self.verbose || level != "DEBUG";
        if loud {
            eprintln!("{ts} {level:<7} {msg}");
            let _ = std::io::stderr().flush();
        }
    }

    fn signal(&mut self, sig: &Signal, roots: &[PathBuf]) {
        let sample = sig
            .sample_paths
            .iter()
            .take(3)
            .map(|p| display_path(p, roots))
            .collect::<Vec<_>>()
            .join(", ");
        self.line(
            "SIGNAL",
            &format!(
                "{} (+{}) {} [{}]",
                sig.kind.as_str(),
                sig.score(),
                sig.detail,
                sample
            ),
        );
    }
}

impl Engine {
    pub fn new(cfg: Config) -> anyhow::Result<Self> {
        if cfg.watch.paths.is_empty() {
            anyhow::bail!("no watch paths configured");
        }
        for r in &cfg.watch.paths {
            if !r.is_dir() {
                anyhow::bail!("watch path is not a directory: {}", r.display());
            }
        }
        let roots: Vec<PathBuf> = cfg
            .watch
            .paths
            .iter()
            .map(|r| std::fs::canonicalize(r).unwrap_or_else(|_| r.clone()))
            .collect();
        let d = &cfg.detection;
        let thresholds = Thresholds {
            window: d.window.get(),
            entropy_burst_files: d.entropy_burst_files,
            rename_burst_files: d.rename_burst_files,
            mass_touch_files: d.mass_touch_files,
            ransom_ext_files: d.ransom_ext_files,
            delete_burst_files: d.delete_burst_files,
            rewrite_burst_files: d.rewrite_burst_files,
            create_burst_files: d.create_burst_files,
            replacement_creates: d.replacement_creates,
            replacement_deletes: d.replacement_deletes,
            extension_dominance: d.extension_dominance as f32,
            burst_floor: d.burst_floor,
            incident_score: d.incident_score,
            cooldown: Duration::from_secs(d.cooldown_secs),
            single_rewrite_needs: d.entropy_burst_files.max(3),
        };
        let log = EventLog::open(&cfg)?;
        let sampler = ProcSampler::new();
        Ok(Self {
            store: FileStore::new(Duration::from_secs(60)),
            detector: Detector::new(thresholds),
            decoys: DecoySet::empty(),
            roots,
            dirty: HashMap::new(),
            pending: HashMap::new(),
            settle: HashMap::new(),
            self_write_quiet: HashMap::new(),
            log,
            running: Arc::new(AtomicBool::new(true)),
            incidents: 0,
            started: Instant::now(),
            sampler,
            decoy_trips: Vec::new(),
            sample_backoff: HashMap::new(),
            exit_after_incident: false,
            cfg,
        })
    }

    /// Ask the engine to stop once it has responded to its first incident.
    pub fn set_exit_after_incident(&mut self, yes: bool) {
        self.exit_after_incident = yes;
    }

    /// Stop flag shared with signal handlers and tests.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        self.log.line(
            "INFO",
            &format!(
                "ransomwatch {} watching {}",
                env!("CARGO_PKG_VERSION"),
                self.roots
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
        self.log.line(
            "INFO",
            &format!(
                "thresholds: high entropy {:.2} bits/byte, {}-file entropy burst in {:?}; suspend={}",
                self.cfg.detection.high_entropy as f32,
                self.cfg.detection.entropy_burst_files,
                self.cfg.detection.window,
                self.cfg.response.suspend
            ),
        );
        if self.cfg.response.suspend && !sys::is_root() {
            self.log.line(
                "INFO",
                "not root: only processes owned by the current user can be suspended",
            );
        }

        // Decoys before the watcher, so their creation is not seen as activity.
        if self.cfg.decoy.enabled {
            self.place_decoys();
        }

        let (handle, rx) = watch::start(&self.roots)?;

        if self.cfg.scan.baseline_on_start {
            self.baseline();
        }

        let mut last_poll = Instant::now();
        let mut last_prune = Instant::now();
        let mut last_reconcile = Instant::now();
        let mut last_sample = Instant::now() - Duration::from_secs(1);
        let mut last_fd_sweep = Instant::now() - Duration::from_secs(10);

        while self.running.load(Ordering::Relaxed) {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(touch) => {
                    if touch.rescan {
                        self.log
                            .line("WARN", "filesystem events were dropped; rescanning tree");
                        self.rescan_all();
                        continue;
                    }
                    if !self.in_scope(&touch.path) || self.is_ignorable(&touch.path) {
                        continue;
                    }
                    self.mark_dirty(&touch.path, touch.at);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("filesystem watcher stopped unexpectedly");
                }
            }

            let now = Instant::now();
            self.process_dirty(now);
            self.process_pending(now);
            self.process_settle(now);
            self.expire_self_writes(now);

            // Write-rate sampling drives attribution; keep it fresh.  This is
            // one rusage read per pid, a few ms for the whole machine, and it
            // is what lets us name a writer that exits before the response.
            if now.duration_since(last_sample) >= Duration::from_millis(700) {
                last_sample = now;
                self.sampler.sample();
            }
            // The fd sweep is much more expensive (~15 ms on this machine),
            // so it runs less often: it only needs to catch "this pid had a
            // file in the tree open", not every transition.
            if now.duration_since(last_fd_sweep) >= Duration::from_secs(3) {
                last_fd_sweep = now;
                self.sampler.record_open_fds(&self.roots);
            }

            if now.duration_since(last_poll) >= self.cfg.decoy.poll_interval.get() {
                last_poll = now;
                self.poll_decoys(now);
            }

            self.maybe_check_verdict(now);

            if now.duration_since(last_prune) >= Duration::from_secs(30) {
                last_prune = now;
                self.store.purge_graves(now);
                for r in self.roots.clone() {
                    self.store.purge_stale(&r, now, Duration::from_secs(900));
                }
                self.sample_backoff
                    .retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
            }

            if !self.cfg.scan.reconcile_interval.get().is_zero()
                && now.duration_since(last_reconcile) >= self.cfg.scan.reconcile_interval.get()
            {
                last_reconcile = now;
                self.reconcile();
            }
        }

        drop(handle);
        self.log.line(
            "INFO",
            &format!(
                "stopped after {:.0}s; {} observations, {} incident(s)",
                self.started.elapsed().as_secs_f64(),
                self.detector.observed,
                self.incidents
            ),
        );
        Ok(())
    }

    // ---------------------------------------------------------------- scope

    fn in_scope(&self, path: &Path) -> bool {
        self.roots.iter().any(|r| path.starts_with(r))
    }

    /// Ignorable: build outputs, editor temp files, our own evidence.
    fn is_ignorable(&self, path: &Path) -> bool {
        if path.as_os_str().is_empty() {
            return true;
        }
        if let Some(ev) = &self.cfg.response.evidence_dir {
            if path.starts_with(ev) {
                return true;
            }
        }
        let Some(root) = self.roots.iter().find(|r| path.starts_with(r)) else {
            return true;
        };
        // Decoys and their directory are never ignorable.
        if self.decoys.contains(path) {
            return false;
        }
        self.cfg.is_ignored_relative(root, path)
    }

    fn mark_dirty(&mut self, path: &Path, at: Instant) {
        let e = self
            .dirty
            .entry(path.to_path_buf())
            .or_insert(Dirty { last_event: at });
        e.last_event = at;
    }

    // ------------------------------------------------------------ baseline

    fn place_decoys(&mut self) {
        let cfg = decoy::PlacementConfig {
            roots: &self.roots,
            count_per_root: self.cfg.decoy.count_per_root,
            names: &self.cfg.decoy.names,
            file_bytes: self.cfg.decoy.file_bytes,
            subdir: &self.cfg.decoy.subdir,
            adopt_existing: false,
        };
        match decoy::place(&cfg) {
            Ok(set) => {
                let n = set.files.len();
                self.decoys = set;
                self.log.line(
                    "INFO",
                    &format!("placed {n} decoy file(s) under the watched roots"),
                );
            }
            Err(e) => self.log.line("WARN", &format!("decoy placement failed: {e}")),
        }
    }

    fn baseline(&mut self) {
        let now = Instant::now();
        let mut count = 0usize;
        let cfg = self.cfg.sample_config_full();
        'outer: for root in self.roots.clone() {
            for entry in WalkDir::new(&root)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !self.cfg.is_ignored_relative(&root, e.path()))
                .flatten()
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                if self.decoys.is_decoy_file(entry.path()) {
                    continue;
                }
                if count >= self.cfg.scan.baseline_max_files {
                    self.log.line(
                        "WARN",
                        &format!(
                            "baseline stopped at {} files (scan.baseline_max_files)",
                            self.cfg.scan.baseline_max_files
                        ),
                    );
                    break 'outer;
                }
                let path = entry.path().to_path_buf();
                let Some(meta) = stat(&path) else { continue };
                let mut rec = FileRecord::new(meta, now);
                if meta.size <= self.cfg.scan.max_sample_bytes {
                    if let Ok(s) = sample_file(&path, cfg) {
                        rec.entropy = Some(s.entropy);
                        rec.printable = s.printable;
                        rec.format = format::detect(&s.head);
                        rec.digest = s.digest;
                        rec.class =
                            classify(rec.format, s.entropy, self.cfg.detection.high_entropy as f32);
                        rec.last_sample = now;
                    }
                }
                self.store.insert(path, rec);
                count += 1;
            }
        }
        self.log
            .line("INFO", &format!("baseline recorded {count} file(s)"));
    }

    fn rescan_all(&mut self) {
        for r in self.roots.clone() {
            let stale: Vec<PathBuf> = self
                .store
                .files
                .keys()
                .filter(|p| p.starts_with(&r))
                .cloned()
                .collect();
            for p in stale {
                self.store.remove(&p, false, Instant::now());
            }
        }
        self.baseline();
    }

    /// Full walk against the knowledge base; catches events the kernel dropped.
    fn reconcile(&mut self) {
        let now = Instant::now();
        let mut seen: HashSet<PathBuf> = HashSet::new();
        let mut changed = Vec::new();
        for root in self.roots.clone() {
            for entry in WalkDir::new(&root)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !self.cfg.is_ignored_relative(&root, e.path()))
                .flatten()
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path().to_path_buf();
                seen.insert(path.clone());
                let Some(meta) = stat(&path) else { continue };
                match self.store.get(&path) {
                    Some(rec) if rec.meta == meta => {}
                    _ => changed.push(path),
                }
            }
        }
        for p in changed {
            self.mark_dirty(&p, now);
        }
        let known: Vec<PathBuf> = self.store.files.keys().cloned().collect();
        for p in known {
            if !seen.contains(&p) {
                // Only treat as removed if it is still gone right now (the
                // walk and this check race with active writers).
                if stat(&p).is_none() {
                    self.on_removed(&p, now);
                }
            }
        }
    }

    // ----------------------------------------------------------- processing

    fn process_dirty(&mut self, now: Instant) {
        const SETTLE: Duration = Duration::from_millis(120);
        let ready: Vec<PathBuf> = self
            .dirty
            .iter()
            .filter(|(_, d)| now.duration_since(d.last_event) >= SETTLE)
            .map(|(p, _)| p.clone())
            .collect();
        for path in ready {
            self.dirty.remove(&path);
            self.observe_path(&path, now);
        }
    }

    /// Second chance for unknown inodes: by now a rename source has been seen.
    fn process_pending(&mut self, now: Instant) {
        const DEFER: Duration = Duration::from_millis(120);
        let ready: Vec<PathBuf> = self
            .pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.seen_at) >= DEFER)
            .map(|(p, _)| p.clone())
            .collect();
        for path in ready {
            self.pending.remove(&path);
            let Some(meta) = stat(&path) else { continue };
            if self.store.get(&path).is_some() {
                continue;
            }
            self.on_created(&path, meta, now);
        }
    }

    fn process_settle(&mut self, now: Instant) {
        let ready: Vec<PathBuf> = self
            .settle
            .iter()
            .filter(|(_, t)| now.duration_since(**t) >= Duration::from_millis(250))
            .map(|(p, _)| p.clone())
            .collect();
        for path in ready {
            self.settle.remove(&path);
            self.observe_path(&path, now);
        }
    }

    fn expire_self_writes(&mut self, now: Instant) {
        self.self_write_quiet.retain(|_, until| now < *until);
    }

    /// The core reconcile step for one path.
    fn observe_path(&mut self, path: &Path, now: Instant) {
        if !self.in_scope(path) || self.is_ignorable(path) {
            return;
        }
        if self.decoys.contains(path) {
            // Our own decoy maintenance must not look like a trip.
            if self.self_write_quiet.contains_key(path) {
                return;
            }
            self.on_decoy_event(path, now);
            return;
        }

        let prior = self.store.get(path).cloned();
        let meta = stat(path);
        match (meta, prior) {
            (Some(_meta), None) => {
                // Unknown inode: maybe the new half of a rename whose source
                // has not arrived yet.  Decide after a short deferral.
                self.pending
                    .entry(path.to_path_buf())
                    .or_insert(Pending { seen_at: now });
            }
            (Some(meta), Some(prior)) => {
                if prior.meta == meta {
                    // Same stat data.  Re-sample occasionally so a write that
                    // preserved size and mtime is still caught by digest.
                    if now.duration_since(prior.last_sample) > Duration::from_secs(5) {
                        self.resample_and_diff(path, prior, now);
                    }
                } else if prior.meta.key == meta.key {
                    self.on_content_changed(path, prior, meta, now);
                } else {
                    // Replace-and-rename at the same path (editor save).
                    self.store.remove(path, true, now);
                    self.observe_content(path, Some(prior), meta, now);
                }
            }
            (None, Some(_)) => self.on_removed(path, now),
            (None, None) => {}
        }
    }

    /// Re-sample a file whose metadata is unchanged; emits a change if the
    /// content digest moved.
    fn resample_and_diff(&mut self, path: &Path, mut prior: FileRecord, now: Instant) {
        if prior.meta.size > self.cfg.scan.max_sample_bytes {
            return;
        }
        let Ok(s) = sample_file(path, self.cfg.sample_config_full()) else {
            return;
        };
        let old_class = prior.class;
        let old_entropy = prior.entropy;
        if s.digest == prior.digest {
            prior.last_sample = now;
            self.store.insert(path.to_path_buf(), prior);
            return;
        }
        let f = format::detect(&s.head);
        prior.entropy = Some(s.entropy);
        prior.printable = s.printable;
        prior.format = f;
        prior.digest = s.digest;
        prior.class = classify(f, s.entropy, self.cfg.detection.high_entropy as f32);
        prior.last_sample = now;
        let new_class = prior.class;
        self.store.insert(path.to_path_buf(), prior);
        self.emit_content_change(path, old_class, new_class, old_entropy, Some(s.entropy), now);
    }

    fn on_created(&mut self, path: &Path, meta: FileMeta, now: Instant) {
        // Paired rename?
        if let Some(grave) = self.store.take_grave(meta.key, now) {
            if !sys::same_file(&grave.path, path) {
                self.on_renamed(path, grave.path.clone(), grave.record, meta, now);
                return;
            }
        }
        let mut rec = FileRecord::new(meta, now);
        self.maybe_sample(path, &mut rec, now);
        let class = rec.class;
        let entropy = rec.entropy;
        self.store.insert(path.to_path_buf(), rec);

        let mut obs = vec![Observation {
            at: now,
            path: path.to_path_buf(),
            kind: ObsKind::Created {
                class,
                entropy,
                size: rec_size(&self.store, path),
            },
        }];
        self.add_extension_obs(path, class, &mut obs, now);
        self.maybe_add_note(path, &mut obs, now);
        self.feed(obs, now);
    }

    fn on_content_changed(&mut self, path: &Path, prior: FileRecord, meta: FileMeta, now: Instant) {
        self.observe_content(path, Some(prior), meta, now);
    }

    fn observe_content(
        &mut self,
        path: &Path,
        prior: Option<FileRecord>,
        meta: FileMeta,
        now: Instant,
    ) {
        let old_class = prior
            .as_ref()
            .map(|r| r.class)
            .unwrap_or(ContentClass::Unsampled);
        let old_entropy = prior.as_ref().and_then(|r| r.entropy);
        let mut rec = match prior {
            Some(mut r) => {
                r.meta = meta;
                r.last_seen = now;
                r
            }
            None => FileRecord::new(meta, now),
        };

        let backoff = self
            .sample_backoff
            .get(path)
            .map(|t| now.duration_since(*t) < Duration::from_secs(5))
            .unwrap_or(false);
        if !backoff {
            if meta.size > self.cfg.scan.max_sample_bytes {
                self.sample_backoff.insert(path.to_path_buf(), now);
            } else if let Ok(s) = sample_file(path, self.cfg.sample_config_full()) {
                let f = format::detect(&s.head);
                rec.entropy = Some(s.entropy);
                rec.printable = s.printable;
                rec.format = f;
                rec.digest = s.digest;
                rec.class = classify(f, s.entropy, self.cfg.detection.high_entropy as f32);
                rec.last_sample = now;
            }
        }
        rec.last_seen = now;
        let new_class = rec.class;
        let new_entropy = rec.entropy;
        self.store.insert(path.to_path_buf(), rec);
        self.emit_content_change(path, old_class, new_class, old_entropy, new_entropy, now);
    }

    fn emit_content_change(
        &mut self,
        path: &Path,
        old_class: ContentClass,
        new_class: ContentClass,
        old_entropy: Option<f32>,
        new_entropy: Option<f32>,
        now: Instant,
    ) {
        let mut obs = vec![Observation {
            at: now,
            path: path.to_path_buf(),
            kind: ObsKind::ContentChanged {
                old_class,
                new_class,
                old_entropy,
                new_entropy,
                new_size: rec_size(&self.store, path),
            },
        }];
        self.add_extension_obs(path, new_class, &mut obs, now);
        self.maybe_add_note(path, &mut obs, now);
        self.feed(obs, now);
    }

    fn on_renamed(
        &mut self,
        new_path: &Path,
        old_path: PathBuf,
        mut rec: FileRecord,
        meta: FileMeta,
        now: Instant,
    ) {
        let old_class = rec.class;
        let old_entropy = rec.entropy;
        rec.meta = meta;
        rec.last_seen = now;
        rec.renamed_count += 1;
        // An encryptor may write ciphertext and then rename; re-sample.
        self.maybe_sample(new_path, &mut rec, now);
        let new_class = rec.class;
        let new_entropy = rec.entropy;
        self.store.insert(new_path.to_path_buf(), rec);

        let old_ext = old_path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(format::extension_of);
        let new_ext = new_path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(format::extension_of);

        let mut obs = Vec::new();
        if new_ext != old_ext {
            obs.push(Observation {
                at: now,
                path: new_path.to_path_buf(),
                kind: ObsKind::Renamed {
                    from: old_path,
                    new_ext,
                    old_class,
                    new_class,
                },
            });
        } else if old_class != new_class {
            obs.push(Observation {
                at: now,
                path: new_path.to_path_buf(),
                kind: ObsKind::ContentChanged {
                    old_class,
                    new_class,
                    old_entropy,
                    new_entropy,
                    new_size: rec_size(&self.store, new_path),
                },
            });
        }
        self.add_extension_obs(new_path, new_class, &mut obs, now);
        self.maybe_add_note(new_path, &mut obs, now);
        self.feed(obs, now);
    }

    fn on_removed(&mut self, path: &Path, now: Instant) {
        if self.store.get(path).is_none() {
            return;
        }
        self.store.remove(path, true, now);
        self.feed(
            vec![Observation {
                at: now,
                path: path.to_path_buf(),
                kind: ObsKind::Removed,
            }],
            now,
        );
    }

    fn maybe_sample(&mut self, path: &Path, rec: &mut FileRecord, now: Instant) {
        if rec.meta.size > self.cfg.scan.max_sample_bytes {
            return;
        }
        if let Ok(s) = sample_file(path, self.cfg.sample_config_full()) {
            let f = format::detect(&s.head);
            rec.entropy = Some(s.entropy);
            rec.printable = s.printable;
            rec.format = f;
            rec.digest = s.digest;
            rec.class = classify(f, s.entropy, self.cfg.detection.high_entropy as f32);
            rec.last_sample = now;
        }
    }

    fn add_extension_obs(
        &self,
        path: &Path,
        class: ContentClass,
        obs: &mut Vec<Observation>,
        now: Instant,
    ) {
        if class != ContentClass::HighEntropy {
            return;
        }
        if let Some(ext) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(format::extension_of)
        {
            if format::is_ransomware_extension(&ext) {
                obs.push(Observation {
                    at: now,
                    path: path.to_path_buf(),
                    kind: ObsKind::RansomwareExtension { ext },
                });
            }
        }
    }

    /// Append a note observation if the name or body looks like a ransom note.
    /// The caller feeds the full vector exactly once.
    fn maybe_add_note(&mut self, path: &Path, obs: &mut Vec<Observation>, now: Instant) {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        let name_hit = format::looks_like_ransom_note_name(name);
        let body_hit = {
            let known = self.store.get(path);
            let small_text = known
                .map(|r| {
                    r.meta.size <= 64 * 1024
                        && matches!(r.class, ContentClass::Plain | ContentClass::Opague)
                })
                .unwrap_or(false);
            // Only read bodies of small candidate files; reading every file
            // would be expensive and pointless.
            if small_text && (name_hit || known.map(|r| r.meta.size <= 8192).unwrap_or(false)) {
                match std::fs::read(path) {
                    Ok(b) if b.len() <= 64 * 1024 => {
                        format::looks_like_ransom_note_body(&String::from_utf8_lossy(&b))
                    }
                    _ => false,
                }
            } else {
                false
            }
        };
        if name_hit || body_hit {
            obs.push(Observation {
                at: now,
                path: path.to_path_buf(),
                kind: ObsKind::RansomNote {
                    name_matched: name_hit,
                    body_matched: body_hit,
                },
            });
        }
    }

    // -------------------------------------------------------------- decoys

    fn on_decoy_event(&mut self, path: &Path, now: Instant) {
        let Some(trip) = self.decoys.check(path, true) else {
            // FSEvents can report a write before it lands; re-check shortly.
            self.settle.insert(path.to_path_buf(), now);
            return;
        };
        self.handle_trip(trip, now);
    }

    fn poll_decoys(&mut self, now: Instant) {
        self.decoys.mark_armed(now, self.cfg.decoy.arm_after.get());
        for trip in self.decoys.poll() {
            self.handle_trip(trip, now);
        }
        // Restore decoys that were consumed, and remember when we wrote them
        // so our own writes are not mistaken for attacker activity.
        if self.cfg.decoy.enabled && self.decoys.files.iter().any(|f| f.consumed) {
            let reset = self.decoys.restore_tripped();
            for p in &reset {
                self.self_write_quiet
                    .insert(p.clone(), now + self.cfg.decoy.self_write_quiet.get());
            }
            if !reset.is_empty() {
                self.log
                    .line("INFO", &format!("restored {} decoy file(s)", reset.len()));
            }
        }
    }

    fn handle_trip(&mut self, trip: Trip, now: Instant) {
        self.log.line(
            "DECOY",
            &format!(
                "decoy {}: {} ({})",
                trip.path.display(),
                trip.action.as_str(),
                trip.detail
            ),
        );
        self.decoy_trips.push((trip.path.clone(), trip.action));
        if self.decoy_trips.len() > 64 {
            self.decoy_trips.remove(0);
        }
        let enabled = match trip.action {
            DecoyAction::Read => self.cfg.decoy.trip_on_read,
            DecoyAction::OpenedForWrite | DecoyAction::Written | DecoyAction::ContentChanged => {
                self.cfg.decoy.trip_on_write
            }
            DecoyAction::Renamed => self.cfg.decoy.trip_on_rename,
            DecoyAction::Deleted => self.cfg.decoy.trip_on_delete,
        };
        if !enabled {
            return;
        }
        // A read of a decoy is only meaningful if a *suspicious* process did
        // it.  Spotlight, Time Machine, rsync and other indexers read files
        // for a living; if the reader is one of them the trip is dropped.
        if trip.action == DecoyAction::Read {
            match crate::respond::classify_readers(&self.sampler, &self.cfg, &trip.path) {
                crate::respond::ReaderVerdict::BenignOnly => {
                    self.log.line(
                        "DEBUG",
                        &format!(
                            "ignoring decoy read of {} by known benign tooling",
                            trip.path.display()
                        ),
                    );
                    return;
                }
                crate::respond::ReaderVerdict::Suspicious(pids) => {
                    self.log.line(
                        "DECOY",
                        &format!(
                            "decoy {} read by suspicious pid(s) {:?}",
                            trip.path.display(),
                            pids
                        ),
                    );
                }
                crate::respond::ReaderVerdict::Unknown => {}
            }
        }
        self.feed(
            vec![Observation {
                at: now,
                path: trip.path,
                kind: ObsKind::DecoyTouched {
                    action: trip.action,
                },
            }],
            now,
        );
    }

    // ------------------------------------------------------------ detector

    fn feed(&mut self, obs: Vec<Observation>, now: Instant) {
        let mut signals = Vec::new();
        for o in &obs {
            signals.extend(self.detector.observe(o));
        }
        for s in &signals {
            if s.kind.is_detail() {
                self.log
                    .line("DEBUG", &format!("{} {}", s.kind.as_str(), s.detail));
            } else {
                let roots = self.roots.clone();
                self.log.signal(s, &roots);
            }
        }
        self.maybe_check_verdict(now);
    }

    fn maybe_check_verdict(&mut self, now: Instant) {
        let Some(incident) = self.detector.verdict(now) else {
            return;
        };
        self.detector.note_incident(now);
        self.incidents += 1;
        self.log.line(
            "INCIDENT",
            &format!(
                "ransomware-like activity detected (score {}): {}",
                incident.score,
                incident
                    .signals
                    .iter()
                    .map(|s| s.kind.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
        for s in &incident.signals {
            let roots = self.roots.clone();
            self.log.signal(s, &roots);
        }
        // The write-rate snapshot tells us which process is writing right now;
        // the decoy trip tells us which one read the honeytoken.
        let report: ResponseReport = respond::respond(
            &incident,
            &self.roots,
            &self.cfg,
            &self.decoy_trips,
            &self.sampler,
        );
        self.log.line(
            "RESPONSE",
            &format!(
                "{} suspect(s); suspended={}; evidence={}",
                report.suspects.len(),
                report.suspended,
                report
                    .evidence_dir
                    .clone()
                    .unwrap_or_else(|| "-".into())
            ),
        );
        if report.suspects.is_empty() {
            self.log.line(
                "WARN",
                "no process could be attributed to this incident; nothing was suspended",
            );
        }
        for a in &report.actions {
            self.log.line(
                if a.ok { "ACTION" } else { "ACTION-FAILED" },
                &format!(
                    "{} pid {} ({}): {}{}",
                    a.action,
                    a.pid,
                    a.name,
                    if a.ok { "ok" } else { "failed" },
                    a.error
                        .as_ref()
                        .map(|e| format!(" ({e})"))
                        .unwrap_or_default()
                ),
            );
        }
        if let Some(dir) = report.evidence_dir {
            self.log
                .line("INFO", &format!("evidence bundle written to {dir}"));
        }
        if self.exit_after_incident {
            self.running.store(false, Ordering::Relaxed);
        }
    }
}

fn rec_size(store: &FileStore, path: &Path) -> u64 {
    store.get(path).map(|r| r.meta.size).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg_for(dir: &Path) -> Config {
        let mut c = Config::default();
        c.watch.paths = vec![dir.to_path_buf()];
        c.decoy.enabled = false;
        c.scan.baseline_on_start = false;
        c.scan.reconcile_interval = crate::config::HumanDuration::secs(3600);
        c.response.suspend = false;
        c
    }

    fn encrypt_in_place(path: &Path) {
        let mut buf = vec![0u8; 20_000];
        let mut x: u64 = 7;
        for b in buf.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x >> 24) as u8;
        }
        std::fs::write(path, &buf).unwrap();
    }

    #[test]
    fn detects_in_place_mass_encryption() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        for i in 0..30 {
            std::fs::write(
                root.join("docs").join(format!("report{i}.txt")),
                "Quarterly numbers and commentary for the team.\n".repeat(50),
            )
            .unwrap();
        }
        let mut e = Engine::new(cfg_for(&root)).unwrap();
        e.baseline();
        let root = e.roots[0].clone();
        for i in 0..30 {
            let p = root.join("docs").join(format!("report{i}.txt"));
            encrypt_in_place(&p);
            e.observe_path(&p, Instant::now());
        }
        assert!(e.incidents >= 1, "expected an incident");
    }

    #[test]
    fn ignores_gzip_output() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::write(root.join("data.txt"), "text data ".repeat(4000)).unwrap();
        let mut e = Engine::new(cfg_for(&root)).unwrap();
        e.baseline();
        let root = e.roots[0].clone();
        for i in 0..20 {
            let p = root.join(format!("data{i}.txt.gz"));
            let mut buf = vec![0x1f, 0x8b, 0x08, 0x00];
            buf.extend(std::iter::repeat(0x5a).take(10_000));
            std::fs::write(&p, &buf).unwrap();
            e.observe_path(&p, Instant::now());
        }
        assert_eq!(e.incidents, 0);
    }
}
