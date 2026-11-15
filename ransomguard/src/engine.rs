//! Detection engine.
//!
//! The watcher feeds debounced filesystem events into [`Engine::ingest`].
//! Every event is classified against an on-disk baseline and pushed into a
//! rolling time window; when the window crosses calibrated thresholds an
//! [`Alert`] is emitted. Canary touches and confirmed ransom notes bypass
//! the windowing entirely and alert immediately.

use crate::config::{Thresholds, SUSPICIOUS_EXTENSIONS};
use crate::entropy::{file_entropy, is_trusted_high_entropy_type, HIGH_ENTROPY_THRESHOLD};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum FsEventKind {
    Created,
    Modified,
    /// `from` is the previous path (the watcher pairs FSEvents rename halves).
    Renamed {
        from: PathBuf,
    },
    Deleted,
}

#[derive(Debug, Clone)]
pub struct FsEvent {
    pub path: PathBuf,
    pub kind: FsEventKind,
    pub ts: i64,
}

#[derive(Debug, Clone)]
pub struct FileBaseline {
    pub size: u64,
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AlertLevel {
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub ts: i64,
    pub level: AlertLevel,
    pub signal: String,
    pub score: u32,
    pub message: String,
    pub evidence: Vec<String>,
    pub metrics: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
struct EventRecord {
    ts: i64,
    path: PathBuf,
    content_change: bool,
    high_entropy: bool,
    entropy_surge: bool,
    trusted_archive: bool,
    extension_swapped: bool,
    suspicious_extension: bool,
}

/// Paths of canary files plus the canary directory prefixes.
#[derive(Debug, Clone, Default)]
pub struct CanarySet {
    pub files: Vec<PathBuf>,
    pub dirs: Vec<PathBuf>,
}

impl CanarySet {
    pub fn contains(&self, path: &Path) -> bool {
        // FSEvents reports real paths while callers may hand us paths
        // through /var -> /private/var-style symlinks; compare canonically.
        let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if self
            .files
            .iter()
            .any(|c| c.canonicalize().unwrap_or_else(|_| c.clone()).eq(&canon))
        {
            return true;
        }
        self.dirs.iter().any(|d| {
            let dc = d.canonicalize().unwrap_or_else(|_| d.clone());
            canon.starts_with(&dc)
        })
    }
}

pub struct Engine {
    pub baselines: HashMap<PathBuf, FileBaseline>,
    pub canaries: CanarySet,
    pub thresholds: Thresholds,
    pub note_name_hints: Vec<String>,
    pub note_content_markers: Vec<String>,
    events: VecDeque<EventRecord>,
    last_fired: HashMap<String, i64>,
    pub alerts: Vec<Alert>,
}

const MAX_EVIDENCE: usize = 20;
const NOTE_READ_LIMIT: u64 = 1024 * 1024;

impl Engine {
    pub fn new(
        baselines: HashMap<PathBuf, FileBaseline>,
        canaries: CanarySet,
        thresholds: Thresholds,
        note_name_hints: Vec<String>,
        note_content_markers: Vec<String>,
    ) -> Self {
        Self {
            baselines,
            canaries,
            thresholds,
            note_name_hints,
            note_content_markers,
            events: VecDeque::new(),
            last_fired: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    /// Main entry point. Returns an alert if one fired (also stored in
    /// `self.alerts`).
    pub fn ingest(&mut self, raw_ev: &FsEvent) -> Option<Alert> {
        // Canonicalize so symlink-prefix differences (e.g. /var vs
        // /private/var on macOS) never break canary or baseline lookups.
        let ev = self.canonical_event(raw_ev);
        let ev = &ev;
        // 1) Canary: any touch is immediately critical.
        if self.canaries.contains(&ev.path) {
            let alert = Alert {
                ts: ev.ts,
                level: AlertLevel::Critical,
                signal: "canary_touched".into(),
                score: 100,
                message: format!(
                    "诱饵文件被触碰: {} — 合法操作绝不会访问 canary",
                    ev.path.display()
                ),
                evidence: vec![ev.path.display().to_string()],
                metrics: vec![("event_kind".into(), format!("{:?}", ev.kind))],
            };
            self.alerts.push(alert.clone());
            self.update_baseline(ev);
            return Some(alert);
        }

        // 2) Ransom note detection. Only a *confirmed* note (or canary)
        //    short-circuits windowing; a name-only suspicion is attached to
        //    the event so the same write still feeds entropy/churn analysis.
        let note_alert = self.detect_note(ev);
        let note_confirmed = note_alert
            .as_ref()
            .is_some_and(|a| a.signal == "ransom_note_confirmed");
        if note_confirmed {
            let alert = note_alert.unwrap();
            self.alerts.push(alert.clone());
            self.update_baseline(ev);
            return Some(alert);
        }

        // 3) Content / extension classification into the rolling window.
        self.record_event(ev);
        self.update_baseline(ev);

        // 4) Window evaluation.
        self.prune(ev.ts);
        let window_alert = self.evaluate(ev.ts);
        match (note_alert, window_alert) {
            (Some(note), None) => {
                self.alerts.push(note.clone());
                Some(note)
            }
            (None, Some(w)) => Some(w),
            // Both fired: surface the stronger window alert but keep both
            // recorded in `self.alerts` for the forensic trail.
            (Some(note), Some(w)) => {
                self.alerts.push(note);
                Some(w)
            }
            (None, None) => None,
        }
    }

    fn detect_note(&self, ev: &FsEvent) -> Option<Alert> {
        if matches!(ev.kind, FsEventKind::Deleted) {
            return None;
        }
        let name = ev
            .path
            .file_name()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())?;
        let name_hint = self
            .note_name_hints
            .iter()
            .any(|h| name.contains(&h.to_ascii_lowercase()));

        let content = self.read_candidate_note(ev, name_hint)?;
        let marker_hits: Vec<&String> = self
            .note_content_markers
            .iter()
            .filter(|m| content.contains(&m.to_ascii_lowercase()))
            .collect();

        if !name_hint && marker_hits.len() < 2 {
            return None;
        }
        if marker_hits.is_empty() {
            // Name looks like a note but content does not confirm it.
            return Some(Alert {
                ts: ev.ts,
                level: AlertLevel::Warning,
                signal: "ransom_note_suspected".into(),
                score: 65,
                message: format!("疑似勒索信文件名: {}", ev.path.display()),
                evidence: vec![ev.path.display().to_string()],
                metrics: vec![],
            });
        }
        Some(Alert {
            ts: ev.ts,
            level: AlertLevel::Critical,
            signal: "ransom_note_confirmed".into(),
            score: 100,
            message: format!("确认勒索信文件: {}", ev.path.display()),
            evidence: vec![ev.path.display().to_string()],
            metrics: vec![(
                "content_markers".into(),
                marker_hits
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            )],
        })
    }

    fn read_candidate_note(&self, ev: &FsEvent, name_hint: bool) -> Option<String> {
        let meta = std::fs::metadata(&ev.path).ok()?;
        if !meta.is_file() || meta.len() > NOTE_READ_LIMIT {
            return None;
        }
        // Only spend a read on hinted names or small files that might be text.
        if !name_hint && meta.len() > 64 * 1024 {
            return None;
        }
        let bytes = std::fs::read(&ev.path).ok()?;
        if bytes.contains(&0u8) {
            return None; // binary
        }
        Some(String::from_utf8_lossy(&bytes).to_ascii_lowercase())
    }

    fn record_event(&mut self, ev: &FsEvent) {
        let meta = std::fs::metadata(&ev.path).ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let is_rename = matches!(ev.kind, FsEventKind::Renamed { .. });
        // A rename is a real change even though the old path no longer has
        // metadata; deletions and missing files do not enter the window.
        let content_change =
            is_rename || (!matches!(ev.kind, FsEventKind::Deleted) && meta.is_some());
        if !content_change {
            return;
        }
        if size < self.thresholds.min_file_size && !is_rename {
            return; // tiny-file noise
        }

        let current_entropy = if matches!(ev.kind, FsEventKind::Deleted) {
            None
        } else {
            file_entropy(&ev.path)
        };

        let old_path = match &ev.kind {
            FsEventKind::Renamed { from } => Some(from.as_path()),
            _ => None,
        };
        let baseline_entropy = old_path
            .and_then(|p| self.baselines.get(p))
            .or_else(|| self.baselines.get(&ev.path))
            .and_then(|b| b.entropy);

        // High entropy either in absolute terms or as a sharp jump from the
        // on-disk baseline (catches files whose encrypted form lands just
        // under the absolute cutoff but clearly diverged from plaintext).
        let high_abs = current_entropy
            .map(|e| e >= self.thresholds.high_entropy)
            .unwrap_or(false);
        let entropy_surge = match (current_entropy, baseline_entropy) {
            (Some(e), Some(b)) => {
                e - b >= self.thresholds.entropy_delta && e >= self.thresholds.high_entropy - 0.8
            }
            _ => false,
        };
        let is_high_entropy = high_abs || entropy_surge;

        let file_name = ev
            .path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let trusted_archive = is_trusted_high_entropy_type(&file_name);

        let (extension_swapped, suspicious_extension) = match &ev.kind {
            FsEventKind::Renamed { from } => {
                let new_ext = ext_of(&ev.path);
                let old_ext = ext_of(from);
                let swapped = new_ext != old_ext;
                let susp = new_ext
                    .map(|e| {
                        SUSPICIOUS_EXTENSIONS
                            .iter()
                            .any(|s| e.eq_ignore_ascii_case(s))
                    })
                    .unwrap_or(false);
                (swapped, susp)
            }
            _ => {
                let susp = ext_of(&ev.path)
                    .map(|e| {
                        SUSPICIOUS_EXTENSIONS
                            .iter()
                            .any(|s| e.eq_ignore_ascii_case(s))
                    })
                    .unwrap_or(false);
                (false, susp)
            }
        };

        self.events.push_back(EventRecord {
            ts: ev.ts,
            path: ev.path.clone(),
            content_change,
            high_entropy: is_high_entropy && !trusted_archive,
            entropy_surge: entropy_surge && !trusted_archive,
            trusted_archive,
            extension_swapped: extension_swapped && !trusted_archive,
            suspicious_extension,
        });
    }

    fn prune(&mut self, now: i64) {
        let cutoff = now - self.thresholds.window_secs;
        while self.events.front().map(|e| e.ts < cutoff).unwrap_or(false) {
            self.events.pop_front();
        }
    }

    fn evaluate(&mut self, now: i64) -> Option<Alert> {
        let t = &self.thresholds;
        let total: usize = self.events.iter().filter(|e| e.content_change).count();
        if total == 0 {
            return None;
        }
        let high: Vec<&EventRecord> = self
            .events
            .iter()
            .filter(|e| e.content_change && e.high_entropy)
            .collect();
        let surge: Vec<&EventRecord> = self
            .events
            .iter()
            .filter(|e| e.content_change && e.entropy_surge)
            .collect();
        let swaps: Vec<&EventRecord> = self.events.iter().filter(|e| e.extension_swapped).collect();
        let suspicious: Vec<&EventRecord> = self
            .events
            .iter()
            .filter(|e| e.suspicious_extension)
            .collect();
        let archives = self.events.iter().filter(|e| e.trusted_archive).count();

        let high_ratio = high.len() as f64 / total as f64;
        let swap_ratio = swaps.len() as f64 / total as f64;

        let entropy_signal =
            high.len() >= t.entropy_event_count && high_ratio >= t.entropy_event_ratio;
        let extension_signal =
            swaps.len() >= t.extension_event_count && swap_ratio >= t.extension_event_ratio;
        let suspicious_burst = suspicious.len() >= 5;

        if !entropy_signal && !extension_signal && !suspicious_burst {
            return None;
        }

        let mut score = 0u32;
        let mut signals: Vec<&str> = vec![];
        if entropy_signal {
            // A broad, ratio-confirmed jump to high-entropy content is the
            // defining ransomware behavior; it is treated as critical on its
            // own, not only when another signal corroborates it.
            score += 85;
            signals.push("entropy_surge");
        }
        if extension_signal {
            score += 60;
            signals.push("extension_churn");
        }
        if suspicious_burst {
            score += 25;
            signals.push("suspicious_extensions");
        }
        let level = if score >= t.score_critical {
            AlertLevel::Critical
        } else {
            AlertLevel::Warning
        };
        let signal_key = signals.join("+");

        // Cooldown: don't re-emit the same signal family within the window.
        if let Some(last) = self.last_fired.get(&signal_key) {
            if now - last < t.cooldown_secs {
                return None;
            }
        }
        self.last_fired.insert(signal_key.clone(), now);

        let mut evidence: Vec<String> = surge
            .iter()
            .chain(swaps.iter())
            .chain(suspicious.iter())
            .map(|e| e.path.display().to_string())
            .collect();
        evidence.sort_unstable();
        evidence.dedup();
        evidence.truncate(MAX_EVIDENCE);

        let alert = Alert {
            ts: now,
            level,
            signal: signal_key,
            score,
            message: format!(
                "窗口 {}s 内: {} 次高熵写入 (占比 {:.0}%), {} 次扩展名变更 (占比 {:.0}%), {} 个可疑后缀",
                t.window_secs,
                high.len(),
                high_ratio * 100.0,
                swaps.len(),
                swap_ratio * 100.0,
                suspicious.len(),
            ),
            evidence,
            metrics: vec![
                ("window_events".into(), total.to_string()),
                ("high_entropy_events".into(), high.len().to_string()),
                ("high_entropy_ratio".into(), format!("{:.2}", high_ratio)),
                ("extension_swaps".into(), swaps.len().to_string()),
                ("suspicious_ext".into(), suspicious.len().to_string()),
                ("trusted_archive_events".into(), archives.to_string()),
            ],
        };
        self.alerts.push(alert.clone());
        Some(alert)
    }

    fn update_baseline(&mut self, ev: &FsEvent) {
        match &ev.kind {
            FsEventKind::Deleted => {
                self.baselines.remove(&ev.path);
            }
            FsEventKind::Renamed { from } => {
                if let Some(old) = self.baselines.remove(from) {
                    self.baselines.insert(ev.path.clone(), old);
                } else if let Ok(meta) = std::fs::metadata(&ev.path) {
                    self.baselines.insert(
                        ev.path.clone(),
                        FileBaseline {
                            size: meta.len(),
                            entropy: file_entropy(&ev.path),
                        },
                    );
                }
            }
            _ => {
                if let Ok(meta) = std::fs::metadata(&ev.path) {
                    if meta.is_file() {
                        self.baselines.insert(
                            ev.path.clone(),
                            FileBaseline {
                                size: meta.len(),
                                entropy: file_entropy(&ev.path),
                            },
                        );
                    }
                }
            }
        }
    }
}

fn ext_of(path: &Path) -> Option<String> {
    path.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
}

impl Engine {
    fn canonical_event(&self, ev: &FsEvent) -> FsEvent {
        let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        let kind = match &ev.kind {
            FsEventKind::Renamed { from } => FsEventKind::Renamed { from: canon(from) },
            other => other.clone(),
        };
        FsEvent {
            path: canon(&ev.path),
            kind,
            ts: ev.ts,
        }
    }
}

/// Used by the calibration harness: what the engine would call high-entropy.
pub fn classify_entropy(e: f64) -> bool {
    e >= HIGH_ENTROPY_THRESHOLD
}
