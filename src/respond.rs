//! Response: identify the suspect, preserve the scene, suspend.
//!
//! Order matters and is deliberate:
//!
//! 1. **Capture** — read `/proc`-equivalent process metadata and open-file
//!    attribution *while the suspect is still running*. A suspended process
//!    still shows its fds, but a process that notices the alert and exits takes
//!    everything with it, so capture first.
//! 2. **Record** — write `incident.json` / `incident.txt` / `processes.json` and
//!    copy evidence. If the machine dies during suspension, the record exists.
//! 3. **Suspend** — SIGSTOP the suspect (and optionally its subtree). Suspension
//!    rather than SIGKILL is what preserves the scene: the process keeps its
//!    memory, its open handles and its children, and an operator can decide
//!    whether to inspect, dump, or resume it.
//!
//! Trust gates suspension, never alerting. A trusted tool that somehow touches a
//! decoy still produces a critical record; it is simply not frozen. That is the
//! one place where "don't break backups" and "stop the encryptor" genuinely pull
//! in opposite directions, and freezing a backup agent mid-write would itself be
//! destructive.

use crate::attr;
use crate::config::{Config, ResponseMode};
use crate::decoy::DecoyAlert;
use crate::detect::{IncidentDraft, Trigger};
use crate::entropy;
use crate::forensics::{
    self, CaptureContext, DecoyRecord, FileRecord, Forensics, IncidentRecord, ProcessRecord,
};
use crate::procinfo::{ProcInfo, ProcTable, Trust};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::path::{Path, PathBuf};

/// What the response layer did, for logging and for the record.
#[derive(Debug)]
pub struct Outcome {
    pub record: IncidentRecord,
    pub record_dir: PathBuf,
    pub suspended: Vec<i32>,
    pub failed: Vec<(i32, String)>,
    pub console: String,
}

pub struct Responder {
    cfg: Config,
    table: ProcTable,
    /// Optional background fd sweep. When present, attribution also considers
    /// who held the file a second or two ago, because a fast encryptor closes its
    /// fd before the alert is raised.
    tracker: Option<Arc<crate::attr::HolderTracker>>,
}

impl Responder {
    pub fn new(cfg: Config) -> Self {
        let table = ProcTable::new(cfg.trust.clone());
        Self {
            cfg,
            table,
            tracker: None,
        }
    }

    pub fn with_tracker(mut self, tracker: Arc<crate::attr::HolderTracker>) -> Self {
        self.tracker = Some(tracker);
        self
    }

    pub fn table(&self) -> &ProcTable {
        &self.table
    }

    pub fn table_mut(&mut self) -> &mut ProcTable {
        &mut self.table
    }

    /// Is `pid` trusted to touch watched files? Returned as (trusted, reason).
    pub fn trust_of(&self, pid: i32, io_ext: Option<&str>) -> (bool, String) {
        match self.table.lookup(pid) {
            Some(p) => {
                let t = self.table.classify(
                    pid,
                    &p.name,
                    p.exe.as_deref(),
                    p.signing.as_ref(),
                    io_ext,
                );
                (t != Trust::Untrusted, format!("{:?} ({})", t, p.short()))
            }
            None => (false, "unknown process".into()),
        }
    }

    /// Handle a scored incident: attribute, capture, record, suspend.
    pub fn handle_scored(
        &mut self,
        draft: &IncidentDraft,
        roots: &[PathBuf],
        extra_paths: &[PathBuf],
    ) -> std::io::Result<Outcome> {
        self.table.refresh();
        let implicated: Vec<PathBuf> = {
            let mut v: Vec<PathBuf> = draft.signals.iter().map(|s| s.path.clone()).collect();
            v.extend(extra_paths.iter().cloned());
            dedupe(&mut v);
            v
        };
        let (suspects, held) = self.find_suspects(&implicated);
        let ctx = self.capture_ctx(roots, &suspects, &held, &implicated, None);
        self.finish(draft, ctx, suspects)
    }

    /// Handle a decoy alert: always critical, always attributed, and suspension
    /// ignores the "score" gate entirely.
    pub fn handle_decoy(
        &mut self,
        alert: &DecoyAlert,
        roots: &[PathBuf],
    ) -> std::io::Result<Outcome> {
        self.table.refresh();
        let implicated = vec![alert.decoy.path.clone()];
        // Prefer the pids the fd poller already saw; fall back to attribution.
        let mut suspects: Vec<ProcInfo> = Vec::new();
        let mut held: HashMap<i32, Vec<String>> = HashMap::new();
        for pid in &alert.pids {
            if let Some(p) = self.table.lookup(*pid) {
                held.entry(*pid).or_default().push(alert.decoy.path.display().to_string());
                suspects.push(p);
            }
        }
        let (extra, extra_held) = self.find_suspects(&implicated);
        for p in extra {
            if !suspects.iter().any(|s| s.pid == p.pid) {
                suspects.push(p);
            }
        }
        for (k, v) in extra_held {
            held.entry(k).or_default().extend(v);
        }

        let decoy_rec = DecoyRecord {
            path: alert.decoy.path.display().to_string(),
            canary: alert.decoy.canary.clone(),
            violation: alert.violation.as_str().into(),
            detail: alert.detail.clone(),
        };
        let draft = IncidentDraft {
            severity: crate::detect::Severity::Critical,
            trigger: Trigger::Decoy,
            reason: format!(
                "decoy file {} tripped: {}",
                alert.decoy.path.display(),
                alert.detail
            ),
            signals: draft_decoy_signals(alert),
            distinct_files: 1,
            score: crate::detect::DECOY_WEIGHT,
        };
        let ctx = self.capture_ctx(roots, &suspects, &held, &implicated, Some(decoy_rec));
        self.finish(&draft, ctx, suspects)
    }

    /// Find processes holding any implicated file, ranked, expanded to their
    /// subtrees. Returns (process infos, pid -> held paths) for the *primary*
    /// suspect and its descendants only.
    pub fn find_suspects(
        &self,
        implicated: &[PathBuf],
    ) -> (Vec<crate::procinfo::ProcInfo>, HashMap<i32, Vec<String>>) {
        // Give the caller one more chance to catch a live holder: the incident is
        // raised right after a write, and on a fast machine the fd may still be
        // open. This is cheap (~40 ms) and happens at most once per incident.
        let wanted: HashSet<PathBuf> = implicated.iter().cloned().collect();
        let mut counts: HashMap<i32, usize> = HashMap::new();
        let mut held_by_pid: HashMap<i32, Vec<String>> = HashMap::new();

        // 1. Live holders: most precise, but a fast writer may already be gone.
        let holders = attr::holders_by_pid();
        for (pid, holds) in &holders {
            for h in holds {
                let hit = wanted.contains(&h.path) || wanted.iter().any(|w| same_file(w, &h.path));
                if hit {
                    // Live *write* fds outrank a read-only holder.
                    let bump = if h.writable { 3 } else { 1 };
                    *counts.entry(*pid).or_insert(0) += bump;
                    held_by_pid
                        .entry(*pid)
                        .or_default()
                        .push(h.path.display().to_string());
                }
            }
        }

        // 2. Recent history from the background sweep: a fast encryptor has
        //    usually closed the file already, but its fd for the directory it is
        //    walking lives much longer.
        if let Some(t) = &self.tracker {
            for path in implicated {
                for (rank, pid) in t.recent_for(path).into_iter().enumerate() {
                    *counts.entry(pid).or_insert(0) += if rank == 0 { 2 } else { 1 };
                    held_by_pid
                        .entry(pid)
                        .or_default()
                        .push(path.display().to_string());
                }
                for (rank, pid) in t.recent_for_ancestors(path).into_iter().enumerate() {
                    // Directory holders are weak evidence: every indexer, Finder
                    // and updater holds the directory too. They only count when
                    // the process is not trusted and not a known system helper —
                    // otherwise Spotlight would outrank the encryptor and get
                    // frozen instead of it.
                    let name = self
                        .table
                        .lookup(pid)
                        .map(|p| p.name)
                        .unwrap_or_default();
                    if attr::is_system_helper(&name) {
                        continue;
                    }
                    let trusted = self
                        .table
                        .lookup(pid)
                        .map(|p| {
                            let t = self.table.classify(
                                pid,
                                &p.name,
                                p.exe.as_deref(),
                                p.signing.as_ref(),
                                None,
                            );
                            t != Trust::Untrusted
                        })
                        .unwrap_or(false);
                    if trusted {
                        continue;
                    }
                    // A directory holder alone is worth less than a file holder.
                    let w = if rank == 0 { 1 } else { 0 };
                    if w > 0 {
                        *counts.entry(pid).or_insert(0) += w;
                    }
                }
            }
        }

        if counts.is_empty() {
            return (Vec::new(), HashMap::new());
        }

        // Drop ourselves and processes that no longer exist.
        counts.retain(|pid, _| *pid != std::process::id() as i32);

        let names: HashMap<i32, String> = counts
            .keys()
            .filter_map(|p| self.table.lookup(*p).map(|i| (*p, i.name)))
            .collect();
        let start_times: HashMap<i32, u64> = counts
            .keys()
            .filter_map(|p| self.table.lookup(*p).map(|i| (*p, i.start_time)))
            .collect();
        let ranked = attr::rank_suspects(&counts.keys().copied().collect(), &counts, &start_times, |p| {
            names.get(&p).cloned()
        });
        // Only the top-ranked untrusted process is the suspect; including every
        // holder would freeze Spotlight, Finder and the backup agent too.
        let primary = ranked
            .iter()
            .copied()
            .find(|p| {
                names
                    .get(p)
                    .map(|n| !attr::is_system_helper(n))
                    .unwrap_or(true)
            })
            .or_else(|| ranked.first().copied());
        let mut out: Vec<ProcInfo> = Vec::new();
        let mut held: HashMap<i32, Vec<String>> = HashMap::new();
        if let Some(primary) = primary {
            let mut ids = vec![primary];
            if self.cfg.response.suspend_children {
                ids.extend(self.table.descendants(primary));
            }
            for pid in ids {
                if let Some(info) = self.table.lookup(pid) {
                    out.push(info);
                }
            }
            for info in &out {
                if let Some(h) = held_by_pid.get(&info.pid) {
                    held.entry(info.pid).or_default().extend(h.clone());
                }
            }
        }
        (out, held)
    }

    fn capture_ctx(
        &self,
        roots: &[PathBuf],
        suspects: &[crate::procinfo::ProcInfo],
        held: &HashMap<i32, Vec<String>>,
        implicated: &[PathBuf],
        decoy: Option<DecoyRecord>,
    ) -> CaptureContext<'static> {
        let processes: Vec<ProcessRecord> = suspects
            .iter()
            .map(|p| {
                let children = self.table.descendants(p.pid);
                let held_files = held.get(&p.pid).cloned().unwrap_or_default();
                forensics::process_record(p, children, held_files)
            })
            .collect();

        let mut files: Vec<FileRecord> = implicated
            .iter()
            .map(|p| file_record(p))
            .collect();
        // Hash + classify now, while the bytes are still the suspect's output.
        for f in files.iter_mut() {
            let p = PathBuf::from(&f.path);
            if let Ok(bytes) = std::fs::read(&p) {
                f.sha256 = Some(crate::util::sha256_hex(&bytes));
                let s = entropy::analyze(&bytes, &self.cfg.entropy);
                f.h0_at_capture = Some(s.h0);
                f.class_at_capture = Some(s.class.label());
            }
        }
        // CaptureContext borrows watch_roots, so leak a copy for the record
        // builder's lifetime. This is one small allocation per incident.
        let roots: &'static [PathBuf] = Box::leak(roots.to_vec().into_boxed_slice());
        CaptureContext {
            watch_roots: roots,
            processes,
            files,
            decoy,
        }
    }

    fn finish(
        &mut self,
        draft: &IncidentDraft,
        ctx: CaptureContext<'static>,
        _suspects: Vec<crate::procinfo::ProcInfo>,
    ) -> std::io::Result<Outcome> {
        let sev = draft.severity.as_str();
        let fx = Forensics::begin(&self.cfg.response, sev)?;
        let mut rec = fx.build_record(draft, &ctx);
        let mut ctx = ctx;

        // Evidence copy before suspension: the decryptor/key may be changing the
        // files' state as we work.
        let (evdir, ev_bytes, ev_skipped) = fx.copy_evidence(&mut ctx.files);
        rec.files = ctx.files.clone();
        rec.response.evidence_dir = Some(evdir.display().to_string());
        rec.response.evidence_bytes = ev_bytes;
        rec.response.evidence_skipped = ev_skipped;

        rec.response.mode = format!("{:?}", self.cfg.response.mode).to_lowercase();

        // Suspend.
        if self.cfg.response.mode == ResponseMode::Suspend {
            for p in &ctx.processes {
                let allow = if draft.trigger == Trigger::Decoy {
                    // Decoy touches bypass the score gate, but not the "don't
                    // freeze system helpers" rule.
                    !attr::is_system_helper(&p.name)
                        && !self
                            .cfg
                            .response
                            .never_suspend
                            .iter()
                            .any(|n| n.eq_ignore_ascii_case(&p.name))
                } else {
                    !p.trusted
                        && !self
                            .cfg
                            .response
                            .never_suspend
                            .iter()
                            .any(|n| n.eq_ignore_ascii_case(&p.name))
                };
                let rec_p = rec
                    .processes
                    .iter_mut()
                    .find(|r| r.pid == p.pid);
                if !allow {
                    if let Some(r) = rec_p {
                        r.status_at_capture = format!("{} (not suspended: {}", r.status_at_capture, if p.trusted { "trusted tool" } else { "allow-listed" });
                        r.status_at_capture.push(')');
                    }
                    continue;
                }
                match suspend_pid(p.pid) {
                    Ok(()) => {
                        rec.response.suspended_pids.push(p.pid);
                        if let Some(r) = rec_p {
                            r.suspended = true;
                        }
                    }
                    Err(e) => {
                        rec.response
                            .failed_suspensions
                            .push((p.pid, e.clone()));
                    }
                }
            }
        }

        // Persist.
        fx.write_json(&rec, "incident.json")?;
        let procs = serde_json::to_vec_pretty(&rec.processes).unwrap_or_default();
        let _ = crate::util::write_atomic(&fx.dir.join("processes.json"), &procs);
        let files_json = serde_json::to_vec_pretty(&rec.files).unwrap_or_default();
        let _ = crate::util::write_atomic(&fx.dir.join("files.json"), &files_json);
        let text = forensics::summary_text(&rec);
        let _ = fx.write_text(&text, "incident.txt");
        fx.append_jsonl(&rec);

        // Optional external hook.
        if let Some(cmd) = &self.cfg.response.on_alert_command {
            let status = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(cmd)
                .env("RANSOMWATCH_INCIDENT", fx.dir.display().to_string())
                .env("RANSOMWATCH_SEVERITY", sev)
                .status();
            rec.response.hook_exit = status.ok().and_then(|s| s.code());
        }

        let console = text.clone();
        Ok(Outcome {
            record: rec,
            record_dir: fx.dir.clone(),
            suspended: Vec::new(),
            failed: Vec::new(),
            console,
        })
    }
}

fn draft_decoy_signals(alert: &DecoyAlert) -> Vec<crate::detect::Signal> {
    vec![crate::detect::Signal {
        kind: crate::detect::SignalKind::DecoyTouch,
        weight: crate::detect::DECOY_WEIGHT,
        path: alert.decoy.path.clone(),
        detail: format!("{}: {}", alert.violation.as_str(), alert.detail),
    }]
}

fn suspend_pid(pid: i32) -> Result<(), String> {
    if pid <= 0 {
        return Err("invalid pid".into());
    }
    if crate::procinfo::suspend(pid) {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

/// Resume every pid a record suspended. Used by `ransomwatch resume`.
pub fn resume_incident(path: &Path) -> std::io::Result<Vec<i32>> {
    let text = std::fs::read_to_string(path)?;
    let rec: IncidentRecord = serde_json::from_str(&text)?;
    let mut ok = Vec::new();
    for pid in &rec.response.suspended_pids {
        if crate::procinfo::resume(*pid) {
            ok.push(*pid);
        }
    }
    Ok(ok)
}

fn file_record(p: &Path) -> FileRecord {
    let meta = std::fs::metadata(p).ok();
    let (size, mtime, mode, uid) = match &meta {
        Some(m) => {
            let (mode, uid) = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    (Some(m.mode()), Some(m.uid()))
                }
                #[cfg(not(unix))]
                {
                    (None, None)
                }
            };
            (m.len(), crate::detect::mtime_of(m), mode, uid)
        }
        None => (0, 0, None, None),
    };
    let note = if meta.is_none() {
        Some("file no longer present at capture time".into())
    } else {
        None
    };
    FileRecord {
        path: p.display().to_string(),
        size,
        mtime,
        mode,
        owner_uid: uid,
        h0_at_capture: None,
        class_at_capture: None,
        sha256: None,
        copied_to: None,
        note,
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) {
            return ma.dev() == mb.dev() && ma.ino() == mb.ino();
        }
    }
    false
}

fn dedupe(v: &mut Vec<PathBuf>) {
    let mut seen = HashSet::new();
    v.retain(|p| seen.insert(p.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoy::{Decoy, DecoyViolation};
    use crate::detect::{Signal, SignalKind, Severity};

    fn test_config(base: &Path) -> Config {
        let mut c = Config::default();
        c.watch.roots = vec![base.join("root")];
        c.response.incident_dir = base.join("incidents");
        c.response.mode = ResponseMode::Suspend;
        c.decoy.enabled = false;
        c.decoy.manifest_dir = base.join("decoys");
        c.output.jsonl = Some(base.join("incidents/incidents.jsonl"));
        c
    }

    #[test]
    fn decoy_outcome_is_critical_and_records_decoy() {
        let base = std::env::temp_dir().join(format!("rw-resp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("root")).unwrap();
        let mut cfg = test_config(&base);
        // Suspend mode would try to stop our own helper process; use Alert so the
        // test never freezes anything running in the same process group.
        cfg.response.mode = ResponseMode::Alert;
        let mut r = Responder::new(cfg);
        let dpath = base.join("root/decoy.xlsx");
        std::fs::write(&dpath, b"canary body").unwrap();
        let d = Decoy {
            path: dpath.clone(),
            canary: "abc".into(),
            dev: 0,
            ino: 0,
            size: 11,
            digest: "d".into(),
            planted_at: 0,
        };
        let alert = DecoyAlert {
            decoy: d,
            violation: DecoyViolation::Modified,
            detail: "digest mismatch".into(),
            pids: Vec::new(),
        };
        let out = r
            .handle_decoy(&alert, &[base.join("root")])
            .expect("record written");
        assert_eq!(out.record.severity, "critical");
        assert_eq!(out.record.trigger, "decoy");
        let decoy = out.record.decoy.as_ref().unwrap();
        assert_eq!(decoy.violation, "decoy_modified");
        assert!(out.record_dir.join("incident.json").exists());
        assert!(out.record_dir.join("incident.txt").exists());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn scored_outcome_records_signals_and_files() {
        let base = std::env::temp_dir().join(format!("rw-resp2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("root")).unwrap();
        let mut cfg = test_config(&base);
        cfg.response.mode = ResponseMode::Alert;
        let mut r = Responder::new(cfg);
        let p = base.join("root/a.docx");
        std::fs::write(&p, b"opaque-ish").unwrap();
        let draft = IncidentDraft {
            severity: Severity::High,
            trigger: Trigger::Score,
            reason: "test score".into(),
            signals: vec![Signal {
                kind: SignalKind::OpaqueRewrite,
                weight: 5.0,
                path: p.clone(),
                detail: "was text".into(),
            }],
            distinct_files: 3,
            score: 15.0,
        };
        let out = r.handle_scored(&draft, &[base.join("root")], &[]).unwrap();
        assert_eq!(out.record.trigger, "score");
        assert!(out.record.files.iter().any(|f| f.path == p.display().to_string()));
        assert!(out.record.files[0].sha256.is_some());
        assert!(out.console.contains("HIGH"));
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn suspend_then_resume_roundtrip() {
        if cfg!(not(unix)) {
            return;
        }
        let base = std::env::temp_dir().join(format!("rw-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let _cfg = test_config(&base);
        // Spawn a child that will be suspended, then resumed.
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        assert!(suspend_pid(pid).is_ok());
        // Verify it is stopped.
        let out = std::process::Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        let stat = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(stat.contains('T'), "expected stopped state, got {stat:?}");
        assert!(crate::procinfo::resume(pid));
        child.kill().ok();
        child.wait().ok();
        std::fs::remove_dir_all(&base).ok();
    }
}
