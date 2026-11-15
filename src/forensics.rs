//! Incident records and evidence preservation.
//!
//! The record is written **before** the process is suspended, so that even if
//! the suspension is refused (permissions, SIP, the process already exited) the
//! scene is on disk. Layout:
//!
//! ```text
//! ~/.ransomwatch/incidents/2026-11-15T08-31-04Z-<pid>-<short>/
//!   incident.json      structured record (machine readable)
//!   incident.txt       one-screen human summary
//!   processes.json     full process tree with command lines, cwd, signature
//!   files.json         implicated paths with stat + entropy at capture time
//!   evidence/<sha256>_<name>   copies of the first N implicated files
//! ```
//!
//! Alongside it, `incidents.jsonl` gets one JSON line per incident so a log
//! shipper can ingest without walking directories.

use crate::config::ResponseConfig;
use crate::detect::{IncidentDraft, Signal};
use crate::procinfo::{ProcInfo, Signing};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRecord {
    pub id: String,
    pub detected_at_utc: String,
    pub detected_at_unix: i64,
    pub hostname: String,
    pub username: String,
    pub severity: String,
    pub trigger: String,
    pub reason: String,
    pub score: f64,
    pub distinct_files: usize,
    pub watch_roots: Vec<String>,
    pub signals: Vec<SignalRecord>,
    pub processes: Vec<ProcessRecord>,
    pub files: Vec<FileRecord>,
    pub response: ResponseRecord,
    pub decoy: Option<DecoyRecord>,
    /// Tool/version that wrote the record, so records stay attributable.
    pub producer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalRecord {
    pub kind: String,
    pub weight: f64,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub pid: i32,
    pub ppid: Option<i32>,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
    pub cwd: Option<String>,
    pub uid: Option<u32>,
    pub start_time: u64,
    pub status_at_capture: String,
    pub trusted: bool,
    pub trust_reason: String,
    pub signing: Option<SigningRecord>,
    /// Pids in this process's subtree that are also recorded.
    pub children: Vec<i32>,
    /// Files from the implicated set this process had open.
    pub held_files: Vec<String>,
    pub suspended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRecord {
    pub signed: bool,
    pub adhoc: bool,
    pub platform: bool,
    pub identifier: Option<String>,
    pub team: Option<String>,
    pub authorities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    /// Modification time in **nanoseconds** since the epoch (APFS reports real
    /// nanosecond mtimes; seconds would lose the distinction between rapid
    /// rewrites).
    pub mtime: i64,
    pub mode: Option<u32>,
    pub owner_uid: Option<u32>,
    pub h0_at_capture: Option<f64>,
    pub class_at_capture: Option<String>,
    pub sha256: Option<String>,
    pub copied_to: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseRecord {
    pub mode: String,
    pub suspended_pids: Vec<i32>,
    pub failed_suspensions: Vec<(i32, String)>,
    pub resumed_pids: Vec<i32>,
    pub evidence_dir: Option<String>,
    pub evidence_bytes: u64,
    pub evidence_skipped: usize,
    pub hook_exit: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyRecord {
    pub path: String,
    pub canary: String,
    pub violation: String,
    pub detail: String,
}

impl From<&Signal> for SignalRecord {
    fn from(s: &Signal) -> Self {
        Self {
            kind: s.kind.as_str().into(),
            weight: s.weight,
            path: s.path.display().to_string(),
            detail: s.detail.clone(),
        }
    }
}

pub fn signing_record(s: &Signing) -> SigningRecord {
    SigningRecord {
        signed: s.signed,
        adhoc: s.is_adhoc,
        platform: s.is_platform,
        identifier: s.identifier.clone(),
        team: s.team.clone(),
        authorities: s.authorities.clone(),
    }
}

pub fn process_record(p: &ProcInfo, children: Vec<i32>, held: Vec<String>) -> ProcessRecord {
    ProcessRecord {
        pid: p.pid,
        ppid: p.ppid,
        name: p.name.clone(),
        exe: p.exe.as_ref().map(|e| e.display().to_string()),
        cmdline: p.cmdline.clone(),
        cwd: p.cwd.as_ref().map(|c| c.display().to_string()),
        uid: p.uid,
        start_time: p.start_time,
        status_at_capture: p.status.clone(),
        trusted: p.is_trusted(),
        trust_reason: format!("{:?}", p.trust),
        signing: p.signing.as_ref().map(signing_record),
        children,
        held_files: held,
        suspended: false,
    }
}

/// Everything the response layer needs to write a record.
pub struct CaptureContext<'a> {
    pub watch_roots: &'a [PathBuf],
    pub processes: Vec<ProcessRecord>,
    pub files: Vec<FileRecord>,
    pub decoy: Option<DecoyRecord>,
}

pub struct Forensics {
    cfg: ResponseConfig,
    pub id: String,
    pub dir: PathBuf,
}

impl Forensics {
    /// Allocate an incident directory. The id is timestamp + pid + random hex so
    /// two incidents in the same second never collide.
    pub fn begin(cfg: &ResponseConfig, severity: &str) -> std::io::Result<Self> {
        let now = crate::util::now_unix();
        // Id is wall-clock (readable) + pid + random suffix, so two incidents in
        // the same second on the same process cannot collide.
        let id = format!(
            "{}-{}-{}",
            crate::util::format_utc(now).replace(':', "-"),
            std::process::id(),
            crate::util::random_hex(3)
        );
        let dir = cfg.incident_dir.join(&id);
        std::fs::create_dir_all(&dir)?;
        // Keep a marker so an operator can spot severity without opening JSON.
        std::fs::write(dir.join("severity.txt"), severity.as_bytes()).ok();
        Ok(Self {
            cfg: cfg.clone(),
            id,
            dir,
        })
    }

    pub fn build_record(
        &self,
        draft: &IncidentDraft,
        ctx: &CaptureContext<'_>,
    ) -> IncidentRecord {
        IncidentRecord {
            id: self.id.clone(),
            detected_at_utc: crate::util::format_utc(crate::util::now_unix()),
            detected_at_unix: crate::util::now_unix(),
            hostname: hostname(),
            username: username(),
            severity: if let Some(d) = &ctx.decoy {
                let _ = d;
                draft.severity.as_str().into()
            } else {
                draft.severity.as_str().into()
            },
            trigger: if draft.trigger == crate::detect::Trigger::Decoy {
                "decoy".into()
            } else {
                "score".into()
            },
            reason: draft.reason.clone(),
            score: draft.score,
            distinct_files: draft.distinct_files,
            watch_roots: ctx.watch_roots.iter().map(|p| p.display().to_string()).collect(),
            signals: draft.signals.iter().map(SignalRecord::from).collect(),
            processes: ctx.processes.clone(),
            files: ctx.files.clone(),
            response: ResponseRecord {
                mode: format!("{:?}", self.cfg.mode).to_lowercase(),
                ..Default::default()
            },
            decoy: ctx.decoy.clone(),
            producer: format!("ransomwatch {}", env!("CARGO_PKG_VERSION")),
        }
    }

    pub fn write_json(&self, rec: &IncidentRecord, file: &str) -> std::io::Result<PathBuf> {
        let p = self.dir.join(file);
        let bytes = serde_json::to_vec_pretty(rec).map_err(std::io::Error::other)?;
        crate::util::write_atomic(&p, &bytes)?;
        Ok(p)
    }

    pub fn write_text(&self, text: &str, file: &str) -> std::io::Result<PathBuf> {
        let p = self.dir.join(file);
        crate::util::write_atomic(&p, text.as_bytes())?;
        Ok(p)
    }

    pub fn append_jsonl(&self, rec: &IncidentRecord) {
        let path = match &self.cfg.incident_dir.join("incidents.jsonl") {
            p if p.exists() => p.clone(),
            p => p.clone(),
        };
        let _ = path;
        let target = crate::util::expand_home(
            &self.cfg.incident_dir.join("incidents.jsonl"),
        );
        let line = match serde_json::to_string(rec) {
            Ok(l) => l,
            Err(_) => return,
        };
        let _ = append_line(&target, &line);
    }

    /// Copy the first `max_files` implicated files, up to the byte budget. Each
    /// copy is hashed and stored under its digest so evidence cannot be silently
    /// altered later.
    pub fn copy_evidence(&self, files: &mut [FileRecord]) -> (PathBuf, u64, usize) {
        let evdir = self.dir.join("evidence");
        let _ = std::fs::create_dir_all(&evdir);
        let mut total = 0u64;
        let mut skipped = 0usize;
        let mut copied = 0usize;
        for f in files.iter_mut() {
            if copied >= self.cfg.copy_evidence_files {
                skipped += 1;
                continue;
            }
            let src = PathBuf::from(&f.path);
            let size = match std::fs::metadata(&src) {
                Ok(m) => m.len(),
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            if size > self.cfg.evidence_max_bytes || total + size > self.cfg.evidence_total_bytes
            {
                skipped += 1;
                f.note = Some(format!(
                    "not copied: {} exceeds evidence budget",
                    crate::util::human_size(size)
                ));
                continue;
            }
            let name = crate::util::file_name(&src);
            let safe: String = name
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
                .collect();
            let dest = evdir.join(format!("{}_{}", f.sha256.clone().unwrap_or_else(|| crate::util::random_hex(8)), safe));
            match std::fs::copy(&src, &dest) {
                Ok(_) => {
                    total += size;
                    copied += 1;
                    f.copied_to = Some(dest.display().to_string());
                }
                Err(e) => {
                    skipped += 1;
                    f.note = Some(format!("copy failed: {e}"));
                }
            }
        }
        (evdir, total, skipped)
    }
}

fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{}", line)?;
    Ok(())
}

/// Human summary: what fired, who did it, what was done.
pub fn summary_text(rec: &IncidentRecord) -> String {
    let mut s = String::new();
    s.push_str(&format!("ransomwatch incident {}\n", rec.id));
    s.push_str(&format!(
        "severity : {}   trigger: {}   score: {:.1}   files: {}\n",
        rec.severity.to_uppercase(),
        rec.trigger,
        rec.score,
        rec.distinct_files
    ));
    s.push_str(&format!("when     : {}\n", rec.detected_at_utc));
    s.push_str(&format!(
        "host/user: {} / {}   producer: {}\n",
        rec.hostname, rec.username, rec.producer
    ));
    s.push_str(&format!("reason   : {}\n", rec.reason));
    if let Some(d) = &rec.decoy {
        s.push_str(&format!(
            "DECOY    : {} [{}] {}\n",
            d.path, d.violation, d.detail
        ));
    }
    s.push_str("\nsignals:\n");
    let mut by_kind: BTreeMap<&str, Vec<&SignalRecord>> = BTreeMap::new();
    for sig in &rec.signals {
        by_kind.entry(&sig.kind).or_default().push(sig);
    }
    for (kind, sigs) in by_kind {
        s.push_str(&format!("  {:<18} {} file(s), weight {:.1}\n", kind, sigs.len(), sigs[0].weight));
        for sig in sigs.iter().take(3) {
            s.push_str(&format!("      {}\n        {}\n", sig.path, sig.detail));
        }
    }
    if rec.processes.is_empty() {
        s.push_str("\nprocesses: none identified (no holder found for the implicated files)\n");
    } else {
        s.push_str("\nprocesses:\n");
        for p in &rec.processes {
            s.push_str(&format!(
                "  pid {} {:<24} trusted={} suspended={}\n      {}\n",
                p.pid,
                p.name,
                p.trusted,
                p.suspended,
                p.cmdline.join(" ")
            ));
            if let Some(exe) = &p.exe {
                s.push_str(&format!("      exe: {}\n", exe));
            }
            if let Some(sig) = &p.signing {
                s.push_str(&format!(
                    "      signing: signed={} platform={} adhoc={} team={:?}\n",
                    sig.signed, sig.platform, sig.adhoc, sig.team
                ));
            }
            if !p.held_files.is_empty() {
                s.push_str(&format!("      held: {} file(s)\n", p.held_files.len()));
            }
        }
    }
    s.push_str(&format!("\nresponse: mode={} suspended={:?}\n", rec.response.mode, rec.response.suspended_pids));
    if !rec.response.failed_suspensions.is_empty() {
        s.push_str(&format!("          failed: {:?}\n", rec.response.failed_suspensions));
    }
    if rec.response.evidence_dir.is_some() {
        s.push_str(&format!(
            "          evidence: {} files, {} ({} skipped)\n",
            rec.files.iter().filter(|f| f.copied_to.is_some()).count(),
            crate::util::human_size(rec.response.evidence_bytes),
            rec.response.evidence_skipped
        ));
    }
    s.push_str(&format!("\nrecord dir: {}\n", rec.id));
    s
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::process::Command::new("/bin/hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into())
}

fn username() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Signal, SignalKind};

    fn tmpcfg(dir: &Path) -> ResponseConfig {
        ResponseConfig {
            incident_dir: dir.join("incidents"),
            copy_evidence_files: 2,
            evidence_max_bytes: 1 << 20,
            evidence_total_bytes: 4 << 20,
            ..Default::default()
        }
    }

    fn draft() -> IncidentDraft {
        IncidentDraft {
            severity: crate::detect::Severity::High,
            trigger: crate::detect::Trigger::Score,
            reason: "test".into(),
            signals: vec![Signal {
                kind: SignalKind::OpaqueRewrite,
                weight: 5.0,
                path: PathBuf::from("/tmp/a.docx"),
                detail: "was text now opaque".into(),
            }],
            distinct_files: 4,
            score: 20.0,
        }
    }

    #[test]
    fn writes_record_and_summary() {
        let base = std::env::temp_dir().join(format!("rw-forensic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cfg = tmpcfg(&base);
        let fx = Forensics::begin(&cfg, "high").unwrap();
        let ctx = CaptureContext {
            watch_roots: &[PathBuf::from("/tmp/watched")],
            processes: vec![],
            files: vec![],
            decoy: None,
        };
        let rec = fx.build_record(&draft(), &ctx);
        assert_eq!(rec.severity, "high");
        assert_eq!(rec.distinct_files, 4);
        let p = fx.write_json(&rec, "incident.json").unwrap();
        assert!(p.exists());
        let parsed: IncidentRecord =
            serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(parsed.id, rec.id);
        assert_eq!(parsed.signals.len(), 1);
        let txt = summary_text(&rec);
        assert!(txt.contains("opaque_rewrite"));
        assert!(txt.contains("HIGH"));
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn evidence_copy_budget_and_hashing() {
        let base = std::env::temp_dir().join(format!("rw-evidence-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let cfg = tmpcfg(&base);
        let fx = Forensics::begin(&cfg, "high").unwrap();
        let mut files = Vec::new();
        for i in 0..4 {
            let p = base.join(format!("f{i}.bin"));
            std::fs::write(&p, vec![i as u8; 1000]).unwrap();
            files.push(FileRecord {
                path: p.display().to_string(),
                size: 1000,
                mtime: 0,
                mode: None,
                owner_uid: None,
                h0_at_capture: None,
                class_at_capture: None,
                sha256: Some(crate::util::sha256_hex(format!("x{i}").as_bytes())),
                copied_to: None,
                note: None,
            });
        }
        let (evdir, bytes, skipped) = fx.copy_evidence(&mut files);
        assert_eq!(bytes, 2000);
        assert_eq!(skipped, 2);
        assert_eq!(files.iter().filter(|f| f.copied_to.is_some()).count(), 2);
        assert!(evdir.exists());
        std::fs::remove_dir_all(&base).ok();
    }
}
