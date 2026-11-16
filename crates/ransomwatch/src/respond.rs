//! Response: attribute an incident to processes, suspend them, and capture a
//! forensic snapshot.
//!
//! Attribution
//! -----------
//! There is no portable "who wrote this file" API.  We combine the kernel
//! facts that *are* available, strongest first:
//!
//! 1. **Open-for-write descriptors** on the incident files (or their parent
//!    directory).  A process holding `report.docx` open `O_WRONLY` is the
//!    writer. Downloaded from the process fd table via `proc_pidinfo`.
//! 2. **Write rate**. [`ProcSampler`] polls `proc_pid_rusage` for every process
//!    every ~1.5 s and keeps a short history.  At incident time, a process
//!    that has moved megabytes more than it had a few seconds ago is writing
//!    *now*, which is what an encryptor does.  This catches the common case
//!    where the encryptor opens, writes and closes each file in a tight loop so
//!    that a single pid-only sweep sees no open descriptor.
//! 3. **Read rate**, for the decoy case: a decoy is tripped by a *read*, and
//!    the only process whose read counter advanced is the reader.
//! 4. **Ancestry**, to surface the shell or script that started the writer.
//!
//! Suspend is `SIGSTOP` on the blamed tree; SIGSTOP cannot be caught, so this
//! is containment rather than advice.  Suspended processes stay in memory for
//! evidence collection.

use crate::config::Config;
use crate::detect::{DecoyAction, Incident, SignalKind};
use crate::sys;
use crate::util::{human_bytes, now_unix};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Per-pid I/O counters over time, sampled by the engine.
///
/// Sampling is deliberately cheap: one `proc_pid_rusage` per live pid, no
/// fd-table or path resolution.  That makes it affordable at ~1 s intervals on
/// a busy machine (a few ms per sweep) and gives us two things a point-in-time
/// snapshot cannot:
///
/// * **Who is writing right now**, even when they open and close a file
///   between sweeps — the usual shape of a fast encryptor loop.
/// * **The last known identity** of a pid that exits before the response runs,
///   so an incident can still name the culprit.
pub struct ProcSampler {
    /// pid -> history of (t, written, read, logical)
    history: HashMap<u32, Vec<(Instant, u64, u64, u64)>>,
    /// Last known identity of every pid we have sampled, surviving exit.
    identities: HashMap<u32, sys::ProcessIdentity>,
    /// Pids recently caught holding a writable descriptor inside the watched
    /// tree, with the paths they had open.  A fast encryptor closes each file
    /// between writes, so a point-in-time fd sweep at response time often sees
    /// nothing; this recorder keeps what the periodic sweeps saw.
    fd_hits: HashMap<u32, (Instant, Vec<PathBuf>)>,
    /// Deltas from the most recent synchronous probe: (written, logical, read).
    probe_delta: HashMap<u32, (u64, u64, u64)>,
    /// Highest write rate seen per pid over the last window, even if the pid is
    /// gone by incident time.
    peak_written: HashMap<u32, u64>,
    peak_read: HashMap<u32, u64>,
    pub last_sample: Option<Instant>,
    pub samples: u64,
}

const HISTORY_WINDOW: usize = 24;
const RATE_WINDOW: Duration = Duration::from_secs(5);
/// Pids that have been gone this long are forgotten.
const FORGET_AFTER: Duration = Duration::from_secs(300);

impl ProcSampler {
    pub fn new() -> Self {
        Self {
            history: HashMap::new(),
            identities: HashMap::new(),
            peak_written: HashMap::new(),
            peak_read: HashMap::new(),
            fd_hits: HashMap::new(),
            probe_delta: HashMap::new(),
            last_sample: None,
            samples: 0,
        }
    }

    /// Synchronously measure write/read deltas over `window`.  Used at
    /// response time: an incident can open within 100 ms of the first
    /// rewrites, well before any periodic sample can show a delta, so we take
    /// one ourselves while the encryptor keeps running.
    pub fn probe(&mut self, window: Duration) -> HashMap<u32, (u64, u64, u64)> {
        let mut before: HashMap<u32, (u64, u64, u64)> = HashMap::new();
        for pid in sys::list_pids() {
            if let Some((w, l, r)) = sys::io_counters(pid) {
                before.insert(pid, (w, l, r));
            }
            if let std::collections::hash_map::Entry::Vacant(e) = self.identities.entry(pid) {
                if let Some(id) = sys::identity(pid) {
                    e.insert(id);
                }
            }
        }
        std::thread::sleep(window);
        let mut delta = HashMap::new();
        for pid in sys::list_pids() {
            let Some((w2, l2, r2)) = sys::io_counters(pid) else {
                continue;
            };
            if let Some((w1, l1, r1)) = before.get(&pid) {
                let dw = w2.saturating_sub(*w1);
                let dl = l2.saturating_sub(*l1);
                let dr = r2.saturating_sub(*r1);
                if dw > 0 || dl > 0 || dr > 0 {
                    delta.insert(pid, (dw, dl, dr));
                }
            }
            if let std::collections::hash_map::Entry::Vacant(e) = self.identities.entry(pid) {
                if let Some(id) = sys::identity(pid) {
                    e.insert(id);
                }
            }
        }
        self.probe_delta = delta.clone();
        self.last_sample = Some(Instant::now());
        delta
    }

    /// Recent synchronous-probe deltas, if a probe ran.
    pub fn probe_delta(&self, pid: u32) -> Option<(u64, u64, u64)> {
        self.probe_delta.get(&pid).copied()
    }

    pub fn probe_deltas(&self) -> impl Iterator<Item = (&u32, &(u64, u64, u64))> {
        self.probe_delta.iter()
    }

    /// Record writable descriptors found under a watched root.  Called every
    /// few samples by the engine; deliberately separate from `sample()` so the
    /// expensive fd sweep runs at a lower cadence.
    pub fn record_open_fds(&mut self, roots: &[PathBuf]) {
        let now = Instant::now();
        for pid in sys::list_pids() {
            let mut hits = Vec::new();
            for p in sys::writable_files(pid) {
                if roots.iter().any(|r| p.starts_with(r)) {
                    hits.push(p);
                }
            }
            if !hits.is_empty() {
                self.fd_hits.insert(pid, (now, hits));
            }
        }
        let stale = Duration::from_secs(30);
        self.fd_hits
            .retain(|_, (t, _)| now.duration_since(*t) <= stale);
    }

    /// Did this pid hold any writable descriptor in the tree recently?
    pub fn last_fd_hit(&self, pid: u32) -> Option<&Vec<PathBuf>> {
        self.fd_hits.get(&pid).map(|(_, v)| v)
    }

    /// Pids with a recent in-tree writable descriptor.
    pub fn fd_pids(&self) -> Vec<u32> {
        self.fd_hits.keys().copied().collect()
    }

    pub fn sample(&mut self) {
        let now = Instant::now();
        self.last_sample = Some(now);
        self.samples += 1;
        let mut seen = HashSet::new();
        for pid in sys::list_pids() {
            let Some((written, logical, read)) = sys::io_counters(pid) else {
                continue;
            };
            seen.insert(pid);
            if let std::collections::hash_map::Entry::Vacant(e) = self.identities.entry(pid) {
                if let Some(id) = sys::identity(pid) {
                    e.insert(id);
                }
            }
            let v = self.history.entry(pid).or_default();
            v.push((now, written, read, logical));
            if v.len() > HISTORY_WINDOW {
                v.remove(0);
            }
            // Peak rate over the retained window.
            if let (Some(first), Some(last)) = (v.first(), v.last()) {
                let dw = last.1.saturating_sub(first.1);
                let dr = last.2.saturating_sub(first.2);
                self.peak_written
                    .entry(pid)
                    .and_modify(|m| *m = (*m).max(dw))
                    .or_insert(dw);
                self.peak_read
                    .entry(pid)
                    .and_modify(|m| *m = (*m).max(dr))
                    .or_insert(dr);
            }
        }
        // Old identities are only useful briefly after exit.
        let stale: Vec<u32> = self
            .identities
            .keys()
            .copied()
            .filter(|p| !seen.contains(p))
            .filter(|p| {
                self.history
                    .get(p)
                    .and_then(|h| h.last())
                    .map(|(t, ..)| now.duration_since(*t) > FORGET_AFTER)
                    .unwrap_or(true)
            })
            .collect();
        for p in stale {
            self.identities.remove(&p);
            self.history.remove(&p);
            self.peak_written.remove(&p);
            self.peak_read.remove(&p);
            self.fd_hits.remove(&p);
        }
        // A pid that exited but is still recent keeps its history: that is the
        // record we attribute with.
        self.history.retain(|_, h| {
            h.last()
                .map(|(t, ..)| now.duration_since(*t) <= FORGET_AFTER)
                .unwrap_or(false)
        });
    }

    /// (written, read, logical) delta over the last `window`.
    pub fn recent(&self, pid: u32, window: Duration) -> Option<(u64, u64, u64)> {
        let hist = self.history.get(&pid)?;
        let last = hist.last()?;
        let cutoff = last.0.checked_sub(window);
        let first = hist
            .iter()
            .find(|(t, ..)| cutoff.map(|c| *t >= c).unwrap_or(true))?;
        Some((
            last.1.saturating_sub(first.1),
            last.2.saturating_sub(first.2),
            last.3.saturating_sub(first.3),
        ))
    }

    pub fn span(&self, pid: u32) -> Duration {
        self.history
            .get(&pid)
            .and_then(|h| h.last().zip(h.first()))
            .map(|(a, b)| a.0.duration_since(b.0))
            .unwrap_or_default()
    }

    /// Pids whose *peak* write volume in the retained window is at least
    /// `threshold`.  Includes pids that have already exited.
    pub fn write_burst(&self, threshold: u64) -> Vec<(u32, u64)> {
        let mut v: Vec<(u32, u64)> = self
            .peak_written
            .iter()
            .filter(|(_, b)| **b >= threshold)
            .map(|(p, b)| (*p, *b))
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.1));
        v
    }

    pub fn read_burst(&self, threshold: u64) -> Vec<(u32, u64)> {
        let mut v: Vec<(u32, u64)> = self
            .peak_read
            .iter()
            .filter(|(_, b)| **b >= threshold)
            .map(|(p, b)| (*p, *b))
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.1));
        v
    }

    pub fn identity(&self, pid: u32) -> Option<&sys::ProcessIdentity> {
        self.identities.get(&pid)
    }

    pub fn is_alive(&self, pid: u32) -> bool {
        sys::status(pid).is_some()
    }

    /// Describe a pid, preferring live data and falling back to the cached
    /// identity so an exited writer can still be named.
    /// Milliseconds since the process started, if we know it.
    pub fn age_ms(&self, pid: u32) -> Option<u64> {
        let id = self.identities.get(&pid)?;
        let started = id.start_time?;
        std::time::SystemTime::now()
            .duration_since(started)
            .ok()
            .map(|d| d.as_millis() as u64)
    }

    fn describe(&self, pid: u32) -> Option<(String, u32, Option<PathBuf>, u32)> {
        if let Some(info) = sys::process_info(pid, false) {
            return Some((info.name, info.ppid, info.exe, info.uid));
        }
        let id = self.identity(pid)?;
        Some((id.name.clone(), id.ppid, id.exe.clone(), id.uid))
    }
}

impl Default for ProcSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcSampler {
    /// A copy for response-time probing.  History and identities are preserved;
    /// the new sampler's extra samples are discarded with it.
    pub fn clone_shallow(&self) -> Self {
        Self {
            history: self.history.clone(),
            identities: self.identities.clone(),
            peak_written: self.peak_written.clone(),
            peak_read: self.peak_read.clone(),
            fd_hits: self.fd_hits.clone(),
            probe_delta: self.probe_delta.clone(),
            last_sample: self.last_sample,
            samples: self.samples,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Suspect {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub uid: u32,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub logical_writes: u64,
    /// Bytes written / read during the recent sampling window.
    pub recent_written: u64,
    pub recent_read: u64,
    /// Why we blamed it.
    pub reasons: Vec<String>,
    /// Paths it held open for writing inside the incident set.
    pub held_open: Vec<String>,
    /// 0 = direct blame, >0 = ancestor depth.
    pub depth: usize,
    /// Still running at response time (an exited writer cannot be suspended).
    pub alive: bool,
    /// How long the process has existed.  Ransomware is typically minutes old;
    /// system daemons are hours old.  `None` when unknown.
    pub age_ms: Option<u64>,
}

impl Suspect {
    /// Confidence 0..=100, used to rank and to gate suspension.
    ///
    /// Tiers, strongest first:
    /// * holds an incident path open for writing (direct, contemporaneous)
    /// * a young process that is also the dominant writer (ransomware is
    ///   typically seconds-to-minutes old; daemons are hours old)
    /// * a young process caught by the fd sweep inside the tree
    /// * a rate-only writer that is old — suspicious, but not enough alone
    pub fn confidence(&self) -> u8 {
        let young = |limit: u64| self.age_ms.map(|ms| ms <= limit).unwrap_or(false);
        let mut c: i32 = 0;

        if !self.held_open.is_empty() {
            c += 75;
            if self.depth == 0 {
                c += 15;
            }
        } else if self.recent_written > 0 {
            // Rate-based evidence only means something combined with youth:
            // the burst ran while this process was freshly started.
            if young(120_000) {
                c += 60;
            } else if young(600_000) {
                c += 35;
            } else if self.age_ms.is_some() {
                c += 8; // old daemon: report it, do not act on it alone
            } else {
                c += 25; // age unknown (exited before we sampled start time)
            }
            // Volume magnitude nudges within that band.
            c += ((self.recent_written / (256 * 1024)) as i32).min(25);
        } else if self.depth == 0 && self.age_ms.is_some() && young(600_000) {
            // Young and doing something here, but no measured volume.
            c += 15;
        }

        if self.depth > 0 {
            c -= 25 * self.depth as i32;
        }
        if !self.alive {
            c -= 20;
        }
        c.clamp(0, 100) as u8
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ActionRecord {
    pub action: String,
    pub pid: u32,
    pub name: String,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResponseReport {
    pub suspended: bool,
    pub dry_run: bool,
    pub suspects: Vec<Suspect>,
    pub actions: Vec<ActionRecord>,
    pub evidence_dir: Option<String>,
}

/// How much recent write volume makes a process a suspect on rate alone.
/// Absolute floor for "this process is writing a lot": 512 KiB in the sampling
/// window.  Encryption of even a few hundred small documents clears this, while
/// ordinary editors and compilers that write a handful of KB do not.
const WRITE_RATE_SUSPECT_BYTES: u64 = 512 * 1024;
/// How much recent read volume makes a process a suspect for a decoy trip.
const READ_RATE_SUSPECT_BYTES: u64 = 32 * 1024;
/// Minimum write volume in the synchronous probe for a process to even be
/// considered.  Well above normal syscall chatter, well below any real
/// encryption burst.
const PROBE_MIN_WRITE_BYTES: u64 = 64 * 1024;

/// Attribute the incident to a set of processes.
pub fn attribute(
    incident: &Incident,
    watch_roots: &[PathBuf],
    cfg: &Config,
    sampler: &ProcSampler,
) -> Vec<Suspect> {
    let deadline = Instant::now()
        + Duration::from_millis(cfg.response.attribution_deadline_ms);
    let protected: HashSet<u32> = sys::protected_pids().into_iter().collect();
    let own_pid = std::process::id();

    let incident_paths: Vec<&PathBuf> = incident.top_paths.iter().collect();
    let incident_dirs: HashSet<&Path> = incident
        .top_paths
        .iter()
        .filter_map(|p| p.parent())
        .collect();
    let decoy_trip = incident
        .signals
        .iter()
        .any(|s| s.kind == SignalKind::DecoyTrip);
    let decoy_dirs: Vec<&Path> = incident
        .signals
        .iter()
        .filter(|s| s.kind == SignalKind::DecoyTrip)
        .filter_map(|s| s.sample_paths.first())
        .filter_map(|p| p.parent())
        .collect();

    let excluded = |info: &sys::ProcessInfo| -> bool {
        if info.pid == own_pid || info.pid <= 1 || protected.contains(&info.pid) {
            return true;
        }
        let exe = info.exe_name();
        if cfg.is_allowed_process(&exe) {
            return true;
        }
        cfg.response
            .never_suspend
            .iter()
            .any(|n| exe.eq_ignore_ascii_case(n) || info.name.eq_ignore_ascii_case(n))
    };

    let mut suspects: Vec<Suspect> = Vec::new();

    // ---- Pass 1: open-for-write descriptors -----------------------------
    // Only live processes can hold FDs, so this sweep is over live pids.
    if Instant::now() < deadline {
        for info in sys::snapshot(true) {
            if Instant::now() > deadline {
                break;
            }
            if excluded(&info) {
                continue;
            }
            let mut held: Vec<String> = Vec::new();
            for f in &info.open_files {
                if !f.writable {
                    continue;
                }
                let in_tree = watch_roots.iter().any(|r| f.path.starts_with(r));
                let hit = incident_paths.iter().any(|p| sys::same_file(&f.path, p))
                    || incident_dirs.contains(f.path.as_path())
                    || decoy_dirs.iter().any(|d| f.path.starts_with(d))
                    || in_tree;
                if hit {
                    held.push(f.path.display().to_string());
                }
            }
            if held.is_empty() {
                continue;
            }
            let (rw, rr, _) = sampler
                .recent(info.pid, RATE_WINDOW)
                .unwrap_or((0, 0, 0));
            suspects.push(Suspect {
                pid: info.pid,
                ppid: info.ppid,
                name: info.name.clone(),
                exe: info.exe.as_ref().map(|p| p.display().to_string()),
                uid: info.uid,
                bytes_written: info.bytes_written,
                bytes_read: info.bytes_read,
                logical_writes: info.logical_writes,
                recent_written: rw,
                recent_read: rr,
                reasons: vec![format!(
                    "holds {} file(s) in the watched tree open for writing",
                    held.len()
                )],
                held_open: held,
                depth: 0,
                alive: true,
                age_ms: sampler.age_ms(info.pid),
            });
        }
    }

    // ---- Pass 1b: pids seen by the periodic fd sweep ---------------------
    // Catches a writer that had a file in the tree open moments ago but has
    // since closed it.  Still live, so it can be stopped.
    let already: HashSet<u32> = suspects.iter().map(|s| s.pid).collect();
    let mut fd_candidates: Vec<(u32, Vec<PathBuf>)> = Vec::new();
    for pid in sampler.fd_pids() {
        if already.contains(&pid) {
            continue;
        }
        if let Some(paths) = sampler.last_fd_hit(pid) {
            fd_candidates.push((pid, paths.clone()));
        }
    }
    for (pid, paths) in fd_candidates {
        let Some((name, ppid, exe, uid)) = sampler.describe(pid) else {
            continue;
        };
        let exe_name = exe
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| name.clone());
        if own_pid == pid || pid <= 1 || protected.contains(&pid) {
            continue;
        }
        if cfg.is_allowed_process(&exe_name)
            || cfg
                .response
                .never_suspend
                .iter()
                .any(|n| exe_name.eq_ignore_ascii_case(n) || name.eq_ignore_ascii_case(n))
        {
            continue;
        }
        let alive = sampler.is_alive(pid);
        let (rw, rr, dl) = sampler.recent(pid, RATE_WINDOW).unwrap_or((0, 0, 0));
        let logical = dl;
        let rw = rw.max(logical);
        suspects.push(Suspect {
            pid,
            ppid,
            name,
            exe: exe.map(|p| p.display().to_string()),
            uid,
            bytes_written: rw,
            bytes_read: rr,
            logical_writes: logical,
            recent_written: rw,
            recent_read: rr,
            reasons: vec![format!(
                "had {} file(s) in the watched tree open for writing moments ago",
                paths.len()
            )],
            held_open: paths.iter().map(|p| p.display().to_string()).collect(),
            depth: 0,
            alive,
            age_ms: sampler.age_ms(pid),
        });
    }

    // ---- Pass 2: I/O rate, including processes that already exited ------
    let already: HashSet<u32> = suspects.iter().map(|s| s.pid).collect();
    // A process writing about as much as the whole burst is a strong match.
    // The floor keeps tiny incidents from blaming a chatty daemon.
    let write_threshold =
        (incident.observed_bytes / 2).clamp(WRITE_RATE_SUSPECT_BYTES, 64 * 1024 * 1024);
    let mut rate_candidates: Vec<(u32, u64, u64, &'static str)> = Vec::new();
    for (pid, written) in sampler.write_burst(write_threshold) {
        if !already.contains(&pid) {
            rate_candidates.push((pid, written, 0, "write"));
        }
    }
    // Synchronous-probe results: the writer is often visible only here.
    for (&pid, &(dw, dl, dr)) in sampler.probe_deltas() {
        if already.contains(&pid) || rate_candidates.iter().any(|(p, ..)| *p == pid) {
            continue;
        }
        // `logical` (write syscall bytes) is more responsive than buffered
        // disk bytes, so it is the better rate signal in a fast burst.  The
        // floor here is intentionally low: discrimination happens by age and
        // relative dominance afterwards, not by an absolute byte count.
        let volume = dw.max(dl);
        if volume >= PROBE_MIN_WRITE_BYTES {
            rate_candidates.push((pid, volume, 0, "write"));
        } else if decoy_trip && dr >= READ_RATE_SUSPECT_BYTES {
            rate_candidates.push((pid, 0, dr, "read"));
        }
    }
    if decoy_trip {
        // A decoy trip is a *read*; the reader is the culprit even if it wrote
        // nothing at all.
        for (pid, read) in sampler.read_burst(READ_RATE_SUSPECT_BYTES) {
            if !already.contains(&pid) {
                rate_candidates.push((pid, 0, read, "read"));
            }
        }
    }
    rate_candidates.sort_by_key(|a| std::cmp::Reverse((a.1, a.2)));
    for (pid, written, read, what) in rate_candidates.into_iter().take(10) {
        let Some((name, ppid, exe, uid)) = sampler.describe(pid) else {
            continue;
        };
        let exe_name = exe
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| name.clone());
        if own_pid == pid || pid <= 1 || protected.contains(&pid) {
            continue;
        }
        if cfg.is_allowed_process(&exe_name)
            || cfg
                .response
                .never_suspend
                .iter()
                .any(|n| exe_name.eq_ignore_ascii_case(n) || name.eq_ignore_ascii_case(n))
        {
            continue;
        }
        let (rw, rr, dl) = sampler.recent(pid, RATE_WINDOW).unwrap_or((0, 0, 0));
        let (pw, pl, pr) = sampler.probe_delta(pid).unwrap_or((0, 0, 0));
        let rw = rw.max(pw).max(pl);
        let rr = rr.max(pr);
        let logical = dl.max(pl);
        let span = sampler.span(pid);
        let alive = sampler.is_alive(pid);
        let mut reasons = Vec::new();
        if what == "read" {
            reasons.push(format!(
                "read {} during a decoy trip (peak {} over {:.1}s)",
                human_bytes(rr.max(read)),
                human_bytes(read),
                span.as_secs_f64().max(0.1)
            ));
        } else {
            reasons.push(format!(
                "wrote {} in a {:.1}s window spanning the incident",
                human_bytes(rw.max(written)),
                span.as_secs_f64().max(0.1)
            ));
        }
        if !alive {
            reasons.push("process has already exited".into());
        }
        suspects.push(Suspect {
            pid,
            ppid,
            name,
            exe: exe.map(|p| p.display().to_string()),
            uid,
            bytes_written: written.max(rw),
            bytes_read: read.max(rr),
            logical_writes: logical,
            recent_written: rw.max(written),
            recent_read: rr.max(read),
            reasons,
            held_open: Vec::new(),
            depth: 0,
            alive,
            age_ms: sampler.age_ms(pid),
        });
    }

    // ---- Pass 3: ancestry -------------------------------------------------
    let direct: Vec<(u32, String)> = suspects.iter().map(|s| (s.pid, s.name.clone())).collect();
    let mut seen: HashSet<u32> = suspects.iter().map(|s| s.pid).collect();
    for (pid, name) in direct {
        for (depth, anc) in sys::ancestors(pid).into_iter().enumerate().skip(1) {
            if anc.pid <= 1 || protected.contains(&anc.pid) || !seen.insert(anc.pid) {
                break;
            }
            if excluded(&anc) {
                break;
            }
            let shell = is_shell_like(&anc.exe_name());
            suspects.push(Suspect {
                pid: anc.pid,
                ppid: anc.ppid,
                name: anc.name.clone(),
                exe: anc.exe.as_ref().map(|p| p.display().to_string()),
                uid: anc.uid,
                bytes_written: anc.bytes_written,
                bytes_read: anc.bytes_read,
                logical_writes: anc.logical_writes,
                recent_written: 0,
                recent_read: 0,
                reasons: vec![format!("ancestor of {name} (depth {depth})")],
                held_open: Vec::new(),
                depth,
                alive: true,
                age_ms: sampler.age_ms(anc.pid),
            });
            // Walk past a shell to the script that started it, but do not
            // blame a whole GUI session.
            if !shell {
                break;
            }
        }
    }

    for s in suspects.iter_mut().filter(|s| s.depth == 0) {
        if let Some((pw, pl, pr)) = sampler.probe_delta(s.pid) {
            s.recent_written = s.recent_written.max(pw).max(pl);
            s.recent_read = s.recent_read.max(pr);
            s.bytes_written = s.bytes_written.max(s.recent_written);
        }
    }

    // Rate alone is the weakest evidence, so a rate-only suspect must be a
    // *dominant* writer: within 30% of the largest rate-only writer in the
    // probe.  That keeps the encryptor (the top writer by construction, since
    // it produced the burst) and drops background daemons that merely have
    // busy I/O counters.  A near-tie between two processes is retained as-is
    // and left for the confidence ranking.
    // Score = rate scaled down by age: a burst from a 2-second-old process is
    // the actor; the same volume from a daemon that has run for days is noise.
    let weighted = |s: &Suspect| -> u64 {
        let age = s.age_ms.unwrap_or(3_600_000).max(1);
        s.recent_written.saturating_mul(1_000_000) / age.max(1_000)
    };
    let top_weight = suspects
        .iter()
        .filter(|s| s.depth == 0 && s.held_open.is_empty())
        .map(weighted)
        .max()
        .unwrap_or(0);
    if top_weight > 0 {
        suspects.retain(|s| {
            if !s.held_open.is_empty() || s.depth > 0 {
                return true;
            }
            weighted(s) * 10 >= top_weight * 7
        });
    }

    suspects.sort_by_key(|s| std::cmp::Reverse(s.confidence()));
    suspects
}

fn is_shell_like(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "sh" | "bash" | "zsh" | "dash" | "fish" | "ksh" | "csh" | "tcsh" | "python"
            | "python3" | "perl" | "ruby" | "node" | "osascript" | "env"
    )
}

/// Suspend (or, for dry-run, just report) the blamed processes.
pub fn suspend_suspects(suspects: &[Suspect], cfg: &Config, dry_run: bool) -> Vec<ActionRecord> {
    let mut actions = Vec::new();
    let mut done = HashSet::new();
    // Only act on suspects we actually believe; an ancestry-only entry is
    // reported for context but not stopped.
    let min_confidence = 40;
    for s in suspects {
        if !done.insert(s.pid) {
            continue;
        }
        if s.depth > 0 || s.confidence() < min_confidence {
            continue;
        }
        if !s.alive && sys::status(s.pid).is_none() {
            actions.push(ActionRecord {
                action: "suspend(skipped)".into(),
                pid: s.pid,
                name: s.name.clone(),
                ok: false,
                error: Some("process had already exited; cannot suspend".into()),
            });
            continue;
        }
        if dry_run {
            actions.push(ActionRecord {
                action: "suspend(dry-run)".into(),
                pid: s.pid,
                name: s.name.clone(),
                ok: true,
                error: None,
            });
            continue;
        }
        if !cfg.response.suspend {
            actions.push(ActionRecord {
                action: "suspend(disabled)".into(),
                pid: s.pid,
                name: s.name.clone(),
                ok: false,
                error: Some("response.suspend = false in configuration".into()),
            });
            continue;
        }
        match sys::suspend(s.pid) {
            Ok(()) => {
                // Confirm the process actually stopped.
                let stopped = sys::is_stopped(s.pid);
                actions.push(ActionRecord {
                    action: "SIGSTOP".into(),
                    pid: s.pid,
                    name: s.name.clone(),
                    ok: stopped,
                    error: if stopped {
                        None
                    } else {
                        Some("signal sent but process is not in stopped state".into())
                    },
                });
            }
            Err(e) => actions.push(ActionRecord {
                action: "SIGSTOP".into(),
                pid: s.pid,
                name: s.name.clone(),
                ok: false,
                error: Some(e.to_string()),
            }),
        }
    }
    actions
}

#[derive(Serialize)]
struct ForensicBundle<'a> {
    incident: &'a Incident,
    suspects: &'a [Suspect],
    actions: &'a [ActionRecord],
    captured_at: String,
    watch_roots: Vec<String>,
    processes: Vec<ProcDump>,
    /// Per-path facts, so files can be triaged after the fact even if the
    /// attacker renames them.
    files: Vec<FileFact>,
    decoy_trips: Vec<DecoyFact>,
}

#[derive(Serialize)]
struct ProcDump {
    pid: u32,
    ppid: u32,
    name: String,
    exe: Option<String>,
    uid: u32,
    bytes_written: u64,
    bytes_read: u64,
    logical_writes: u64,
    recent_written: u64,
    recent_read: u64,
    /// Suspended or not at capture time.
    stopped: bool,
    open_files: Vec<String>,
}

#[derive(Serialize)]
struct FileFact {
    path: String,
    exists: bool,
    size: Option<u64>,
    mtime: Option<String>,
    extension: Option<String>,
    sample_entropy: Option<f32>,
    first_bytes_hex: Option<String>,
    note_language: bool,
}

#[derive(Serialize)]
struct DecoyFact {
    path: String,
    action: String,
}

/// Write a forensic bundle for an incident.  Returns the directory created.
pub fn capture_evidence(
    incident: &Incident,
    suspects: &[Suspect],
    actions: &[ActionRecord],
    watch_roots: &[PathBuf],
    cfg: &Config,
    decoy_trips: &[(PathBuf, DecoyAction)],
) -> std::io::Result<PathBuf> {
    let base = cfg
        .response
        .evidence_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("ransomwatch-evidence"));
    let stamp = chrono::Local::now().format("%Y%m%dT%H%M%S%.3f");
    let dir = base.join(format!("incident-{stamp}"));
    std::fs::create_dir_all(&dir)?;

    let mut processes = Vec::new();
    for s in suspects {
        if let Some(info) = sys::process_info(s.pid, true) {
            processes.push(ProcDump {
                pid: info.pid,
                ppid: info.ppid,
                name: info.name,
                exe: info.exe.as_ref().map(|p| p.display().to_string()),
                uid: info.uid,
                bytes_written: info.bytes_written,
                bytes_read: info.bytes_read,
                logical_writes: info.logical_writes,
                recent_written: s.recent_written,
                recent_read: s.recent_read,
                stopped: sys::is_stopped(s.pid),
                open_files: info
                    .open_files
                    .iter()
                    .map(|f| {
                        format!(
                            "{} ({})",
                            f.path.display(),
                            if f.writable { "w" } else { "r" }
                        )
                    })
                    .collect(),
            });
        }
    }

    let mut files = Vec::new();
    for p in &incident.top_paths {
        let meta = std::fs::metadata(p).ok();
        let sample = crate::entropy::sample_file(p, crate::entropy::SampleConfig::small()).ok();
        let head_hex = sample.as_ref().map(|s| {
            s.head
                .iter()
                .take(16)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        });
        let note = sample
            .as_ref()
            .map(|s| crate::format::looks_like_ransom_note_body(&String::from_utf8_lossy(&s.head)))
            .unwrap_or(false);
        files.push(FileFact {
            path: p.display().to_string(),
            exists: meta.is_some(),
            size: meta.as_ref().map(|m| m.len()),
            mtime: meta
                .as_ref()
                .and_then(|m| m.modified().ok())
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Local> = t.into();
                    dt.to_rfc3339()
                }),
            extension: p
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(crate::format::extension_of),
            sample_entropy: sample.as_ref().map(|s| s.entropy),
            first_bytes_hex: head_hex,
            note_language: note,
        });
    }

    let decoy_facts: Vec<DecoyFact> = decoy_trips
        .iter()
        .map(|(p, a)| DecoyFact {
            path: p.display().to_string(),
            action: a.as_str().to_string(),
        })
        .collect();

    let bundle = ForensicBundle {
        incident,
        suspects,
        actions,
        captured_at: chrono::Local::now().to_rfc3339(),
        watch_roots: watch_roots.iter().map(|p| p.display().to_string()).collect(),
        processes,
        files,
        decoy_trips: decoy_facts,
    };

    let json = serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".into());
    std::fs::write(dir.join("incident.json"), json)?;

    // Plain-text summary for humans and ticketing systems.
    let mut summary = String::new();
    summary.push_str("RANSOMWATCH INCIDENT\n");
    summary.push_str(&format!(
        "captured: {}\nscore: {}\ndry_run: false\n\n",
        bundle.captured_at, incident.score
    ));
    summary.push_str("Signals:\n");
    for s in &incident.signals {
        summary.push_str(&format!(
            "  - {:<32} +{:<4} {}\n",
            s.kind.as_str(),
            s.score(),
            s.detail
        ));
    }
    summary.push_str("\nBlamed processes (ranked by confidence):\n");
    for s in suspects {
        summary.push_str(&format!(
            "  pid {} ({}) ppid {} uid {} conf {} depth {}\n    wrote {} ({}) read {}\n    \
             reasons: {}\n    held open: {}\n",
            s.pid,
            s.name,
            s.ppid,
            s.uid,
            s.confidence(),
            s.depth,
            human_bytes(s.bytes_written),
            human_bytes(s.recent_written),
            human_bytes(s.bytes_read),
            s.reasons.join("; "),
            s.held_open.join(", ")
        ));
    }
    summary.push_str("\nActions:\n");
    if actions.is_empty() {
        summary.push_str("  (none)\n");
    }
    for a in actions {
        summary.push_str(&format!(
            "  {} pid {} ({}) ok={}{}\n",
            a.action,
            a.pid,
            a.name,
            a.ok,
            a.error
                .as_ref()
                .map(|e| format!(" error={e}"))
                .unwrap_or_default()
        ));
    }
    summary.push_str("\nEvidence paths:\n");
    for f in incident.top_paths.iter().take(20) {
        summary.push_str(&format!("  {}\n", f.display()));
    }
    summary.push_str("\nDecoy trips:\n");
    for (p, a) in decoy_trips {
        summary.push_str(&format!("  {} {}\n", a.as_str(), p.display()));
    }
    std::fs::write(dir.join("summary.txt"), summary)?;

    let manifest = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "captured_unix": now_unix(),
        "suspects": suspects.iter().map(|s| s.pid).collect::<Vec<_>>(),
        "signals": incident.signals.iter().map(|s| s.kind.as_str()).collect::<Vec<_>>(),
        "actuated": actions.iter().any(|a| a.ok && a.action == "SIGSTOP"),
    });
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap_or_default(),
    )?;

    Ok(dir)
}

/// Optional operator hook: pipe incident JSON to a shell command.
pub fn run_hook(
    command: &str,
    incident: &Incident,
    suspects: &[Suspect],
    actions: &[ActionRecord],
) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    let payload = serde_json::json!({
        "incident": incident,
        "suspects": suspects,
        "actions": actions,
    });
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(payload.to_string().as_bytes());
    }
    let _ = child.wait();
    Ok(())
}

/// Suspend and report.  Called by the engine when the detector opens an
/// incident.
pub fn respond(
    incident: &Incident,
    watch_roots: &[PathBuf],
    cfg: &Config,
    decoy_trips: &[(PathBuf, DecoyAction)],
    sampler: &ProcSampler,
) -> ResponseReport {
    let dry_run = cfg.response.dry_run;
    let mut sampler = sampler.clone_shallow();
    // An incident can open within 100 ms of the first rewrites, before any
    // periodic sample has a delta.  Take a synchronous one, and sweep the fd
    // table a few times while the writer is still going, so attribution has
    // something to work with.
    sampler.probe(Duration::from_millis(250));
    for _ in 0..3 {
        sampler.record_open_fds(watch_roots);
        std::thread::sleep(Duration::from_millis(60));
    }
    sampler.record_open_fds(watch_roots);
    let suspects = attribute(incident, watch_roots, cfg, &sampler);

    let actions = suspend_suspects(&suspects, cfg, dry_run);
    let mut evidence_dir = None;
    if !dry_run {
        match capture_evidence(incident, &suspects, &actions, watch_roots, cfg, decoy_trips) {
            Ok(d) => evidence_dir = Some(d.display().to_string()),
            Err(e) => eprintln!("ransomwatch: evidence capture failed: {e}"),
        }
        if let Some(cmd) = &cfg.response.on_incident_command {
            if let Err(e) = run_hook(cmd, incident, &suspects, &actions) {
                eprintln!("ransomwatch: incident hook failed: {e}");
            }
        }
    }
    let suspended = actions.iter().any(|a| a.ok && a.action == "SIGSTOP");
    ResponseReport {
        suspended,
        dry_run,
        suspects,
        actions,
        evidence_dir,
    }
}

/// Verdict on who read a decoy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReaderVerdict {
    /// All processes with read activity are known backup/indexing tools.
    BenignOnly,
    /// One or more processes with read activity are not on the allow list.
    Suspicious(Vec<u32>),
    /// No read activity could be measured (too fast, or no sampling yet).
    Unknown,
}

/// Decide whether a decoy read is attributable to benign tooling.
///
/// Coarse by necessity: read counters are per process, not per file.  We look
/// at every process with a meaningful read delta and ask whether it is on the
/// allow list.  A single unrecognised reader is enough to keep the trip.
pub fn classify_readers(sampler: &ProcSampler, cfg: &Config, _path: &Path) -> ReaderVerdict {
    let mut readers = 0usize;
    let mut suspicious = Vec::new();
    for (&pid, &(_, _, read)) in sampler.probe_deltas() {
        if read >= READ_RATE_SUSPECT_BYTES {
            readers += 1;
            let name = sampler
                .identity(pid)
                .map(|i| i.exe_name())
                .unwrap_or_default();
            if !cfg.is_allowed_process(&name) {
                suspicious.push(pid);
            }
        }
    }
    // Also consider the periodic history, where probe deltas are absent.
    for (pid, _read) in sampler.read_burst(READ_RATE_SUSPECT_BYTES) {
        readers += 1;
        let name = sampler
            .identity(pid)
            .map(|i| i.exe_name())
            .unwrap_or_default();
        if !cfg.is_allowed_process(&name) && !suspicious.contains(&pid) {
            suspicious.push(pid);
        }
    }
    if suspicious.is_empty() {
        if readers > 0 {
            ReaderVerdict::BenignOnly
        } else {
            ReaderVerdict::Unknown
        }
    } else {
        ReaderVerdict::Suspicious(suspicious)
    }
}

/// Which parent directory names look like session roots (never suspend above
/// these).
pub fn is_system_dir(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/System") || s.starts_with("/usr") || s.starts_with("/Library/Apple")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Signal, SignalKind};

    #[test]
    fn confidence_ranks_open_fd_highest() {
        let base = Suspect {
            pid: 1,
            ppid: 1,
            name: "x".into(),
            exe: None,
            uid: 0,
            bytes_written: 0,
            bytes_read: 0,
            logical_writes: 0,
            recent_written: 0,
            recent_read: 0,
            reasons: vec![],
            held_open: vec![],
            depth: 0,
            alive: true,
            age_ms: None,
        };
        let mut a = base.clone();
        a.held_open = vec!["/w/a.txt".into()];
        let mut b = base.clone();
        b.recent_written = 16 * 1024 * 1024;
        assert!(a.confidence() > b.confidence());
        let mut c = base.clone();
        c.depth = 2;
        c.held_open = vec!["/w/a.txt".into()];
        assert!(c.confidence() < a.confidence());
    }

    #[test]
    fn dry_run_does_not_signal() {
        let cfg = Config::default();
        let inc = Incident {
            at: Instant::now(),
            score: 100,
            signals: vec![Signal {
                kind: SignalKind::DecoyTrip,
                at: Instant::now(),
                detail: "x".into(),
                sample_paths: vec![],
                count: 1,
            }],
            top_paths: vec![],
            observed_bytes: 0,
        };
        let sampler = ProcSampler::new();
        let mut cfg2 = cfg.clone();
        cfg2.response.dry_run = true;
        let report = respond(&inc, &[], &cfg2, &[], &sampler);
        // Dry run must never actuate: any action records are labelled dry-run.
        assert!(!report.suspended);
        assert!(report.actions.iter().all(|a| a.action.contains("dry-run") || !a.ok));
        assert!(report.evidence_dir.is_none());
    }
}
