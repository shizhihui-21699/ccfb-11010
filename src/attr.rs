//! "Who touched this file?"
//!
//! FSEvents does not say which process wrote a path, so attribution is done by
//! asking the kernel which processes hold the file open. On macOS that is
//! `proc_listallpids` + `proc_pidinfo(PROC_PIDLISTFDS)` +
//! `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)`, which enumerates every vnode fd
//! for every visible process through libproc in a few milliseconds — far cheaper
//! and more reliable than spawning `lsof` (and it works while the suspect is
//! blocked writing).
//!
//! Linux uses `/proc/<pid>/fd`. Other platforms return an empty set, and the
//! detector then reports the incident without a suspect process.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// A process that has at least one watched file open.
#[derive(Debug, Clone)]
pub struct OpenHolder {
    pub pid: i32,
    /// Path as the kernel reports it (canonicalised by the caller if needed).
    pub path: PathBuf,
    /// True when the fd was opened with write access.
    pub writable: bool,
    /// Open flags as reported (`fi_openflags`), for the record.
    pub open_flags: u32,
}

/// Enumerate all open vnode fds across all visible processes.
///
/// Returns (pid -> holders). Permission-denied processes are skipped silently:
/// on macOS most system processes are not inspectable by a non-root user, and
/// that is expected.
pub fn holders_by_pid() -> HashMap<i32, Vec<OpenHolder>> {
    #[cfg(target_os = "macos")]
    {
        macos::holders_by_pid()
    }
    #[cfg(target_os = "linux")]
    {
        linux::holders_by_pid()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        HashMap::new()
    }
}

/// All holder pids that have `target` open in a way matching `want_write`.
pub fn pids_holding(target: &Path, want_write: bool) -> Vec<i32> {
    let want = canonical_or_self(target);
    let mut out: Vec<i32> = Vec::new();
    for (pid, holds) in holders_by_pid() {
        for h in holds {
            let matches = h.path == want || h.path == target || same_inode(&h.path, &want);
            if matches && (!want_write || h.writable) {
                out.push(pid);
                break;
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn canonical_or_self(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn same_inode(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) {
            return ma.dev() == mb.dev() && ma.ino() == mb.ino();
        }
    }
    false
}

impl OpenHolder {
    pub fn is_write_fd(&self) -> bool {
        self.writable
    }
}

// ---------------------------------------------------------------------------
// Recent-holder attribution
// ---------------------------------------------------------------------------
//
// FSEvents arrives *after* the write, and a fast encryptor closes its fd before
// the detector has finished sampling the file. Polling holders only at alert
// time therefore misses exactly the processes worth catching.
//
// The sweep below runs continuously in the background and remembers, per path,
// which pids were seen holding it. When an incident fires, attribution combines
// the live sweep with this recent history, so "who wrote it" survives the
// suspect closing its file.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Per-path attribution facts gathered over the last few seconds.
#[derive(Debug, Clone, Default)]
pub struct RecentHolders {
    /// pid -> (last seen, was a write fd)
    pub pids: HashMap<i32, (Instant, bool)>,
}

/// Background fd sweeper.
pub struct HolderTracker {
    inner: Arc<Mutex<HashMap<PathBuf, RecentHolders>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    interval: Duration,
    retain: Duration,
}

impl HolderTracker {
    pub fn spawn(interval: Duration) -> Self {
        let inner: Arc<Mutex<HashMap<PathBuf, RecentHolders>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let retain = Duration::from_secs(12);
        let handle = {
            let inner = inner.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let t0 = Instant::now();
                    sweep_into(&inner, retain);
                    let elapsed = t0.elapsed();
                    std::thread::sleep(interval.saturating_sub(elapsed).max(Duration::from_millis(20)));
                }
            })
        };
        Self {
            inner,
            stop,
            handle: Some(handle),
            interval,
            retain,
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Cleared on stop so a long-lived tracker cannot grow without bound.
    pub fn retain(&self) -> Duration {
        self.retain
    }

    /// Pids recently seen holding `path`, newest first, write fds preferred.
    pub fn recent_for(&self, path: &Path) -> Vec<i32> {
        let map = match self.inner.lock() {
            Ok(m) => m,
            Err(e) => e.into_inner(),
        };
        let mut rec = map.get(path).cloned().unwrap_or_default();
        if rec.pids.is_empty() {
            // Paths are canonicalised by the kernel; try the canonical form too.
            if let Ok(c) = std::fs::canonicalize(path) {
                if let Some(r) = map.get(&c) {
                    rec = r.clone();
                }
            }
        }
        let mut v: Vec<(i32, Instant, bool)> =
            rec.pids.into_iter().map(|(p, (t, w))| (p, t, w)).collect();
        v.sort_by_key(|(_, t, w)| (u64::MAX - t.elapsed().as_secs(), !*w));
        v.into_iter().map(|(p, _, _)| p).collect()
    }

    /// Pids recently holding any directory that contains `path`, nearest
    /// directory first. A process walking a tree holds the directory it is
    /// iterating far longer than it holds any single file, so this is the
    /// sturdier attribution signal for a fast encryptor.
    pub fn recent_for_ancestors(&self, path: &Path) -> Vec<i32> {
        let map = match self.inner.lock() {
            Ok(m) => m,
            Err(e) => e.into_inner(),
        };
        let mut out: Vec<i32> = Vec::new();
        let mut cur = path.parent();
        let mut depth = 0;
        while let Some(dir) = cur {
            if depth > 8 {
                break;
            }
            if let Some(rec) = map.get(dir) {
                let mut pids: Vec<(i32, Instant, bool)> = rec
                    .pids
                    .iter()
                    .map(|(p, (t, w))| (*p, *t, *w))
                    .collect();
                pids.sort_by_key(|(_, t, w)| (u64::MAX - t.elapsed().as_secs(), !*w));
                for (p, _, _) in pids {
                    if !out.contains(&p) {
                        out.push(p);
                    }
                }
            }
            cur = dir.parent();
            depth += 1;
        }
        out
    }

    /// All paths that had at least one holder recently.
    pub fn tracked_paths(&self) -> Vec<PathBuf> {
        match self.inner.lock() {
            Ok(m) => m.keys().cloned().collect(),
            Err(e) => e.into_inner().keys().cloned().collect(),
        }
    }
}

impl Drop for HolderTracker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn sweep_into(inner: &Arc<Mutex<HashMap<PathBuf, RecentHolders>>>, retain: Duration) {
    let holders = holders_by_pid();
    let mut map = match inner.lock() {
        Ok(m) => m,
        Err(e) => e.into_inner(),
    };
    let now = Instant::now();
    for (pid, holds) in holders {
        for h in holds {
            let e = map.entry(h.path.clone()).or_default();
            e.pids.insert(pid, (now, h.writable));
        }
    }
    map.retain(|_, r| {
        r.pids.retain(|_, (t, _)| now.saturating_duration_since(*t) <= retain);
        !r.pids.is_empty()
    });
}

/// Names commonly used by installers/updaters that legitimately touch many
/// files. Kept separate from the "trusted tools" list in config so that
/// attribution can rank suspects sensibly.
pub fn is_system_helper(name: &str) -> bool {
    const HELPERS: &[&str] = &[
        "mdworker",
        "mdworker_shared",
        "mds",
        "mds_stores",
        "fseventsd",
        "Spotlight",
        "backupd",
        "backupd-helper",
        "QuickLookUIService",
        "QuickLook",
        "Finder",
        "Dock",
        "cfprefsd",
        "runningboardd",
        "launchd",
        "XprotectService",
        "XProtect",
        "syspolicyd",
        "coreduetd",
        "knowledgeconstructiond",
        "fileproviderd",
        "filecoordinationd",
        "com.apple.DiskManagement",
        "sandboxd",
    ];
    HELPERS.iter().any(|h| h == &name)
}

/// Rank candidate pids: prefer ones that are not system helpers, then ones with
/// more held files from the watch set, then the most recent.
pub fn rank_suspects(
    candidates: &HashSet<i32>,
    holder_counts: &HashMap<i32, usize>,
    start_times: &HashMap<i32, u64>,
    name_of: impl Fn(i32) -> Option<String>,
) -> Vec<i32> {
    let mut v: Vec<i32> = candidates.iter().copied().collect();
    v.sort_by_key(|&pid| {
        let sys = name_of(pid).map(|n| is_system_helper(&n)).unwrap_or(false);
        let cnt = holder_counts.get(&pid).copied().unwrap_or(0);
        let start = start_times.get(&pid).copied().unwrap_or(0);
        // Lower tuple sorts first: non-system, more files, newer process.
        (sys, usize::MAX - cnt, u64::MAX - start)
    });
    v
}

#[cfg(target_os = "macos")]
mod macos {
    use super::OpenHolder;
    use std::collections::HashMap;
    use std::ffi::CStr;

    const PROC_PIDLISTFDS: libc::c_int = 1;
    const PROC_PIDFDVNODEPATHINFO: libc::c_int = 2;
    const PROX_FDTYPE_VNODE: u32 = 1;
    /// `struct vnode_fdinfowithpath` on this SDK: proc_fileinfo (24) + vnode_info_path (1176).
    const VNODE_FDINFO_WITH_PATH_SIZE: usize = 1200;
    const MAXPATHLEN: usize = 1024;
    const FI_OFFSET: usize = 24;
    const VIP_PATH_OFFSET: usize = FI_OFFSET + 152;
    /// `fi_openflags` is *not* the fcntl access mode. It carries the BSD
    /// `struct file` flags: FREAD=0x1, FWRITE=0x2, FAPPEND=0x8 (verified
    /// against live processes on macOS 26: RDONLY=0x01, WRONLY=0x02, RDWR=0x03,
    /// O_APPEND=0x0a). So write capability is exactly the FWRITE bit.
    const FWRITE: u32 = 0x2;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcFdInfo {
        proc_fd: i32,
        proc_fdtype: u32,
    }

    extern "C" {
        fn proc_listallpids(buffer: *mut libc::c_int, buffersize: libc::c_int) -> libc::c_int;
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
        fn proc_pidfdinfo(
            pid: libc::c_int,
            fd: libc::c_int,
            flavor: libc::c_int,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }

    pub fn holders_by_pid() -> HashMap<i32, Vec<OpenHolder>> {
        let mut out: HashMap<i32, Vec<OpenHolder>> = HashMap::new();
        let pids = list_pids();
        let mut fd_buf = vec![ProcFdInfo { proc_fd: 0, proc_fdtype: 0 }; 512];
        let fd_bytes = std::mem::size_of::<ProcFdInfo>();
        let mut info_buf = vec![0u8; VNODE_FDINFO_WITH_PATH_SIZE];

        for pid in pids {
            if pid <= 0 {
                continue;
            }
            let mut cap = fd_buf.len();
            let mut got = unsafe {
                proc_pidinfo(
                    pid,
                    PROC_PIDLISTFDS,
                    0,
                    fd_buf.as_mut_ptr() as *mut libc::c_void,
                    (cap * fd_bytes) as libc::c_int,
                )
            };
            // Grow when the process holds more fds than our first buffer.
            while got > 0 && got as usize >= cap * fd_bytes {
                cap *= 2;
                fd_buf.resize(cap, ProcFdInfo { proc_fd: 0, proc_fdtype: 0 });
                got = unsafe {
                    proc_pidinfo(
                        pid,
                        PROC_PIDLISTFDS,
                        0,
                        fd_buf.as_mut_ptr() as *mut libc::c_void,
                        (cap * fd_bytes) as libc::c_int,
                    )
                };
            }
            if got <= 0 {
                continue;
            }
            let count = (got as usize / fd_bytes).min(cap);
            let mut holds: Vec<OpenHolder> = Vec::new();
            for fd in &fd_buf[..count] {
                if fd.proc_fdtype != PROX_FDTYPE_VNODE {
                    continue;
                }
                let r = unsafe {
                    proc_pidfdinfo(
                        pid,
                        fd.proc_fd,
                        PROC_PIDFDVNODEPATHINFO,
                        info_buf.as_mut_ptr() as *mut libc::c_void,
                        VNODE_FDINFO_WITH_PATH_SIZE as libc::c_int,
                    )
                };
                if r < (VIP_PATH_OFFSET + 2) as libc::c_int {
                    continue;
                }
                let path = match extract_path(&info_buf[VIP_PATH_OFFSET..(r as usize).min(VNODE_FDINFO_WITH_PATH_SIZE)]) {
                    Some(p) => p,
                    None => continue,
                };
                let flags =
                    u32::from_le_bytes([info_buf[0], info_buf[1], info_buf[2], info_buf[3]]);
                holds.push(OpenHolder {
                    pid,
                    path,
                    writable: flags & FWRITE != 0,
                    open_flags: flags,
                });
            }
            if !holds.is_empty() {
                out.insert(pid, holds);
            }
        }
        out
    }

    fn list_pids() -> Vec<i32> {
        let mut cap = 1024usize;
        loop {
            let mut pids = vec![0i32; cap];
            let n = unsafe {
                proc_listallpids(pids.as_mut_ptr(), (cap * std::mem::size_of::<i32>()) as libc::c_int)
            };
            if n <= 0 {
                return Vec::new();
            }
            let n = n as usize;
            if n < cap {
                pids.truncate(n);
                pids.retain(|&p| p > 0);
                return pids;
            }
            cap *= 2;
        }
    }

    /// `vip_path` is a NUL-terminated C string at a fixed offset. Some kernels
    /// report a truncated prefix; take everything up to the first NUL.
    fn extract_path(buf: &[u8]) -> Option<std::path::PathBuf> {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        if end == 0 {
            return None;
        }
        let bytes = &buf[..end.min(MAXPATHLEN - 1)];
        let s = std::str::from_utf8(bytes).ok()?;
        if !s.starts_with('/') {
            return None;
        }
        Some(std::path::PathBuf::from(s))
    }

    #[allow(dead_code)]
    fn cstr(buf: &[u8]) -> Option<&CStr> {
        CStr::from_bytes_until_nul(buf).ok()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::OpenHolder;
    use std::collections::HashMap;
    use std::os::unix::fs::MetadataExt;

    pub fn holders_by_pid() -> HashMap<i32, Vec<OpenHolder>> {
        let mut out = HashMap::new();
        let rd = match std::fs::read_dir("/proc") {
            Ok(r) => r,
            Err(_) => return out,
        };
        for entry in rd.flatten() {
            let name = entry.file_name();
            let pid: i32 = match name.to_string_lossy().parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let fd_dir = format!("/proc/{}/fd", pid);
            let fds = match std::fs::read_dir(&fd_dir) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let mut holds = Vec::new();
            for fd in fds.flatten() {
                let link = match std::fs::read_link(fd.path()) {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                if !link.is_absolute() {
                    continue;
                }
                // Writable fds on Linux are visible in /proc/<pid>/fdinfo flags.
                let flags = std::fs::read_to_string(format!(
                    "/proc/{}/fdinfo/{}",
                    pid,
                    fd.file_name().to_string_lossy()
                ))
                .ok()
                .and_then(|t| {
                    t.lines()
                        .find(|l| l.starts_with("flags:"))
                        .and_then(|l| u32::from_str_radix(l[6..].trim(), 8).ok())
                })
                .unwrap_or(0);
                let _ = MetadataExt::ino(&std::fs::metadata(fd.path()).unwrap_or_else(|_| {
                    std::fs::metadata("/").unwrap()
                }));
                holds.push(OpenHolder {
                    pid,
                    path: link,
                    writable: flags & 0o3 != 0,
                    open_flags: flags,
                });
            }
            if !holds.is_empty() {
                out.insert(pid, holds);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sees_our_own_open_file() {
        // Only meaningful where libproc/procfs is available.
        if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
            return;
        }
        let dir = std::env::temp_dir().join(format!("rw-proc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("held.txt");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&p)
            .unwrap();
        use std::io::Write;
        (&f).write_all(b"hello").unwrap();
        let pids = pids_holding(&p, true);
        assert!(
            pids.contains(&(std::process::id() as i32)),
            "expected own pid in {pids:?} for {}",
            p.display()
        );
        drop(f);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn system_helpers_recognised() {
        assert!(is_system_helper("mdworker_shared"));
        assert!(!is_system_helper("encryptor"));
    }
}
