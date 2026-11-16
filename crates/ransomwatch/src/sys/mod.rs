//! Platform process inspection and control.
//!
//! Everything the response side needs: enumerate processes, map their open
//! file descriptors to paths, read I/O counters, walk the ancestor chain, and
//! suspend/resume a process tree.

use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct OpenFile {
    pub path: PathBuf,
    /// `true` if the descriptor is open for writing (O_WRONLY / O_RDWR).
    pub writable: bool,
    pub fd: i32,
}

#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub uid: u32,
    /// Cumulative bytes written to disk by this process (best effort).
    pub bytes_written: u64,
    /// Cumulative bytes read from disk by this process (best effort).
    pub bytes_read: u64,
    /// Number of completed write operations, where the platform exposes it.
    pub logical_writes: u64,
    pub start_time: Option<SystemTime>,
    pub running: bool,
    pub open_files: Vec<OpenFile>,
}

impl ProcessInfo {
    /// Does this process currently hold `path` open for writing?
    pub fn holds_open_for_write(&self, path: &std::path::Path) -> bool {
        self.open_files
            .iter()
            .any(|f| f.writable && same_file(&f.path, path))
    }

    pub fn holds_open(&self, path: &std::path::Path) -> bool {
        self.open_files.iter().any(|f| same_file(&f.path, path))
    }

    pub fn exe_name(&self) -> String {
        self.exe
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.name.clone())
    }
}

/// Path canonicalisation is expensive and often unnecessary; compare the
/// textual forms after stripping the `/private` prefix that macOS reports back
/// from kernel APIs.
pub fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    if a == b {
        return true;
    }
    let (a, b) = (strip_private(a), strip_private(b));
    a == b
}

fn strip_private(p: &std::path::Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("/private") {
        PathBuf::from(rest)
    } else {
        PathBuf::from(s.as_ref())
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    // sys/proc_info.h constants (not all are exported by the libc crate).
    const PROC_ALL_PIDS: u32 = 1;
    const PROC_PIDTBSDINFO: i32 = 3;
    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_PIDFDVNODEPATHINFO: i32 = 2;
    const PROX_FDTYPE_VNODE: u32 = 1;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcFileInfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_guardflags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct VnodeFdInfoWithPath {
        pfi: ProcFileInfo,
        pvi: libc::vnode_info_path,
    }

    impl Default for VnodeFdInfoWithPath {
        fn default() -> Self {
            // All-zero is a valid POD representation for these structs.
            unsafe { std::mem::zeroed() }
        }
    }

    fn path_from_vip(vip: &libc::vnode_info_path) -> Option<PathBuf> {
        let mut bytes = Vec::with_capacity(1024);
        'outer: for chunk in vip.vip_path.iter() {
            for &c in chunk.iter() {
                if c == 0 {
                    break 'outer;
                }
                bytes.push(c as u8);
            }
        }
        if bytes.is_empty() {
            return None;
        }
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes)))
    }

    pub fn list_pids() -> Vec<u32> {
        let mut buf = vec![0i32; 16384];
        let n = unsafe {
            libc::proc_listpids(
                PROC_ALL_PIDS,
                0,
                buf.as_mut_ptr() as *mut libc::c_void,
                (buf.len() * std::mem::size_of::<i32>()) as i32,
            )
        };
        if n <= 0 {
            return Vec::new();
        }
        let count = (n as usize) / std::mem::size_of::<i32>();
        buf.truncate(count);
        buf.into_iter().filter(|p| *p > 0).map(|p| p as u32).collect()
    }

    fn bsd_info(pid: u32) -> Option<libc::proc_bsdinfo> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                std::mem::size_of::<libc::proc_bsdinfo>() as i32,
            )
        };
        if r == std::mem::size_of::<libc::proc_bsdinfo>() as i32 {
            Some(info)
        } else {
            None
        }
    }

    fn exe_path(pid: u32) -> Option<PathBuf> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let r = unsafe {
            libc::proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
        };
        if r <= 0 {
            return None;
        }
        buf.truncate(r as usize);
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buf)))
    }

    /// (bytes written, logical writes, bytes read) from rusage.
    fn rusage_io(pid: u32) -> (u64, u64, u64) {
        let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::proc_pid_rusage(pid as i32, libc::RUSAGE_INFO_V4, &mut info as *mut _ as *mut _)
        };
        if r == 0 {
            (
                info.ri_diskio_byteswritten,
                info.ri_logical_writes,
                info.ri_diskio_bytesread,
            )
        } else {
            (0, 0, 0)
        }
    }

    fn open_files(pid: u32) -> Vec<OpenFile> {
        let mut fds: Vec<libc::proc_fdinfo> = Vec::with_capacity(1024);
        fds.resize_with(1024, || unsafe { std::mem::zeroed() });
        let size = (fds.len() * std::mem::size_of::<libc::proc_fdinfo>()) as i32;
        let r = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr() as *mut libc::c_void,
                size,
            )
        };
        if r <= 0 {
            return Vec::new();
        }
        fds.truncate((r as usize) / std::mem::size_of::<libc::proc_fdinfo>());
        let mut out = Vec::new();
        for fd in fds {
            if fd.proc_fdtype != PROX_FDTYPE_VNODE || fd.proc_fd < 0 {
                continue;
            }
            let mut vn = VnodeFdInfoWithPath::default();
            let rr = unsafe {
                libc::proc_pidfdinfo(
                    pid as i32,
                    fd.proc_fd,
                    PROC_PIDFDVNODEPATHINFO,
                    &mut vn as *mut _ as *mut libc::c_void,
                    std::mem::size_of::<VnodeFdInfoWithPath>() as i32,
                )
            };
            if rr <= 0 {
                continue;
            }
            if let Some(path) = path_from_vip(&vn.pvi) {
                // FREAD | FWRITE are the O_RDONLY/O_WRONLY bits.
                let flags = vn.pfi.fi_openflags;
                out.push(OpenFile {
                    path,
                    writable: flags & 0x2 != 0,
                    fd: fd.proc_fd,
                });
            }
        }
        out
    }

    fn name_of(info: &libc::proc_bsdinfo) -> String {
        let raw: Vec<u8> = info
            .pbi_name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        if raw.is_empty() {
            info.pbi_comm
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect::<Vec<u8>>()
                .into_iter()
                .map(char::from)
                .collect()
        } else {
            String::from_utf8_lossy(&raw).into_owned()
        }
    }

    pub fn process_info(pid: u32, with_fds: bool) -> Option<ProcessInfo> {
        let info = bsd_info(pid)?;
        let (bytes_written, logical_writes, bytes_read) = rusage_io(pid);
        let start = SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(info.pbi_start_tvsec)
            + std::time::Duration::from_micros(info.pbi_start_tvusec);
        // pbi_status: 2 = SRUN, 4 = SSTOP, 5 = SZOMB.
        Some(ProcessInfo {
            pid,
            ppid: info.pbi_ppid,
            name: name_of(&info),
            exe: exe_path(pid),
            uid: info.pbi_uid,
            bytes_written,
            bytes_read,
            logical_writes,
            start_time: Some(start),
            running: info.pbi_status != 5,
            open_files: if with_fds { open_files(pid) } else { Vec::new() },
        })
    }

    pub fn status(pid: u32) -> Option<u32> {
        bsd_info(pid).map(|i| i.pbi_status)
    }

    /// Cheap I/O counters: (written, logical, read).
    pub fn io_counters(pid: u32) -> Option<(u64, u64, u64)> {
        let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::proc_pid_rusage(pid as i32, libc::RUSAGE_INFO_V4, &mut info as *mut _ as *mut _)
        };
        if r == 0 {
            Some((
                info.ri_diskio_byteswritten,
                info.ri_logical_writes,
                info.ri_diskio_bytesread,
            ))
        } else {
            None
        }
    }

    /// Identity fields needed to describe a process after it has exited.
    pub fn identity(pid: u32) -> Option<ProcessIdentity> {
        let info = bsd_info(pid)?;
        Some(ProcessIdentity {
            pid,
            ppid: info.pbi_ppid,
            name: name_of(&info),
            exe: exe_path(pid),
            uid: info.pbi_uid,
            start_time: Some(
                SystemTime::UNIX_EPOCH
                    + std::time::Duration::from_secs(info.pbi_start_tvsec)
                    + std::time::Duration::from_micros(info.pbi_start_tvusec),
            ),
        })
    }

    /// Files this process has open for writing (one fd-table sweep).
    pub fn writable_files(pid: u32) -> Vec<PathBuf> {
        open_files(pid)
            .into_iter()
            .filter(|f| f.writable)
            .map(|f| f.path)
            .collect()
    }

    pub fn signal(pid: u32, sig: i32) -> std::io::Result<()> {
        let r = unsafe { libc::kill(pid as i32, sig) };
        if r == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    fn read_stat(pid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()
    }

    /// Parse `pid (comm) state ppid ...`; comm may contain spaces and parens.
    fn parse_stat(s: &str) -> Option<(String, u32)> {
        let open = s.find('(')?;
        let close = s.rfind(')')?;
        let comm = s[open + 1..close].to_string();
        let rest = &s[close + 1..];
        let mut it = rest.split_whitespace();
        let _state = it.next()?;
        let ppid: u32 = it.next()?.parse().ok()?;
        Some((comm, ppid))
    }

    pub fn list_pids() -> Vec<u32> {
        let mut pids = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                if let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
        pids
    }

    fn read_link(path: String) -> Option<PathBuf> {
        std::fs::read_link(path).ok()
    }

    fn exe_path(pid: u32) -> Option<PathBuf> {
        let p = read_link(format!("/proc/{pid}/exe"))?;
        let s = p.to_string_lossy();
        // Strip the " (deleted)" suffix the kernel appends.
        let s = s.strip_suffix(" (deleted)").unwrap_or(&s);
        Some(PathBuf::from(s))
    }

    fn open_files(pid: u32) -> Vec<OpenFile> {
        let mut out = Vec::new();
        let dir = format!("/proc/{pid}/fd");
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return out;
        };
        for e in rd.flatten() {
            let Ok(fd) = e.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let Ok(target) = std::fs::read_link(e.path()) else {
                continue;
            };
            let ts = target.to_string_lossy();
            if !ts.starts_with('/') {
                continue; // socket, pipe, anon_inode, ...
            }
            let writable = fd_is_writable(pid, fd);
            out.push(OpenFile {
                path: PathBuf::from(ts.as_ref()),
                writable,
                fd,
            });
        }
        out
    }

    fn fd_is_writable(pid: u32, fd: i32) -> bool {
        let Ok(info) = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) else {
            return false;
        };
        for line in info.lines() {
            if let Some(rest) = line.strip_prefix("flags:\t") {
                if let Ok(flags) = u32::from_str_radix(rest.trim(), 8) {
                    return flags & 0o3 != 0; // O_WRONLY or O_RDWR
                }
            }
        }
        false
    }

    /// (bytes written, logical writes, bytes read) from /proc/<pid>/io.
    fn io_counters(pid: u32) -> (u64, u64, u64) {
        let Ok(io) = std::fs::read_to_string(format!("/proc/{pid}/io")) else {
            return (0, 0, 0);
        };
        let mut bytes = 0;
        let mut syscw = 0;
        let mut read = 0;
        for line in io.lines() {
            if let Some(v) = line.strip_prefix("write_bytes: ") {
                bytes = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("syscw: ") {
                syscw = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("read_bytes: ") {
                read = v.trim().parse().unwrap_or(0);
            }
        }
        (bytes, syscw, read)
    }

    pub fn process_info(pid: u32, with_fds: bool) -> Option<ProcessInfo> {
        let stat = read_stat(pid)?;
        let (name, ppid) = parse_stat(&stat)?;
        let (bytes_written, logical_writes, bytes_read) = io_counters(pid);
        let uid = std::fs::metadata(format!("/proc/{pid}"))
            .ok()
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.uid()
            })
            .unwrap_or(0);
        let running = !stat.contains(") Z");
        Some(ProcessInfo {
            pid,
            ppid,
            name,
            exe: exe_path(pid),
            uid,
            bytes_written,
            bytes_read,
            logical_writes,
            start_time: None,
            running,
            open_files: if with_fds { open_files(pid) } else { Vec::new() },
        })
    }

    pub fn status(pid: u32) -> Option<u32> {
        let stat = read_stat(pid)?;
        let close = stat.rfind(')')?;
        let state = stat.get(close + 1..)?.trim_start().chars().next()?;
        Some(match state {
            'R' => 2,
            'T' | 't' => 4,
            'Z' => 5,
            _ => 1,
        })
    }

    pub fn io_counters(pid: u32) -> Option<(u64, u64, u64)> {
        let io = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
        let mut bytes = 0;
        let mut syscw = 0;
        let mut read = 0;
        for line in io.lines() {
            if let Some(v) = line.strip_prefix("write_bytes: ") {
                bytes = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("syscw: ") {
                syscw = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("read_bytes: ") {
                read = v.trim().parse().unwrap_or(0);
            }
        }
        Some((bytes, syscw, read))
    }

    pub fn identity(pid: u32) -> Option<ProcessIdentity> {
        let info = process_info(pid, false)?;
        Some(ProcessIdentity {
            pid: info.pid,
            ppid: info.ppid,
            name: info.name,
            exe: info.exe,
            uid: info.uid,
            start_time: info.start_time,
        })
    }

    pub fn writable_files(pid: u32) -> Vec<PathBuf> {
        open_files(pid)
            .into_iter()
            .filter(|f| f.writable)
            .map(|f| f.path)
            .collect()
    }

    pub fn signal(pid: u32, sig: i32) -> std::io::Result<()> {
        let r = unsafe { libc::kill(pid as i32, sig) };
        if r == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use super::*;
    pub fn list_pids() -> Vec<u32> {
        Vec::new()
    }
    pub fn process_info(_pid: u32, _with_fds: bool) -> Option<ProcessInfo> {
        None
    }
    pub fn status(_pid: u32) -> Option<u32> {
        None
    }
    pub fn signal(_pid: u32, _sig: i32) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "process control not implemented for this platform",
        ))
    }
    pub fn io_counters(_pid: u32) -> Option<(u64, u64, u64)> {
        None
    }
    pub fn identity(_pid: u32) -> Option<ProcessIdentity> {
        None
    }
    pub fn writable_files(_pid: u32) -> Vec<PathBuf> {
        Vec::new()
    }
}

/// Identity fields that survive the process exiting.
#[derive(Clone, Debug)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub uid: u32,
    pub start_time: Option<SystemTime>,
}

impl ProcessIdentity {
    pub fn exe_name(&self) -> String {
        self.exe
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.name.clone())
    }
}

pub use imp::{identity, io_counters, list_pids, process_info, signal, status, writable_files};

pub const SIGSTOP: i32 = libc::SIGSTOP;
pub const SIGCONT: i32 = libc::SIGCONT;

/// Process is stopped (SSTOP == 4 on Darwin, 'T' on Linux).
pub fn is_stopped(pid: u32) -> bool {
    status(pid) == Some(4)
}

pub fn suspend(pid: u32) -> std::io::Result<()> {
    signal(pid, SIGSTOP)
}

pub fn resume(pid: u32) -> std::io::Result<()> {
    signal(pid, SIGCONT)
}

/// Snapshot all processes, optionally collecting open file descriptors.
pub fn snapshot(with_fds: bool) -> Vec<ProcessInfo> {
    list_pids()
        .into_iter()
        .filter_map(|pid| process_info(pid, with_fds))
        .collect()
}

/// Ancestor chain, nearest first, stopping at launchd/systemd (pid 1) and
/// guarding against cycles or stale pids.
pub fn ancestors(pid: u32) -> Vec<ProcessInfo> {
    let mut out = Vec::new();
    let mut cur = pid;
    let mut seen = std::collections::HashSet::new();
    for _ in 0..32 {
        if !seen.insert(cur) {
            break;
        }
        let Some(info) = process_info(cur, false) else {
            break;
        };
        let ppid = info.ppid;
        if ppid <= 1 || ppid == cur {
            out.push(info);
            break;
        }
        out.push(info);
        cur = ppid;
    }
    out
}

/// Direct children of `pid`.
pub fn children(pid: u32) -> Vec<ProcessInfo> {
    snapshot(false)
        .into_iter()
        .filter(|p| p.ppid == pid)
        .collect()
}

/// Every descendant of `pid` (breadth first).
pub fn descendants(pid: u32) -> Vec<ProcessInfo> {
    let all = snapshot(false);
    let mut out = Vec::new();
    let mut frontier = vec![pid];
    let mut seen = std::collections::HashSet::new();
    seen.insert(pid);
    while let Some(parent) = frontier.pop() {
        for p in all.iter().filter(|p| p.ppid == parent) {
            if seen.insert(p.pid) {
                out.push(p.clone());
                frontier.push(p.pid);
            }
        }
    }
    out
}

/// Current process and its ancestors; never suspend these.
pub fn protected_pids() -> Vec<u32> {
    ancestors(std::process::id()).into_iter().map(|p| p.pid).collect()
}

/// Current uid.
pub fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// Is the current process running with effective uid 0?
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
