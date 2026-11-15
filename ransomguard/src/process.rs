//! Process attribution, trusted-process filtering, suspension and forensics.
//!
//! Attribution strategy: when an alert fires we snapshot `lsof` for the
//! offending paths. Ransomware encrypts files by opening them one at a time,
//! so at any instant the currently-open file points straight at the culprit
//! PID. Sampling is repeated by the caller to catch short-lived handles.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct OpenFile {
    pub pid: u32,
    pub command: String,
    pub path: PathBuf,
}

/// Run lsof restricted to the given paths and parse its `-F` machine output.
pub fn lsof_for_paths(paths: &[PathBuf]) -> Vec<OpenFile> {
    if paths.is_empty() {
        return Vec::new();
    }
    let mut cmd = Command::new("lsof");
    // -F pcfln: pid, command, fd, lock, name ; -nP: skip DNS/port resolution.
    cmd.arg("-F").arg("pcfln").arg("-nP");
    for p in paths {
        cmd.arg(p);
    }
    let output = match cmd.output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    parse_lsof(&String::from_utf8_lossy(&output.stdout))
}

/// Global open-file snapshot. Note: on macOS a bare argument-less `lsof`
/// omits other processes' regular-file handles under shared temp dirs, so
/// callers must prefer [`lsof_under_roots`], which uses directory-scoped
/// `+D` queries that are not subject to that restriction.
pub fn lsof_global() -> Vec<OpenFile> {
    let output = Command::new("lsof").args(["-F", "pcfn", "-nP"]).output();
    match output {
        Ok(o) => parse_lsof(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => Vec::new(),
    }
}

/// Recursive open-file scan under each watched root via `lsof +D <dir>`,
/// plus exact-path queries for the alert's evidence files. This is the
/// reliable attribution path on macOS: neither bare `lsof` nor a plain
/// directory argument reports open regular files inside a directory — only
/// `+D` (recursive) or an exact filename argument do.
pub fn lsof_under_roots(roots: &[PathBuf], evidence: &[PathBuf]) -> Vec<OpenFile> {
    let mut rows = Vec::new();
    let mut cmd = Command::new("lsof");
    cmd.args(["-F", "pcfn", "-nP"]);
    let mut queried_any = false;
    for root in roots {
        // +D can be expensive on huge trees; roots here are monitored
        // document directories, and attribution only runs on alerts.
        cmd.arg("+D").arg(root);
        queried_any = true;
    }
    for path in evidence.iter().take(40) {
        cmd.arg(path);
        queried_any = true;
    }
    if !queried_any {
        return rows;
    }
    if let Ok(o) = cmd.output() {
        rows.extend(parse_lsof(&String::from_utf8_lossy(&o.stdout)));
    }
    // De-duplicate: the same handle can appear from +D and an exact path.
    rows.sort_by(|a, b| (a.pid, &a.command, &a.path).cmp(&(b.pid, &b.command, &b.path)));
    rows.dedup_by(|a, b| a.pid == b.pid && a.path == b.path);
    rows
}

/// Keep rows whose open path lies inside one of the watched roots.
pub fn filter_under_roots(rows: &[OpenFile], roots: &[PathBuf]) -> Vec<OpenFile> {
    rows.iter()
        .filter(|row| roots.iter().any(|root| row.path.starts_with(root)))
        .cloned()
        .collect()
}

/// Full open-file snapshot of one PID (for the forensic dump).
pub fn lsof_for_pid(pid: u32) -> String {
    Command::new("lsof")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-nP")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|_| "<lsof unavailable>".into())
}

fn parse_lsof(raw: &str) -> Vec<OpenFile> {
    let mut out = Vec::new();
    let mut pid: Option<u32> = None;
    let mut command = String::new();
    let mut in_file_entry = false;
    for line in raw.lines() {
        let (tag, value) = line.split_at(1);
        match tag {
            "p" => {
                pid = value.parse().ok();
                in_file_entry = false;
            }
            "c" => {
                command = value.to_string();
            }
            "f" => {
                in_file_entry = true; // new file descriptor entry
            }
            "n" if in_file_entry => {
                if let (Some(pid), false) = (pid, value.is_empty()) {
                    out.push(OpenFile {
                        pid,
                        command: command.clone(),
                        path: PathBuf::from(value),
                    });
                }
            }
            _ => {} // l (lock), and any future fields we did not request
        }
    }
    out
}

/// Keep only lsof rows whose open path equals a candidate or lies inside one.
pub fn filter_matches(rows: &[OpenFile], candidates: &[PathBuf]) -> Vec<OpenFile> {
    rows.iter()
        .filter(|row| {
            candidates
                .iter()
                .any(|c| row.path == *c || row.path.starts_with(c))
        })
        .cloned()
        .collect()
}

/// Basename match against the trusted archiver/backup list.
pub fn is_trusted(command: &str, trusted: &[String]) -> bool {
    let base = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    trusted
        .iter()
        .map(|t| t.to_ascii_lowercase())
        .any(|t| t == base)
}

/// Processes that must never be suspended, even under a false positive.
const SUSPEND_DENYLIST: &[&str] = &[
    "kernel_task",
    "launchd",
    "init",
    "windowserver",
    "loginwindow",
    "finder",
    "dock",
    "system",
    "syslogd",
    "opendirectoryd",
    "ransomguard",
];

pub fn is_denylisted(command: &str) -> bool {
    let base = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    SUSPEND_DENYLIST.iter().any(|d| *d == base)
}

fn current_pid() -> u32 {
    std::process::id()
}

fn ancestor_pids() -> Vec<u32> {
    // Walk the parent chain via libc getppid repeatedly is not possible
    // without re-exec; ps gives us the whole chain in one shot.
    let me = current_pid().to_string();
    let out = Command::new("ps").args(["-o", "pid,ppid", "-ax"]).output();
    let Ok(out) = out else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parent_of: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    for line in text.lines().skip(1) {
        let mut it = line.split_whitespace();
        if let (Some(p), Some(pp)) = (it.next(), it.next()) {
            if let (Ok(p), Ok(pp)) = (p.parse::<u32>(), pp.parse::<u32>()) {
                parent_of.insert(p, pp);
            }
        }
    }
    let mut chain = Vec::new();
    let mut cur = current_pid();
    while let Some(&pp) = parent_of.get(&cur) {
        if pp == 0 || pp == cur {
            break;
        }
        chain.push(pp);
        cur = pp;
    }
    let _ = me;
    chain
}

/// Whether suspending `pid` could harm the detector itself or the OS.
pub fn unsafe_to_suspend(pid: u32, command: &str) -> bool {
    pid <= 1 || pid == current_pid() || ancestor_pids().contains(&pid) || is_denylisted(command)
}

/// Send SIGSTOP. On success the process is frozen but still resumable
/// with `kill -CONT <pid>`.
pub fn suspend_pid(pid: u32) -> std::io::Result<()> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub fn process_state(pid: u32) -> String {
    Command::new("ps")
        .args(["-o", "pid,ppid,user,etime,%cpu,%mem,stat,command", "-p"])
        .arg(pid.to_string())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|_| format!("ps unavailable for pid {pid}"))
}

/// Freeze a PID (subject to safety checks) and return a human-readable note.
pub fn suspend_safely(pid: u32, command: &str) -> String {
    if unsafe_to_suspend(pid, command) {
        return format!("pid {pid} ({command}) 命中安全保护清单或为检测器自身/祖先进程, 跳过挂起");
    }
    match suspend_pid(pid) {
        Ok(()) => {
            format!("已发送 SIGSTOP 挂起可疑进程 pid={pid} ({command}); 恢复命令: kill -CONT {pid}")
        }
        Err(e) => format!("挂起 pid={pid} ({command}) 失败: {e} (可能需要更高权限)"),
    }
}

/// Persist everything an IR responder would want into `dir`.
pub fn capture_forensics(
    dir: &Path,
    pids: &[(u32, String)],
    lsof_snapshot: &[OpenFile],
    scene: &serde_json::Value,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("scene.json"), serde_json::to_vec_pretty(scene)?)?;

    let mut snap = String::new();
    for row in lsof_snapshot {
        snap.push_str(&format!(
            "{}\t{}\t{}\n",
            row.pid,
            row.command,
            row.path.display()
        ));
    }
    std::fs::write(dir.join("lsof_snapshot.tsv"), snap)?;

    for (pid, _cmd) in pids {
        std::fs::write(dir.join(format!("process_{pid}.txt")), process_state(*pid))?;
        std::fs::write(dir.join(format!("openfiles_{pid}.txt")), lsof_for_pid(*pid))?;
    }
    Ok(())
}
