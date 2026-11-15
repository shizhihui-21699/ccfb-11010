//! End-to-end acceptance tests.
//!
//! These run the real binary as a subprocess, point it at a real directory, and
//! drive it with the real built-in simulator — no mocking of the filesystem
//! watcher or the process table. That is deliberate: the whole point of this
//! tool is how it behaves against a live OS, and the unit tests cannot prove
//! FSEvents latency, fd attribution or SIGSTOP.
//!
//! Every test is confined to its own temp directory and asserts on the JSONL
//! incident log, so failures point at a concrete outcome rather than log text.
//!
//! The benign tests are the important ones. A detector that catches an encryptor
//! but also fires on `tar -czf` is worse than useless: operators turn it off.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> PathBuf {
    // `CARGO_BIN_EXE_<name>` is set by cargo for integration tests.
    PathBuf::from(env!("CARGO_BIN_EXE_ransomwatch"))
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "ransomwatch-test/{tag}-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("docs")).unwrap();
        Self { root }
    }

    fn docs(&self) -> PathBuf {
        self.root.join("docs")
    }

    /// Incidents land under `$HOME/.ransomwatch/incidents`, and the fixture's
    /// HOME is its own root.
    fn incidents(&self) -> PathBuf {
        self.root.join(".ransomwatch/incidents")
    }

    fn seed_documents(&self, n: usize) {
        for i in 0..n {
            let ext = ["docx", "xlsx", "pdf", "txt", "csv"][i % 5];
            let body = format!(
                "Quarterly report {i}\nRevenue and expenses for unit {i}.\n{}",
                "line of prose for the ledger and notes.\n".repeat(120)
            );
            std::fs::write(self.docs().join(format!("document-{i:03}")).with_extension(ext), body)
                .unwrap();
        }
    }

    fn watch_background(&self, args: &[&str], duration: u64) -> std::process::Child {
        let log = self.root.join("watch.log");
        let out = std::fs::File::create(&log).unwrap();
        let err = out.try_clone().unwrap();
        Command::new(bin())
            .arg("watch")
            .arg("--root")
            .arg(self.docs())
            .arg("--duration")
            .arg(duration.to_string())
            .args(args)
            .env("HOME", &self.root)
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawning watcher")
    }

    fn read_log(&self) -> String {
        std::fs::read_to_string(self.root.join("watch.log")).unwrap_or_default()
    }

    fn read_records(&self) -> Vec<serde_json::Value> {
        read_jsonl(&self.incidents().join("incidents.jsonl"))
    }

    fn sim(&self, extra: &[&str]) -> std::process::ExitStatus {
        Command::new(bin())
            .arg("sim")
            .arg(self.docs())
            .args(extra)
            .status()
            .expect("running simulator")
    }

    /// Simulator invocation. The simulator skips decoy-looking filenames by
    /// default (see `sim --help`), so content-signal tests are not drowned in
    /// decoy alerts. The decoy test opts back in with `--include-decoys`.
    fn sim_docs_only(&self, extra: &[&str]) -> std::process::ExitStatus {
        self.sim(extra)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Never leave decoys or suspended processes behind on failure.
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn read_jsonl(p: &Path) -> Vec<serde_json::Value> {
    let text = match std::fs::read_to_string(p) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn wait_for(pred: impl Fn() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// The core acceptance case: an encryptor rewrites documents in place.
#[test]
fn overwrite_encryptor_raises_high_severity_incident() {
    let f = Fixture::new("overwrite");
    f.seed_documents(40);
    let mut child = f.watch_background(&["--response", "alert"], 30);
    // Let the baseline and watcher settle.
    assert!(
        wait_for(|| f.read_log().contains("watching;"), Duration::from_secs(12)),
        "watcher never started:\n{}",
        f.read_log()
    );
    std::thread::sleep(Duration::from_millis(300));
    f.sim_docs_only(&["--overwrite-only", "--delay-ms", "30", "--remove-original"]);
    let _ = child.wait();

    let recs = f.read_records();
    assert!(
        !recs.is_empty(),
        "no incident recorded for an in-place encryptor:\n{}",
        f.read_log()
    );
    let rec = &recs[0];
    assert_eq!(rec["trigger"], "score");
    let sev = rec["severity"].as_str().unwrap_or("");
    assert!(sev == "high" || sev == "critical", "severity was {sev}");
    let kinds: Vec<&str> = rec["signals"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["kind"].as_str())
        .collect();
    assert!(
        kinds.contains(&"opaque_rewrite"),
        "expected opaque_rewrite, got {kinds:?}"
    );
    assert!(
        rec["distinct_files"].as_u64().unwrap_or(0) >= 3,
        "distinct_files was {}",
        rec["distinct_files"]
    );
}

/// Rename-style encryptor: documents come back as `doc.docx.locked`.
#[test]
fn rename_encryptor_fires_on_stacked_extensions() {
    let f = Fixture::new("rename");
    f.seed_documents(40);
    let mut child = f.watch_background(&["--response", "alert"], 30);
    assert!(wait_for(|| f.read_log().contains("watching;"), Duration::from_secs(12)));
    std::thread::sleep(Duration::from_millis(300));
    f.sim_docs_only(&["--extension", "locked", "--delay-ms", "25"]);
    let _ = child.wait();

    let recs = f.read_records();
    assert!(!recs.is_empty(), "no incident for a rename encryptor:\n{}", f.read_log());
    let kinds: Vec<String> = recs
        .iter()
        .flat_map(|r| r["signals"].as_array().cloned().unwrap_or_default())
        .filter_map(|s| s["kind"].as_str().map(|k| k.to_string()))
        .collect();
    assert!(
        kinds.iter().any(|k| k == "stacked_extension"),
        "expected stacked_extension in {kinds:?}"
    );
}

/// Intermittent encryption — every other 4 KiB block — is the tactic BlackCat/
/// ALPHV, LockFile and others use to go fast. It leaves most bytes untouched, so
/// a whole-file entropy check would miss it. This exercises the chunked sampler
/// through the full watcher, not just the classifier.
#[test]
fn intermittent_encryption_is_detected() {
    let f = Fixture::new("intermittent");
    f.seed_documents(20);
    let mut child = f.watch_background(&["--response", "alert"], 30);
    assert!(wait_for(|| f.read_log().contains("watching;"), Duration::from_secs(12)));
    std::thread::sleep(Duration::from_millis(300));

    let status = Command::new("python3")
        .arg("-c")
        .arg(r#"
import glob, hashlib, os, sys
root = sys.argv[1]
# Leave the canaries alone: this test is about content signals, and a decoy
# alert would otherwise be the first (and only) record.
DECOY = ('q3-budget', 'payroll', '董事会', 'project-atlas', 'supplier-list',
         'merger-due', '员工花名册', '客户合同')
def is_decoy(p):
    return any(m in os.path.basename(p).lower() for m in DECOY)
ks = b''.join(hashlib.sha256(b'k%d' % i).digest() for i in range(400_000))
def enc(b):
    return bytes(x ^ y for x, y in zip(b, ks[:len(b)]))
victims = [p for p in sorted(glob.glob(os.path.join(root, 'document-*')))]
victims = [p for p in victims if not is_decoy(p) and not p.endswith(('.jpg', '.zip'))]
for p in victims:
    d = open(p, 'rb').read()
    out = bytearray(d)
    for off in range(0, len(d), 8192):
        out[off:off+4096] = enc(d[off:off+4096])
    open(p, 'wb').write(bytes(out))
print('intermittent encryption applied to', len(victims), 'files', flush=True)
"#)
        .arg(f.docs().to_string_lossy().to_string())
        .status()
        .expect("intermittent workload");
    assert!(status.success());
    let _ = child.wait();

    let recs = f.read_records();
    // Decoy alerts may come first if the encryptor happened to touch a canary.
    // What this test is about is the content signal.
    let scored: Vec<&serde_json::Value> =
        recs.iter().filter(|r| r["trigger"] == "score").collect();
    assert!(
        !scored.is_empty(),
        "intermittent encryption was not detected:\n{}",
        f.read_log()
    );
    let details: String = serde_json::to_string(&scored).unwrap_or_default();
    assert!(
        details.contains("partial-opaque") || details.contains("opaque_rewrite"),
        "expected ciphertext evidence in {details}"
    );
}

/// A decoy that an unknown process opens for writing must fire immediately,
/// with no scoring, and identify that process.
#[test]
fn decoy_touch_fires_critical_and_names_the_process() {
    let f = Fixture::new("decoy");
    f.seed_documents(10);
    let mut child = f.watch_background(&["--response", "suspend"], 25);
    assert!(wait_for(|| f.read_log().contains("watching;"), Duration::from_secs(12)));

    // Find a planted decoy.
    let decoy = std::fs::read_dir(f.docs())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            let n = p.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
            n.contains("payroll") || n.contains("budget") || n.contains("contract")
                || n.contains("merger") || n.contains("supplier") || n.contains("atlas")
        })
        .expect("a decoy should have been planted");

    // Open it for writing from a helper process, hold it briefly, then let go.
    let mut appender = Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import time\nf=open({:?},'a')\nf.write('x'*64)\nf.flush()\ntime.sleep(1.5)",
            decoy.to_string_lossy()
        ))
        .spawn()
        .expect("spawning appender");
    let appender_pid = appender.id() as i32;

    let fired = wait_for(|| !f.read_records().is_empty(), Duration::from_secs(8));
    let recs_at_capture = f.read_records();

    // The appender may be suspended. Kill it rather than wait: `wait` on a
    // stopped process blocks forever, which would hang the suite.
    let _ = Command::new(bin())
        .args(["resume"])
        .arg(f.incidents())
        .env("HOME", &f.root)
        .status();
    let _ = resume_pid(appender_pid);
    let _ = appender.kill();
    let _ = appender.wait();
    let _ = child.kill();
    let _ = child.wait();

    assert!(fired, "decoy touch did not fire:\n{}", f.read_log());
    let recs = recs_at_capture;
    // The first record must be a decoy incident; content signals may follow.
    let rec = recs
        .iter()
        .find(|r| r["trigger"] == "decoy")
        .expect("a decoy-triggered record");
    assert_eq!(rec["trigger"], "decoy");
    assert_eq!(rec["severity"], "critical");
    assert!(rec["decoy"].is_object());
    let pids: Vec<i64> = rec["processes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["pid"].as_i64())
        .collect();
    assert!(
        pids.contains(&(appender_pid as i64)),
        "expected pid {appender_pid} in record, got {pids:?}\n{}",
        f.read_log()
    );
}

/// Suspension must actually stop the suspect, the record must name it, and
/// `resume` must be able to release it.
///
/// The sim is not waited on after resuming: the watcher is still running and
/// will legitimately re-suspend it, which is correct behaviour rather than a
/// test failure. The test kills the sim when it is done with it.
#[test]
fn suspect_is_suspended_and_resumable() {
    let f = Fixture::new("suspend");
    f.seed_documents(40);
    let mut child = f.watch_background(&["--response", "suspend"], 25);
    assert!(wait_for(|| f.read_log().contains("watching;"), Duration::from_secs(12)));
    std::thread::sleep(Duration::from_millis(300));

    // 150 ms per file: attribution is poll-based, and a writer that closes its
    // fd within a few milliseconds is genuinely hard to catch on macOS without
    // Endpoint Security (which needs root). This is the realistic budget the
    // README documents.
    let mut sim = Command::new(bin())
        .arg("sim")
        .arg(f.docs())
        .args(["--overwrite-only", "--delay-ms", "150"])
        .spawn()
        .expect("spawning sim");
    let sim_pid = sim.id() as i32;

    // The simulator should get frozen mid-run.
    let stopped = wait_for(
        || process_is_stopped(sim_pid).unwrap_or(false),
        Duration::from_secs(15),
    );
    // Seeing the process stopped and the record on disk are two different
    // events: the watcher sends SIGSTOP first and then finishes writing the
    // incident. Wait for the record to name this pid rather than racing it.
    let recorded = wait_for(
        || {
            f.read_records().iter().any(|r| {
                r["response"]["suspended_pids"]
                    .as_array()
                    .map(|a| a.iter().any(|v| v.as_i64() == Some(sim_pid as i64)))
                    .unwrap_or(false)
            })
        },
        Duration::from_secs(8),
    );
    let recs = f.read_records();
    let suspended: Vec<i64> = recs
        .iter()
        .flat_map(|r| r["response"]["suspended_pids"].as_array().cloned().unwrap_or_default())
        .filter_map(|v| v.as_i64())
        .collect();

    // Release everything the incident froze via the CLI, which is what an
    // operator would do, and verify the process moves out of the stopped state.
    let _ = Command::new(bin())
        .args(["resume"])
        .arg(f.incidents())
        .env("HOME", &f.root)
        .status();
    let resumed = wait_for(
        || matches!(process_is_stopped(sim_pid), Some(false)),
        Duration::from_secs(3),
    );

    // Tear down: kill the sim, then the watcher.
    let _ = sim.kill();
    let _ = sim.wait();
    let _ = child.kill();
    let _ = child.wait();

    assert!(stopped, "simulator was never suspended:\n{}", f.read_log());
    assert!(
        recorded,
        "no record named pid {sim_pid} within 8s of the freeze:\n{}",
        f.read_log()
    );
    assert!(
        suspended.contains(&(sim_pid as i64)),
        "record should name the suspended pid {sim_pid}, got {suspended:?}"
    );
    assert!(
        resumed,
        "resume did not release pid {sim_pid}:\n{}",
        f.read_log()
    );
}

fn resume_pid(pid: i32) -> bool {
    unsafe { libc::kill(pid, libc::SIGCONT) == 0 }
}

fn process_is_stopped(pid: i32) -> Option<bool> {
    let out = Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let stat = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if stat.is_empty() {
        return None;
    }
    Some(stat.starts_with('T'))
}

// ---------------------------------------------------------------------------
// False positives — the tests that matter most
// ---------------------------------------------------------------------------

/// A complete backup run written *inside* the watched directory: tar.gz of the
/// whole tree, per-file gzip/bzip2/xz, a zip archive, ditto and rsync mirrors.
/// Nothing here may raise an incident.
#[test]
fn compression_and_backup_workload_is_quiet() {
    let f = Fixture::new("benign-backup");
    f.seed_documents(60);
    let mut child = f.watch_background(&["--response", "alert", "--fail-on-incident"], 40);
    assert!(wait_for(|| f.read_log().contains("watching;"), Duration::from_secs(12)));
    std::thread::sleep(Duration::from_millis(300));

    let docs = f.docs();
    let status = Command::new("python3")
        .arg("-c")
        .arg(BENIGN_WORKLOAD)
        .arg(docs.to_string_lossy().to_string())
        .status()
        .expect("benign workload");
    assert!(status.success(), "benign workload failed");
    let watcher_status = child.wait().expect("watcher exit");

    let recs = f.read_records();
    assert!(
        recs.is_empty(),
        "backup/compression workload produced {} false positive(s):\n{}\n{}",
        recs.len(),
        serde_json::to_string_pretty(&recs).unwrap_or_default(),
        f.read_log()
    );
    assert_eq!(
        watcher_status.code(),
        Some(0),
        "--fail-on-incident must stay 0 on a benign workload\n{}",
        f.read_log()
    );
}

/// Ordinary editing: touch many files, append prose, rename within known
/// extensions. No encryption, no incident.
#[test]
fn plain_editing_is_quiet() {
    let f = Fixture::new("benign-edits");
    f.seed_documents(50);
    let mut child = f.watch_background(&["--response", "alert"], 25);
    assert!(wait_for(|| f.read_log().contains("watching;"), Duration::from_secs(12)));
    std::thread::sleep(Duration::from_millis(300));

    // Append to every document and rename a few to .bak.
    let docs = f.docs();
    let status = Command::new("python3")
        .arg("-c")
        .arg(r#"
import glob, os, shutil, sys
root = sys.argv[1]
for i, p in enumerate(sorted(glob.glob(os.path.join(root, 'document-*')))[:40]):
    if p.endswith(('.jpg', '.zip')):
        continue
    with open(p, 'a') as fh:
        fh.write('action item: follow up with finance\n')
for p in sorted(glob.glob(os.path.join(root, '*.csv')))[:5]:
    shutil.copy(p, p + '.bak')
print('edits done')
"#)
        .arg(docs.to_string_lossy().to_string())
        .status()
        .expect("edit workload");
    assert!(status.success());
    let _ = child.wait();

    let recs = f.read_records();
    assert!(
        recs.is_empty(),
        "plain editing produced {} false positive(s):\n{}\n{}",
        recs.len(),
        serde_json::to_string_pretty(&recs).unwrap_or_default(),
        f.read_log()
    );
}

/// The simulator must refuse to run outside a test directory.
#[test]
fn simulator_refuses_real_locations() {
    for bad in ["/Users/Shared/ransomwatch-test-home", "/tmp/../Users"] {
        let out = Command::new(bin()).arg("sim").arg(bad).arg("--dry-run").output().unwrap();
        // The first path contains "ransomwatch-test" so it is allowed; the
        // second resolves outside /tmp and must be refused.
        if bad == "/tmp/../Users" {
            assert!(
                !out.status.success(),
                "sim must refuse {bad}: {:?}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

const BENIGN_WORKLOAD: &str = r#"
import bz2, glob, gzip, lzma, os, shutil, subprocess, sys, tarfile, zipfile
root = sys.argv[1]
files = sorted(glob.glob(os.path.join(root, 'document-*')))
print('victims:', len(files), flush=True)

# 1. Whole-tree archive, the shape of every nightly backup.
with tarfile.open(os.path.join(root, 'daily-snapshot.tar.gz'), 'w:gz') as t:
    for f in files[:20]:
        t.add(f, arcname=os.path.basename(f))

# 2. Per-file compression into a subdirectory.
os.makedirs(os.path.join(root, 'compressed'), exist_ok=True)
for f in files[:25]:
    base = os.path.basename(f)
    data = open(f, 'rb').read()
    for ext, fn in (('.gz', gzip.compress), ('.bz2', bz2.compress), ('.xz', lzma.compress)):
        open(os.path.join(root, 'compressed', base + ext), 'wb').write(fn(data))

# 3. A zip archive.
with zipfile.ZipFile(os.path.join(root, 'bundle.zip'), 'w', zipfile.ZIP_DEFLATED) as z:
    for f in files[25:50]:
        z.write(f, os.path.basename(f))

# 4. Compressed copies that carry a stacked extension.
for f in files[50:55]:
    open(f + '.gz', 'wb').write(gzip.compress(open(f, 'rb').read()))

# 5. macOS copy and rsync mirrors.
subprocess.run(['ditto', os.path.join(root, 'compressed'), os.path.join(root, 'mirror')])
subprocess.run(['rsync', '-a', root + '/', os.path.join(root, 'synced')])

# 6. A cautious user's .bak copies.
for f in glob.glob(os.path.join(root, '*.csv'))[:5]:
    shutil.copy(f, f + '.bak')

print('benign workload complete', flush=True)
"#;
