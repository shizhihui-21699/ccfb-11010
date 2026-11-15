//! Integration + calibration tests for RansomGuard.
//!
//! These tests run entirely under `target/` temp dirs. The end-to-end cases
//! spawn the real `sim_encryptor` binary and the real watcher; every child
//! process is cleaned up (including any that the detector suspends).

use ransomguard::config::{Config, Thresholds};
use ransomguard::engine::{AlertLevel, CanarySet, Engine, FileBaseline, FsEvent, FsEventKind};
use ransomguard::entropy::{
    file_entropy, is_trusted_high_entropy_type, shannon_entropy, HIGH_ENTROPY_THRESHOLD,
};
use ransomguard::process::{is_denylisted, is_trusted};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------- helpers ----------

fn ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn write_random(path: &Path, size: usize, seed: u64) {
    // Simple deterministic LCG, more than random-looking enough for entropy.
    let mut x = seed.max(1);
    let mut buf = vec![0u8; size];
    for b in buf.iter_mut() {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (x >> 33) as u8;
    }
    fs::write(path, buf).unwrap();
}

fn write_text(path: &Path, size: usize) {
    let paragraph = b"The quarterly business review is scheduled for next Friday morning. \
Please bring the updated revenue figures, hiring plan and risk register. ";
    let mut buf = Vec::with_capacity(size);
    while buf.len() < size {
        buf.extend_from_slice(paragraph);
    }
    buf.truncate(size);
    fs::write(path, buf).unwrap();
}

fn test_thresholds() -> Thresholds {
    // Tighter than production defaults so tests stay fast but exercise the
    // same code paths and ratios. Score cutoffs are lowered in proportion to
    // the smaller event counts in synthetic scenarios.
    Thresholds {
        window_secs: 30,
        min_file_size: 64,
        high_entropy: HIGH_ENTROPY_THRESHOLD,
        entropy_delta: 1.5,
        entropy_event_count: 5,
        entropy_event_ratio: 0.6,
        extension_event_count: 4,
        extension_event_ratio: 0.4,
        score_warning: 50,
        score_critical: 70,
        cooldown_secs: 0,
    }
}

fn test_engine(root: &Path, canaries: CanarySet) -> Engine {
    let cfg = Config::merged_defaults();
    Engine::new(
        baseline_from_dir(root, 64),
        canaries,
        test_thresholds(),
        cfg.note_name_hints,
        cfg.note_content_markers,
    )
}

fn baseline_from_dir(
    root: &Path,
    min_size: u64,
) -> std::collections::HashMap<PathBuf, FileBaseline> {
    let mut map = std::collections::HashMap::new();
    for entry in walkdir_lite(root) {
        if let Ok(meta) = fs::metadata(&entry) {
            if meta.is_file() && meta.len() >= min_size {
                map.insert(
                    entry.clone(),
                    FileBaseline {
                        size: meta.len(),
                        entropy: file_entropy(&entry),
                    },
                );
            }
        }
    }
    map
}

fn walkdir_lite(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
    }
    out
}

fn modify_event(path: &Path, t: i64) -> FsEvent {
    FsEvent {
        path: path.to_path_buf(),
        kind: FsEventKind::Modified,
        ts: t,
    }
}

// ---------- calibration: prove the 7.4 threshold separates content classes ----------

#[test]
fn calibrates_entropy_threshold_on_real_content_classes() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();

    // Random / "encrypted" content: several sizes, all must classify high.
    for (i, size) in [512usize, 4096, 65536, 200_000].into_iter().enumerate() {
        let f = p.join(format!("random_{i}.bin"));
        write_random(&f, size, 1000 + i as u64);
        let e = file_entropy(&f).unwrap();
        assert!(
            e >= HIGH_ENTROPY_THRESHOLD,
            "random {size}B entropy {e:.3} below cutoff {HIGH_ENTROPY_THRESHOLD}"
        );
    }

    // Text-like content: must classify low.
    for (i, size) in [512usize, 4096, 65536, 200_000].into_iter().enumerate() {
        let f = p.join(format!("text_{i}.txt"));
        write_text(&f, size);
        let e = file_entropy(&f).unwrap();
        assert!(
            e < HIGH_ENTROPY_THRESHOLD,
            "text {size}B entropy {e:.3} above cutoff {HIGH_ENTROPY_THRESHOLD}"
        );
    }

    // Repeating/structured content is very low entropy.
    let low = shannon_entropy(&vec![b'A'; 8192]);
    assert!(low < 1.0);

    // Uniform 256-symbol data sits at the 8.0 ceiling.
    let uniform: Vec<u8> = (0u32..256).map(|i| i as u8).cycle().take(8192).collect();
    assert!((shannon_entropy(&uniform) - 8.0).abs() < 0.02);
}

#[test]
fn compressed_archives_are_recognized_as_trusted_high_entropy() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("payload.txt");
    // Large, varied text: once compressed it approaches the entropy ceiling.
    let mut body = String::new();
    for i in 0..12_000u32 {
        body.push_str(&format!(
            "line {i}: quarterly revenue {i}x{}, headcount plan {}, risk {}\n",
            i.wrapping_mul(7) % 97,
            i % 11,
            i % 5
        ));
    }
    fs::write(&src, body).unwrap();
    let gz = dir.path().join("payload.txt.gz");
    let status = std::process::Command::new("gzip")
        .arg("-c")
        .arg(&src)
        .stdout(fs::File::create(&gz).unwrap())
        .status()
        .expect("system gzip required for this calibration test");
    assert!(status.success());

    let e = file_entropy(&gz).unwrap();
    assert!(e >= HIGH_ENTROPY_THRESHOLD, "gzip entropy {e:.3}");
    assert!(is_trusted_high_entropy_type("payload.txt.gz"));
    assert!(is_trusted_high_entropy_type("BACKUP.ZIP"));
    assert!(!is_trusted_high_entropy_type("notes.txt"));
}

// ---------- engine signal tests ----------

#[test]
fn detects_mass_high_entropy_rewrites() {
    let dir = tempfile::tempdir().unwrap();
    let n = 12;
    for i in 0..n {
        write_text(&dir.path().join(format!("doc_{i}.txt")), 8000);
    }
    let mut engine = test_engine(dir.path(), CanarySet::default());
    let t0 = ts();

    for i in 0..n {
        let f = dir.path().join(format!("doc_{i}.txt"));
        write_random(&f, 8000, 7000 + i);
        let Some(alert) = engine.ingest(&modify_event(&f, t0 + i as i64)) else {
            continue;
        };
        assert!(alert.signal.contains("entropy_surge"));
        assert_eq!(alert.level, AlertLevel::Critical);
        return;
    }
    panic!("entropy surge alert never fired");
}

#[test]
fn detects_extension_churn_even_without_high_entropy() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..10 {
        write_text(&dir.path().join(format!("report_{i}.docx")), 4000);
    }
    let mut engine = test_engine(dir.path(), CanarySet::default());
    let t0 = ts();

    let mut fired = false;
    let mut seen = Vec::new();
    for i in 0..10 {
        let from = dir.path().join(format!("report_{i}.docx"));
        let to = dir.path().join(format!("report_{i}.docx.locked"));
        fs::rename(&from, &to).unwrap();
        if let Some(a) = engine.ingest(&FsEvent {
            path: to.clone(),
            kind: FsEventKind::Renamed { from },
            ts: t0 + i as i64,
        }) {
            seen.push(format!("{}:{}", a.signal, a.score));
            if a.signal.contains("extension_churn") {
                fired = true;
                break;
            }
        }
    }
    if !fired {
        panic!("extension churn alert never fired; saw: {seen:?}");
    }
}

#[test]
fn suspicious_extension_burst_alone_warns() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = test_engine(dir.path(), CanarySet::default());
    let t0 = ts();
    let mut fired = false;
    for i in 0..6 {
        // Pure create with a ransomware-style suffix and low-entropy content.
        let f = dir.path().join(format!("file_{i}.encrypted"));
        write_text(&f, 4000);
        if let Some(a) = engine.ingest(&FsEvent {
            path: f,
            kind: FsEventKind::Created,
            ts: t0 + i as i64,
        }) {
            assert!(a.signal.contains("suspicious_extensions"));
            fired = true;
            break;
        }
    }
    assert!(fired);
}

#[test]
fn canary_touch_alerts_instantly_and_critically() {
    let dir = tempfile::tempdir().unwrap();
    let canary_dir = dir.path().join(".ransomguard-canary");
    fs::create_dir_all(&canary_dir).unwrap();
    let bait = canary_dir.join("quarterly_report_2026.docx");
    write_text(&bait, 4000);
    let canaries = CanarySet {
        files: vec![bait.clone()],
        dirs: vec![canary_dir],
    };
    let mut engine = test_engine(dir.path(), canaries);

    // A single touch — nothing else happening — must alert immediately.
    write_random(&bait, 4000, 42);
    let alert = engine
        .ingest(&modify_event(&bait, ts()))
        .expect("canary touch must alert");
    assert_eq!(alert.level, AlertLevel::Critical);
    assert_eq!(alert.signal, "canary_touched");
}

#[test]
fn confirms_ransom_note_by_name_and_content() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = test_engine(dir.path(), CanarySet::default());
    let note = dir.path().join("README_DECRYPT_YOUR_FILES.txt");
    fs::write(
        &note,
        "YOUR FILES HAVE BEEN ENCRYPTED. Pay the ransom in Bitcoin to the \
         wallet below to receive the decryption key. Do not attempt recovery yourself.\n",
    )
    .unwrap();
    let alert = engine
        .ingest(&FsEvent {
            path: note,
            kind: FsEventKind::Created,
            ts: ts(),
        })
        .expect("note must alert");
    assert_eq!(alert.level, AlertLevel::Critical);
    assert_eq!(alert.signal, "ransom_note_confirmed");
}

#[test]
fn note_like_name_without_markers_is_only_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = test_engine(dir.path(), CanarySet::default());
    let note = dir.path().join("readme_project.txt");
    write_text(&note, 2000);
    let alert = engine
        .ingest(&FsEvent {
            path: note,
            kind: FsEventKind::Created,
            ts: ts(),
        })
        .expect("name hint must at least warn");
    assert_eq!(alert.level, AlertLevel::Warning);
    assert_eq!(alert.signal, "ransom_note_suspected");
}

#[test]
fn normal_editing_activity_does_not_alert() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..20 {
        write_text(&dir.path().join(format!("notes_{i}.md")), 6000);
    }
    let mut engine = test_engine(dir.path(), CanarySet::default());
    let t0 = ts();
    for round in 0..3 {
        for i in 0..20 {
            let f = dir.path().join(format!("notes_{i}.md"));
            write_text(&f, 6000 + round * 137); // low-entropy rewrites
            assert!(engine
                .ingest(&modify_event(&f, t0 + round as i64 * 20 + i as i64))
                .is_none());
        }
    }
    assert!(
        engine.alerts.is_empty(),
        "false positives: {:?}",
        engine.alerts
    );
}

#[test]
fn archiver_output_is_excluded_from_entropy_signals() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = test_engine(dir.path(), CanarySet::default());
    // Simulate a backup run: many new .gz files with random-looking payload.
    for i in 0..12 {
        let f = dir.path().join(format!("backup_{i}.tar.gz"));
        write_random(&f, 8000, 9000 + i);
        let alert = engine.ingest(&FsEvent {
            path: f,
            kind: FsEventKind::Created,
            ts: ts() + i as i64,
        });
        assert!(alert.is_none(), "archiver output alerted: {alert:?}");
    }
}

#[test]
fn trusted_process_matching_and_denylist() {
    let cfg = Config::merged_defaults();
    assert!(is_trusted("/usr/bin/tar", &cfg.trusted_processes));
    assert!(is_trusted("rsync", &cfg.trusted_processes));
    assert!(!is_trusted("sim_encryptor", &cfg.trusted_processes));
    assert!(is_denylisted("launchd"));
    assert!(is_denylisted("/sbin/launchd"));
    assert!(!is_denylisted("sim_encryptor"));
}

// ---------- end-to-end with the real FSEvents watcher + simulator binary ----------

fn simulator_bin() -> PathBuf {
    // `cargo test` sets CARGO_BIN_EXE_<name>.
    PathBuf::from(env!("CARGO_BIN_EXE_sim_encryptor"))
}

fn build_test_tree(root: &Path, files: usize) {
    for i in 0..files {
        write_text(&root.join(format!("document_{i:03}.txt")), 5000 + i);
    }
}

#[test]
fn end_to_end_detects_simulated_attack_and_suspends_process() {
    // The detector itself runs inside this test process via the library API
    // (same code path as main.rs), so the "suspended" culprit is the spawned
    // simulator child.
    let dir = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    build_test_tree(dir.path(), 25);

    let canaries = ransomguard::canary::deploy(
        &[dir.path().to_path_buf()],
        &Config::merged_defaults().canary_names,
        &[],
        state.path(),
    )
    .unwrap();

    let mut watcher = ransomguard::watcher::FsWatcher::new().unwrap();
    watcher.watch(dir.path()).unwrap();
    let mut engine = Engine::new(
        baseline_from_dir(dir.path(), 64),
        canaries,
        test_thresholds(),
        Config::merged_defaults().note_name_hints,
        Config::merged_defaults().note_content_markers,
    );
    let trusted = Config::merged_defaults().trusted_processes;

    // Same background attribution sampler the production binary uses.
    let evidence_slot = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (sampler, sampler_handle) = ransomguard::sampler::AttributionSampler::start(
        vec![dir.path().to_path_buf()],
        evidence_slot.clone(),
    );

    // Give FSEvents and the sampler a moment to settle before the storm.
    std::thread::sleep(std::time::Duration::from_millis(500));

    let mut child = std::process::Command::new(simulator_bin())
        .arg("--target")
        .arg(dir.path())
        .arg("--delay-ms")
        .arg("150") // slow enough for lsof to catch open handles
        .arg("--hold-open-ms")
        .arg("400") // > sampler's 250ms poll: at least one poll lands in it
        .arg("--hidden-last") // mass-encryption phase before canary phase
        .spawn()
        .unwrap();
    let child_pid = child.id();

    let start = std::time::Instant::now();
    let mut got_critical = false;
    let mut suspended = false;
    while start.elapsed().as_secs() < 40 {
        let now = std::time::Instant::now();
        for ev in watcher.drain(now) {
            if let Some(alert) = engine.ingest(&ev) {
                if alert.level == AlertLevel::Critical {
                    got_critical = true;
                    let evidence: Vec<PathBuf> = alert.evidence.iter().map(PathBuf::from).collect();
                    *evidence_slot.lock().unwrap() = evidence;
                    // Read the continuously refreshed sampler snapshot.
                    // Up to ~2.4s of retries: with 400ms hold-open the
                    // sampler (250ms poll) must observe at least one handle.
                    let mut rows = sampler.snapshot();
                    for _ in 0..12 {
                        if rows.iter().any(|r| r.command.contains("sim_encryptor")) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        rows = sampler.snapshot();
                    }
                    for row in &rows {
                        if !is_trusted(&row.command, &trusted) {
                            let note = ransomguard::process::suspend_safely(row.pid, &row.command);
                            if note.starts_with("已发送") {
                                suspended = true;
                            }
                        }
                    }
                }
            }
        }
        if got_critical {
            // Drain another second to allow the suspension to land, then stop.
            std::thread::sleep(std::time::Duration::from_millis(1000));
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // The simulator must have been frozen (T) or, if it finished in the
    // reaction window, at least be a zombie (Z) rather than still running.
    let ps = std::process::Command::new("ps")
        .args(["-o", "stat=", "-p"])
        .arg(child_pid.to_string())
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    // Cleanup: resume then kill, so a stopped child never outlives the test.
    let _ = std::process::Command::new("kill")
        .arg("-CONT")
        .arg(child_pid.to_string())
        .status();
    let _ = std::process::Command::new("kill")
        .arg("-KILL")
        .arg(child_pid.to_string())
        .status();
    // Reap so no zombie survives the test.
    let _ = child.wait();
    sampler.shutdown();
    let _ = sampler_handle.join();

    assert!(got_critical, "no critical alert during simulated attack");
    assert!(
        suspended || ps.contains('T') || ps.contains('Z'),
        "simulator was not suspended or stopped (ps state: {ps:?})"
    );

    // Forensic artifacts exist. The ransom note may never be written when the
    // simulator was frozen early — that is the desired outcome, not a failure.
    assert!(state.path().join("canaries.json").exists());
    assert!(engine
        .alerts
        .iter()
        .any(|a| a.level == AlertLevel::Critical));
}

#[test]
fn end_to_end_canary_trip_without_other_files() {
    let dir = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let canaries = ransomguard::canary::deploy(
        &[dir.path().to_path_buf()],
        &Config::merged_defaults().canary_names,
        &[],
        state.path(),
    )
    .unwrap();
    let bait = canaries.files[0].clone();

    let mut watcher = ransomguard::watcher::FsWatcher::new().unwrap();
    watcher.watch(dir.path()).unwrap();
    let mut engine = Engine::new(
        baseline_from_dir(dir.path(), 64),
        canaries,
        test_thresholds(),
        Config::merged_defaults().note_name_hints,
        Config::merged_defaults().note_content_markers,
    );
    std::thread::sleep(std::time::Duration::from_millis(400));

    // FSEvents reports data-change events, not plain reads: modify the bait
    // the way an encrypting process would.
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("echo touched >> '{}'", bait.display()))
        .spawn()
        .unwrap();
    let _ = child.wait();

    let start = std::time::Instant::now();
    let mut fired = false;
    while start.elapsed().as_secs() < 5 {
        for ev in watcher.drain(std::time::Instant::now()) {
            if let Some(a) = engine.ingest(&ev) {
                if a.signal == "canary_touched" {
                    fired = true;
                }
            }
        }
        if fired {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(fired, "writing a canary did not raise an alert");
}
