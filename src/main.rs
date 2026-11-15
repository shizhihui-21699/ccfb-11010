//! `ransomwatch` — watch directories for ransomware behaviour.
//!
//! Subcommands:
//!   watch     run the monitor (default)
//!   scan      one-shot: scan a directory and report content classes
//!   sim       run the built-in encryptor against a throwaway test directory
//!             (this is the tool the acceptance test uses, and it is
//!             deliberately confined to the directory you pass)
//!   resume    SIGCONT every process an incident record suspended
//!   config    print the default configuration
//!   decoys    list / re-plant decoy files

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use notify::Watcher;
use ransomwatch::config::{Config, ResponseMode};
use ransomwatch::decoy::DecoySet;
use ransomwatch::detect::{self, Detector};
use ransomwatch::entropy;
use ransomwatch::events;
use ransomwatch::respond::Responder;
use ransomwatch::util;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "ransomwatch",
    version,
    about = "Endpoint-side early ransomware detection for a watched directory",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
    /// Config file (TOML). Defaults are used when omitted.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the monitor (default when no subcommand is given).
    Watch(WatchArgs),
    /// One-shot scan: classify the contents of a directory and exit.
    Scan(ScanArgs),
    /// Run the built-in test encryptor inside a throwaway directory.
    Sim(SimArgs),
    /// Resume (SIGCONT) processes suspended by a previous incident.
    Resume {
        /// Incident directory or the incident.json inside it.
        incident: PathBuf,
    },
    /// Print the default configuration as TOML.
    Config,
    /// List the decoy files for the configured roots (planting them if needed).
    Decoys {
        /// Re-plant missing decoys before listing.
        #[arg(long)]
        replant: bool,
    },
}

#[derive(Args, Debug)]
struct WatchArgs {
    /// Directory to protect. May be repeated. Overrides config `watch.roots`.
    #[arg(long = "root", short = 'r')]
    roots: Vec<PathBuf>,
    /// Exclusion prefix, repeated.
    #[arg(long = "exclude")]
    exclude: Vec<PathBuf>,
    /// Do not build the pre-existing-content baseline.
    #[arg(long)]
    no_baseline: bool,
    /// Disable decoy files for this run.
    #[arg(long)]
    no_decoys: bool,
    /// Response mode override: alert | suspend | none.
    #[arg(long)]
    response: Option<String>,
    /// Exit after this many seconds (0 = run forever). Used by tests.
    #[arg(long, default_value_t = 0)]
    duration: u64,
    /// Machine-readable event lines on stdout instead of human text.
    #[arg(long)]
    json: bool,
    /// Exit non-zero when an incident fires within `--duration`. Lets a CI job
    /// assert "no false positives" over a benign workload.
    #[arg(long)]
    fail_on_incident: bool,
}

#[derive(Args, Debug)]
struct ScanArgs {
    path: PathBuf,
    /// Print one line per file.
    #[arg(long)]
    verbose: bool,
}

#[derive(Args, Debug)]
struct SimArgs {
    /// The directory to encrypt. Must be inside a temporary or test directory:
    /// the simulator refuses to run anywhere that looks like real user data.
    dir: PathBuf,
    /// Files to create if the directory is empty.
    #[arg(long, default_value_t = 40)]
    create: usize,
    /// Rename encrypted files to this extension.
    #[arg(long, default_value = "locked")]
    extension: String,
    /// Write a ransom note.
    #[arg(long, default_value_t = true)]
    note: bool,
    /// Do not encrypt: only show what would be touched.
    #[arg(long)]
    dry_run: bool,
    /// Milliseconds to sleep between files (lets the watcher keep up).
    #[arg(long, default_value_t = 15)]
    delay_ms: u64,
    /// Delete the original after writing the encrypted copy.
    #[arg(long)]
    remove_original: bool,
    /// Keep the original content class low-entropy: simulate by writing text
    /// first, then encrypting.
    #[arg(long, default_value_t = false)]
    overwrite_only: bool,
    /// Also encrypt the decoy files. Off by default: the simulator is a test
    /// tool, and a run that trips every canary obscures whether the content
    /// signals work. The decoy test opts in explicitly.
    #[arg(long)]
    include_decoys: bool,
}

fn main() {
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ransomwatch: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command.unwrap_or(Cmd::Watch(WatchArgs {
        roots: Vec::new(),
        exclude: Vec::new(),
        no_baseline: false,
        no_decoys: false,
        response: None,
        duration: 0,
        json: false,
        fail_on_incident: false,
    })) {
        Cmd::Watch(a) => run_watch(cli.config.as_deref(), a),
        Cmd::Scan(a) => run_scan(cli.config.as_deref(), a),
        Cmd::Sim(a) => run_sim(a),
        Cmd::Resume { incident } => run_resume(&incident),
        Cmd::Config => {
            print!("{}", Config::defaults_toml());
            Ok(0)
        }
        Cmd::Decoys { replant } => run_decoys(cli.config.as_deref(), replant),
    }
}

// ---------------------------------------------------------------------------
// watch
// ---------------------------------------------------------------------------

fn run_watch(config_path: Option<&Path>, args: WatchArgs) -> Result<i32> {
    let mut cfg = Config::load(config_path)?;
    if !args.roots.is_empty() {
        cfg.watch.roots = args.roots.clone();
    }
    cfg.watch.roots = cfg
        .watch
        .roots
        .iter()
        .map(|p| util::expand_home(p))
        .collect();
    if !args.exclude.is_empty() {
        cfg.watch.exclude_paths.extend(args.exclude.clone());
    }
    if args.no_baseline {
        cfg.watch.scan_on_start = false;
    }
    if args.no_decoys {
        cfg.decoy.enabled = false;
    }
    if let Some(r) = &args.response {
        cfg.response.mode = match r.to_lowercase().as_str() {
            "alert" => ResponseMode::Alert,
            "suspend" => ResponseMode::Suspend,
            "none" => ResponseMode::None,
            other => anyhow::bail!("unknown --response {other:?} (alert|suspend|none)"),
        };
    }
    // Root existence is checked here rather than in Config::validate so that
    // `ransomwatch config` and `--help` work without any.
    let roots = cfg.existing_roots();
    if roots.is_empty() {
        anyhow::bail!(
            "none of the configured roots exist: {:?}",
            cfg.watch.roots
        );
    }

    let log = Logger::new(&cfg.output.level, cfg.output.color, args.json);
    log.info(&format!(
        "ransomwatch {} watching {} root(s)",
        env!("CARGO_PKG_VERSION"),
        roots.len()
    ));
    for r in &roots {
        log.info(&format!("  root: {}", r.display()));
    }

    // Baseline.
    let mut det = Detector::new(cfg.detect.clone(), cfg.entropy.clone());
    if cfg.watch.scan_on_start {
        let t0 = Instant::now();
        let n = detect::scan_baseline(&cfg, &roots, &mut det, |count, path| {
            log.debug(&format!("baselined {count} files ({})", path.display()));
        });
        log.info(&format!(
            "baseline: {} files ({} classes) in {:.2}s",
            n,
            det.known_exts().len(),
            t0.elapsed().as_secs_f64()
        ));
    }

    // Decoys.
    let mut decoys = if cfg.decoy.enabled {
        match DecoySet::setup(&cfg.decoy, &roots, &cfg.watch) {
            Ok(s) => {
                log.info(&format!("decoys: {} planted/verified", s.len()));
                for d in s.decoys() {
                    log.debug(&format!("  decoy: {}", d.path.display()));
                }
                Some(s)
            }
            Err(e) => {
                log.warn(&format!("decoy setup failed: {e}"));
                None
            }
        }
    } else {
        None
    };

    // Watcher.
    let (tx, rx) = mpsc::channel();
    let mut watcher: notify::RecommendedWatcher = notify::RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        notify::Config::default(),
    )
    .context("creating filesystem watcher")?;
    for r in &roots {
        watcher
            .watch(r, notify::RecursiveMode::Recursive)
            .with_context(|| format!("watching {}", r.display()))?;
    }

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc_or_default(move || stop.store(true, Ordering::SeqCst));
    }

    // Background fd sweep: FSEvents arrives after the write, so a fast
    // encryptor has usually closed its fd by the time an incident is raised.
    // The tracker keeps a few seconds of holder history so attribution still
    // finds the suspect.
    let tracker = Arc::new(ransomwatch::attr::HolderTracker::spawn(Duration::from_millis(
        cfg.decoy.holder_sweep_ms.clamp(50, 1000),
    )));
    let mut responder = Responder::new(cfg.clone()).with_tracker(tracker.clone());
    let start = Instant::now();
    let deadline = if args.duration > 0 {
        Some(start + Duration::from_secs(args.duration))
    } else {
        None
    };
    let decoy_poll = Duration::from_millis(cfg.decoy.poll_ms.max(50));
    let mut last_decoy_poll = Instant::now();
    let mut incidents = 0usize;
    let mut last_incident_at: Option<Instant> = None;

    log.info("watching; ctrl-c (or SIGTERM) to stop");

    while !stop.load(Ordering::SeqCst) {
        if let Some(d) = deadline {
            if Instant::now() >= d {
                break;
            }
        }
        let timeout = if decoys.is_some() {
            decoy_poll.min(Duration::from_millis(250))
        } else {
            Duration::from_millis(250)
        };
        match rx.recv_timeout(timeout) {
            Ok(Ok(ev)) => {
                for obs in events::normalise(&ev) {
                    handle_observation(
                        &obs,
                        &mut det,
                        &mut responder,
                        &roots,
                        decoys.as_mut(),
                        &log,
                        args.json,
                        &mut incidents,
                        &mut last_incident_at,
                        &cfg,
                    );
                }
            }
            Ok(Err(e)) => log.warn(&format!("watcher error: {e}")),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        // Decoy polling: fd scan for readers/writers, stat check for tampering.
        if let Some(ds) = decoys.as_mut() {
            if last_decoy_poll.elapsed() >= decoy_poll {
                last_decoy_poll = Instant::now();
                // Tamper check first: an encryptor that rewrote a decoy has
                // probably also closed it, so the stat evidence is what remains.
                let paths: Vec<PathBuf> = ds.decoys().map(|d| d.path.clone()).collect();
                for p in paths {
                    if let Some(alert) = ds.check(&p) {
                        emit_decoy_alert(
                            alert,
                            &mut responder,
                            &roots,
                            &log,
                            &mut incidents,
                            &mut last_incident_at,
                            &cfg,
                        );
                    }
                }
                let table = responder.table();
                let alerts = ds.poll_openers(|pid| {
                    let (trusted, reason) = {
                        let t = match table.lookup(pid) {
                            Some(p) => {
                                let t = table.classify(
                                    pid,
                                    &p.name,
                                    p.exe.as_deref(),
                                    p.signing.as_ref(),
                                    None,
                                );
                                (t != ransomwatch::procinfo::Trust::Untrusted, format!("{:?} ({})", t, p.short()))
                            }
                            None => (false, "unknown process".to_string()),
                        };
                        t
                    };
                    let _ = reason;
                    Some((trusted, String::new()))
                });
                for alert in alerts {
                    emit_decoy_alert(
                        alert,
                        &mut responder,
                        &roots,
                        &log,
                        &mut incidents,
                        &mut last_incident_at,
                        &cfg,
                    );
                }
            }
        }
    }

    log.info(&format!(
        "stopped after {:.1}s; {} incident(s)",
        start.elapsed().as_secs_f64(),
        incidents
    ));
    if args.fail_on_incident && incidents > 0 {
        return Ok(1);
    }
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
fn handle_observation(
    obs: &events::Observed,
    det: &mut Detector,
    responder: &mut Responder,
    roots: &[PathBuf],
    mut decoys: Option<&mut DecoySet>,
    log: &Logger,
    json: bool,
    incidents: &mut usize,
    last_incident_at: &mut Option<Instant>,
    cfg: &Config,
) {
    let path = &obs.path;
    let is_decoy = decoys.as_ref().map(|d| d.contains(path)).unwrap_or(false);
    if is_excluded_fast(path, cfg) && !is_decoy {
        return;
    }
    let now = Instant::now();

    if obs.hint == events::Hint::Renamed {
        if let Some(to) = &obs.rename_to {
            // A rename can *be* the tampering: an encryptor that renames the
            // decoy, or renames a document to a ransom extension. Check both
            // ends before touching the detector.
            if let Some(ds) = decoys.as_mut() {
                if ds.contains(path) {
                    if let Some(alert) = ds.check(path) {
                        emit_decoy_alert(alert, responder, roots, log, incidents, last_incident_at, cfg);
                        return;
                    }
                }
                let dest_was_decoy = ds.contains(to);
                if dest_was_decoy {
                    if let Some(alert) = ds.check(to) {
                        emit_decoy_alert(alert, responder, roots, log, incidents, last_incident_at, cfg);
                        return;
                    }
                }
            }
            // Observe the old path first so the engine records the vanished
            // inode, then the new path so the inode match can pair them. This
            // also handles backends that report the rename as a single event.
            det.observe(now, path);
            if let Some(inc) = det.observe(now, to) {
                raise(inc, to, responder, roots, log, json, incidents, last_incident_at, cfg);
            }
        }
        return;
    }

    // Decoy check happens on every hint that could mean tampering. A rename is
    // handled above; Remove and Changed land here.
    if let Some(ds) = decoys {
        if ds.contains(path) {
            if let Some(alert) = ds.check(path) {
                emit_decoy_alert(alert, responder, roots, log, incidents, last_incident_at, cfg);
                return;
            }
        }
    }

    if let Some(inc) = det.observe(now, path) {
        raise(inc, path, responder, roots, log, json, incidents, last_incident_at, cfg);
    }
    let _ = responder;
}

#[allow(clippy::too_many_arguments)]
fn emit_decoy_alert(
    alert: ransomwatch::decoy::DecoyAlert,
    responder: &mut Responder,
    roots: &[PathBuf],
    log: &Logger,
    incidents: &mut usize,
    last_incident_at: &mut Option<Instant>,
    cfg: &Config,
) {
    // Decoys bypass the cooldown on purpose: every touch is a separate fact.
    let _ = last_incident_at;
    log.critical(&format!(
        "DECOY TRIPPED: {} [{}] {}",
        alert.decoy.path.display(),
        alert.violation.as_str(),
        alert.detail
    ));
    match responder.handle_decoy(&alert, roots) {
        Ok(outcome) => {
            *incidents += 1;
            emit_outcome(&outcome, log, cfg);
        }
        Err(e) => log.error(&format!("could not record decoy incident: {e}")),
    }
}

#[allow(clippy::too_many_arguments)]
fn raise(
    draft: ransomwatch::detect::IncidentDraft,
    trigger_path: &Path,
    responder: &mut Responder,
    roots: &[PathBuf],
    log: &Logger,
    json: bool,
    incidents: &mut usize,
    last_incident_at: &mut Option<Instant>,
    cfg: &Config,
) {
    // Cooldown: one record per incident burst. The signals are consumed by the
    // detector, so post-cooldown evidence accumulates towards the next record.
    if let Some(last) = *last_incident_at {
        if last.elapsed() < Duration::from_secs(cfg.response.cooldown_secs) {
            log.debug(&format!(
                "incident suppressed by cooldown ({}s): {}",
                last.elapsed().as_secs(),
                draft.reason
            ));
            return;
        }
    }
    *last_incident_at = Some(Instant::now());
    log.warn(&format!(
        "INCIDENT {}: {} [{}]",
        draft.severity.as_str(),
        draft.reason,
        trigger_path.display()
    ));
    match responder.handle_scored(&draft, roots, &[]) {
        Ok(outcome) => {
            *incidents += 1;
            emit_outcome(&outcome, log, cfg);
            if json {
                if let Ok(line) = serde_json::to_string(&outcome.record) {
                    println!("{line}");
                }
            }
        }
        Err(e) => log.error(&format!("could not write incident record: {e}")),
    }
}

fn emit_outcome(outcome: &ransomwatch::respond::Outcome, log: &Logger, cfg: &Config) {
    for line in outcome.console.lines() {
        log.raw(line);
    }
    if !outcome.record.response.suspended_pids.is_empty() {
        log.critical(&format!(
            "SUSPENDED pid(s) {:?} — resume with: ransomwatch resume {}",
            outcome.record.response.suspended_pids,
            outcome.record_dir.join("incident.json").display()
        ));
    }
    if cfg.response.on_alert_command.is_some() {
        log.info(&format!("alert hook configured; exit={:?}", outcome.record.response.hook_exit));
    }
}

fn is_excluded_fast(path: &Path, cfg: &Config) -> bool {
    detect::is_excluded(path, cfg)
}

fn ctrlc_or_default<F: Fn() + Send + Sync + 'static>(f: F) {
    #[cfg(unix)]
    {
        use std::sync::OnceLock;
        static CB: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();
        let _ = CB.set(Box::new(f));
        extern "C" fn handler(_: libc::c_int) {
            let cb = CB.get_or_init(|| Box::new(|| {}));
            cb();
        }
        unsafe {
            libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = f;
    }
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

fn run_scan(config_path: Option<&Path>, args: ScanArgs) -> Result<i32> {
    let mut cfg = Config::load(config_path).unwrap_or_default();
    cfg.watch.roots = vec![args.path.clone()];
    let paths = detect::walk_files(&args.path, &cfg);
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut opaque = Vec::new();
    for p in &paths {
        let (s, _) = match entropy::inspect_file(p, &cfg.entropy) {
            Ok(v) => v,
            Err(_) => continue,
        };
        *counts.entry(s.class.label()).or_insert(0) += 1;
        if s.class.has_ciphertext() {
            opaque.push((p.clone(), s.h0));
        }
        if args.verbose {
            let ext = util::ext_lower(p).unwrap_or_default();
            let regions = if s.regions.is_empty() {
                String::new()
            } else {
                format!(" regions={:?}", s.regions.iter().map(|c| c.label()).collect::<Vec<_>>())
            };
            println!(
                "{:<22} H0={:.3} chi2z={:>9.1} p={:.2} {:>9} .{:<8} {}{}",
                s.class.label(),
                s.h0,
                s.chi2_z,
                s.printable,
                util::human_size(s.bytes as u64),
                ext,
                p.display(),
                regions
            );
        }
    }
    println!("files: {}", paths.len());
    for (k, v) in &counts {
        println!("  {:<24} {}", k, v);
    }
    if !opaque.is_empty() && !args.verbose {
        println!("opaque (ciphertext-like) files: {}", opaque.len());
        for (p, h) in opaque.iter().take(20) {
            println!("  H0={:.3} {}", h, p.display());
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// sim — the test encryptor
// ---------------------------------------------------------------------------

/// Guard: the simulator must never be pointed at real data.
fn sim_guard(dir: &Path) -> Result<()> {
    let s = dir.to_string_lossy();
    let tmp = std::env::temp_dir();
    let tmp_s = tmp.to_string_lossy();
    let home = std::env::var("HOME").unwrap_or_default();
    let looks_like_test = s.starts_with(&*tmp_s)
        || s.contains("/ccfb/")
        || s.contains("ransomwatch-test")
        || s.to_lowercase().contains("/tmp/")
        || s.starts_with("/private/var/folders/");
    if !looks_like_test {
        anyhow::bail!(
            "refusing to run the simulator outside a temporary/test directory: {}. \
             It is destructive by design; pass a directory under {} or containing 'ransomwatch-test'.",
            dir.display(),
            tmp.display()
        );
    }
    if !home.is_empty() && s == home {
        anyhow::bail!("refusing to run the simulator on $HOME");
    }
    Ok(())
}

fn run_sim(args: SimArgs) -> Result<i32> {
    sim_guard(&args.dir)?;
    std::fs::create_dir_all(&args.dir)
        .with_context(|| format!("creating {}", args.dir.display()))?;

    // Seed documents if the directory has none.
    let existing: Vec<PathBuf> = std::fs::read_dir(&args.dir)?
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.path())
        .filter(|p| {
            // Never treat a previous run's output as a victim: `--extension gz`
            // would otherwise re-encrypt every `.gz` file it just wrote.
            if !args.extension.is_empty()
                && util::ext_lower(p).as_deref() == Some(args.extension.as_str())
            {
                return false;
            }
            // Skip already-encrypted-looking outputs of earlier runs.
            let name = util::file_name(p);
            entropy::stacked_document_ext(&name).is_none()
        })
        .collect();
    // Decoy files are ordinary documents in the directory; exclude them unless
    // asked, so content-path tests are not drowned in decoy alerts.
    let mut victims: Vec<PathBuf> = if args.include_decoys {
        existing.clone()
    } else {
        existing.iter().filter(|p| !looks_like_decoy(p)).cloned().collect()
    };
    if victims.is_empty() && args.create > 0 {
        for i in 0..args.create {
            let ext = ["docx", "xlsx", "pdf", "txt", "csv"][i % 5];
            let p = args.dir.join(format!("document-{:03}.{}", i, ext));
            std::fs::write(&p, fake_document(i))?;
            victims.push(p);
        }
    }
    println!(
        "sim: {} victim file(s) in {} (ext=.{}, note={})",
        victims.len(),
        args.dir.display(),
        args.extension,
        args.note
    );
    if args.dry_run {
        for v in &victims {
            println!("  would encrypt {}", v.display());
        }
        return Ok(0);
    }

    // Deterministic keystream so repeated runs are reproducible for tests, but
    // the output is still statistically indistinguishable from ciphertext.
    let key = b"ransomwatch-simulated-key-0001";
    // A real encryptor walks the tree and writes in chunks, which means it holds
    // the directory open for far longer than any individual file. Reproduce that
    // shape so attribution has something to find.
    #[cfg(unix)]
    let _dir_fd = std::fs::File::open(&args.dir).ok();

    let mut done = 0usize;
    for (i, v) in victims.iter().enumerate() {
        let data = match std::fs::read(v) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let enc = keystream_xor(&data, key, i as u64);
        let target = if args.overwrite_only {
            v.clone()
        } else {
            let stem = v
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("file{i}"));
            v.with_file_name(format!("{}.{}", stem, args.extension))
        };
        // Write in chunks with a small pause: a real encryptor streams, and the
        // chunked write is what makes the write fd observable.
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&target)?;
            for chunk in enc.chunks(4096) {
                f.write_all(chunk)?;
                if args.delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(args.delay_ms.min(2)));
                }
            }
            f.sync_all().ok();
        }
        if target != *v && args.remove_original {
            std::fs::remove_file(v).ok();
        }
        done += 1;
        if args.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(args.delay_ms));
        }
    }
    if args.note {
        let note = args.dir.join("HOW_TO_RECOVER_FILES.txt");
        std::fs::write(
            &note,
            "All your files have been encrypted.\n\
             Your documents, photos and databases are no longer accessible.\n\
             To recover your files send 0.05 bitcoin to wallet bc1q-sim-example\n\
             and email the unique id below. Do not try to recover the files\n\
             yourself and do not contact law enforcement.\n\
             \n\
             unique id: SIM-0000-0000\n\
             visit the .onion address for the decryption tool\n",
        )?;
    }
    println!("sim: encrypted {} file(s)", done);
    Ok(0)
}

/// Decoys use a fixed vocabulary of business filenames. The simulator skips them
/// by default; this is a *test-tool* convenience, not a detector rule.
fn looks_like_decoy(p: &Path) -> bool {
    let n = util::file_name(p).to_lowercase();
    const MARKERS: &[&str] = &[
        "q3-budget",
        "payroll-",
        "董事会",
        "project-atlas",
        "supplier-list",
        "merger-due",
        "员工花名册",
        "客户合同",
    ];
    MARKERS.iter().any(|m| n.contains(m))
}

fn keystream_xor(data: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    // ChaCha-style quarter-round mixing over a 64-bit counter. Not a real cipher
    // and not intended to be: it produces uniform, headerless output, which is
    // all a simulator needs.
    let mut stream = Vec::with_capacity(data.len() + 64);
    let mut counter = 0u64;
    while stream.len() < data.len() {
        let mut st = [
            0x6170_7865u32,
            0x3320_646eu32,
            0x7461_2065u32,
            0x6b65_7920u32,
            key.len() as u32,
            nonce as u32,
            (nonce >> 32) as u32,
            counter as u32,
            (counter >> 32) as u32,
            0xdead_beef,
            0xfeed_face,
            0x0bad_c0de,
            0x1234_5678,
            0x9abc_def0,
            0x1111_2222,
            0x3333_4444,
        ];
        for _ in 0..8 {
            quarter(&mut st, 0, 4, 8, 12);
            quarter(&mut st, 1, 5, 9, 13);
            quarter(&mut st, 2, 6, 10, 14);
            quarter(&mut st, 3, 7, 11, 15);
            quarter(&mut st, 0, 5, 10, 15);
            quarter(&mut st, 1, 6, 11, 12);
            quarter(&mut st, 2, 7, 8, 13);
            quarter(&mut st, 3, 4, 9, 14);
        }
        for w in st.iter() {
            stream.extend_from_slice(&w.to_le_bytes());
        }
        counter += 1;
    }
    stream.truncate(data.len());
    data.iter().zip(stream).map(|(a, b)| a ^ b).collect()
}

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn fake_document(i: usize) -> Vec<u8> {
    let body = format!(
        "Quarterly report {i}\n\n\
         This document records the financial results for business unit {i}.\n\
         Revenue recognised during the period is reconciled against the general\n\
         ledger. Variances above the materiality threshold require approval from\n\
         the controller before the report is circulated.\n\n\
         Prepared by: finance operations\n\
         Classification: internal\n"
    );
    // Pad with realistic filler so files are large enough to sample.
    let mut v = body.into_bytes();
    for n in 0..60 {
        v.extend_from_slice(
            format!("note {n}: the appendix lists invoices {} through {}.\n", n * 10, n * 10 + 9)
                .as_bytes(),
        );
    }
    v
}

// ---------------------------------------------------------------------------
// resume / decoys
// ---------------------------------------------------------------------------

fn run_resume(incident: &Path) -> Result<i32> {
    // Accept any of: an incident directory, the incident.json inside it, or the
    // incidents root (~/.ransomwatch/incidents). An operator in a hurry types
    // the path they remember, and the tool should not punish that.
    let paths: Vec<PathBuf> = if incident.join("incident.json").is_file() {
        vec![incident.join("incident.json")]
    } else if incident.extension().map(|e| e == "json").unwrap_or(false) {
        vec![incident.to_path_buf()]
    } else if incident.is_dir() {
        // Treat as a root: resume the most recent incident inside it, since that
        // is the one an operator means when they say "resume".
        let mut found: Vec<PathBuf> = std::fs::read_dir(incident)
            .with_context(|| format!("listing {}", incident.display()))?
            .flatten()
            .map(|e| e.path().join("incident.json"))
            .filter(|p| p.is_file())
            .collect();
        found.sort();
        found.pop().into_iter().collect()
    } else {
        vec![incident.to_path_buf()]
    };
    if paths.is_empty() {
        anyhow::bail!("no incident records found under {}", incident.display());
    }
    let mut all = Vec::new();
    for p in &paths {
        let resumed = ransomwatch::respond::resume_incident(p)
            .with_context(|| format!("reading {}", p.display()))?;
        all.extend(resumed);
    }
    println!("resumed pid(s): {:?}", all);
    Ok(0)
}

fn run_decoys(config_path: Option<&Path>, replant: bool) -> Result<i32> {
    let cfg = Config::load(config_path)?;
    let roots = cfg.existing_roots();
    if roots.is_empty() {
        anyhow::bail!("no existing watch roots to plant decoys in");
    }
    if replant {
        // Remove the manifest so setup plants afresh, keeping intact files.
        let _ = std::fs::remove_file(cfg.decoy.manifest_dir.join("manifest.json"));
    }
    let set = DecoySet::setup(&cfg.decoy, &roots, &cfg.watch)?;
    for d in set.decoys() {
        println!("{}\tcanary={}\t{}", d.path.display(), d.canary, util::human_size(d.size));
    }
    println!("{} decoy(s)", set.len());
    Ok(0)
}

// ---------------------------------------------------------------------------
// logging
// ---------------------------------------------------------------------------

struct Logger {
    level: u8,
    color: bool,
    json: bool,
}

impl Logger {
    fn new(level: &str, color: bool, json: bool) -> Self {
        let lvl = match level.to_lowercase().as_str() {
            "error" => 0,
            "warn" => 1,
            "info" => 2,
            _ => 3,
        };
        let color = color && std::io::IsTerminal::is_terminal(&std::io::stdout());
        Self {
            level: lvl,
            color,
            json,
        }
    }

    fn stamp(&self) -> String {
        util::format_utc(util::now_unix())
    }

    fn emit(&self, lvl: u8, tag: &str, color: &str, msg: &str) {
        if lvl > self.level {
            return;
        }
        if self.json {
            let line = serde_json::json!({
                "ts": self.stamp(),
                "level": tag,
                "msg": msg,
            });
            println!("{line}");
            return;
        }
        if self.color {
            println!("\x1b[{}m{}\x1b[0m {} {}", color, self.stamp(), tag, msg);
        } else {
            println!("{} {} {}", self.stamp(), tag, msg);
        }
    }

    fn error(&self, msg: &str) {
        self.emit(0, "ERROR", "31", msg);
    }
    fn warn(&self, msg: &str) {
        self.emit(1, "WARN ", "33", msg);
    }
    fn info(&self, msg: &str) {
        self.emit(2, "INFO ", "36", msg);
    }
    fn debug(&self, msg: &str) {
        self.emit(3, "DEBUG", "90", msg);
    }
    fn critical(&self, msg: &str) {
        self.emit(0, "CRIT ", "1;31", msg);
    }
    fn raw(&self, msg: &str) {
        if self.json {
            return;
        }
        println!("{}", msg);
    }
}
