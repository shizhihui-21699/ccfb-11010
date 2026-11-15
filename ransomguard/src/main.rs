use clap::Parser;
use ransomguard::canary;
use ransomguard::config::Config;
use ransomguard::engine::{AlertLevel, Engine, FsEvent};
use ransomguard::process::{capture_forensics, is_trusted, suspend_safely, OpenFile};
use ransomguard::report::Reporter;
use ransomguard::sampler::AttributionSampler;
use ransomguard::watcher::{baseline_scan, FsWatcher};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Minimum spacing between full response actions (suspend + forensic dump);
/// one encryptor trips many canaries/window alerts in quick succession.
const RESPONSE_COOLDOWN: Duration = Duration::from_secs(10);

#[derive(Parser, Debug)]
#[command(
    name = "ransomguard",
    version,
    about = "Terminal-side early ransomware detection (entropy / extensions / notes / canaries)"
)]
struct Args {
    /// Directories to monitor (repeatable). Merged with the config file list.
    #[arg(long, short = 'w', value_name = "DIR")]
    watch: Vec<PathBuf>,

    /// TOML config file (optional; CLI flags take precedence where overlapping).
    #[arg(long, short = 'c', value_name = "FILE")]
    config: Option<PathBuf>,

    /// State directory for canary manifests, event log and forensic dumps.
    #[arg(long, value_name = "DIR")]
    state_dir: Option<PathBuf>,

    /// Deploy canaries but do not start monitoring.
    #[arg(long)]
    deploy_canaries_only: bool,

    /// Write an example config file to --config and exit.
    #[arg(long)]
    print_default_config: bool,

    /// Do not suspend suspicious processes (forensics only).
    #[arg(long)]
    no_suspend: bool,

    /// Do not deploy canary files.
    #[arg(long)]
    no_canaries: bool,
}

fn default_state_dir() -> PathBuf {
    std::env::var("RANSOMGUARD_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs_lite_home().join(".ransomguard"))
}

fn dirs_lite_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn main() {
    let args = Args::parse();

    if args.print_default_config {
        let cfg = Config::merged_defaults();
        print!(
            "{}",
            toml::to_string_pretty(&cfg).expect("serialize config")
        );
        return;
    }

    let mut cfg = match &args.config {
        Some(p) => Config::load(p).unwrap_or_else(|e| {
            eprintln!("failed to load config {}: {e}", p.display());
            std::process::exit(2);
        }),
        None => Config::merged_defaults(),
    };
    for w in &args.watch {
        if !cfg.watch_dirs.contains(w) {
            cfg.watch_dirs.push(w.clone());
        }
    }
    if cfg.watch_dirs.is_empty() {
        eprintln!("nothing to watch: pass --watch <dir> (repeatable) or set watch_dirs in config");
        std::process::exit(2);
    }
    for d in &cfg.watch_dirs {
        if !d.is_dir() {
            eprintln!("watch directory does not exist: {}", d.display());
            std::process::exit(2);
        }
    }
    let state_dir = args
        .state_dir
        .or(cfg.state_dir.take())
        .unwrap_or_else(default_state_dir);
    std::fs::create_dir_all(&state_dir).expect("create state dir");

    // --- Canary deployment ------------------------------------------------
    let canaries = if args.no_canaries {
        canary::load(&state_dir).unwrap_or_default()
    } else {
        canary::deploy(
            &cfg.watch_dirs,
            &cfg.canary_names,
            &cfg.extra_canaries,
            &state_dir,
        )
        .expect("deploy canaries")
    };
    println!(
        "canaries: {} files in {} directories",
        canaries.files.len(),
        canaries.dirs.len()
    );
    if args.deploy_canaries_only {
        println!("--deploy-canaries-only: exiting");
        return;
    }

    // --- Baseline ----------------------------------------------------------
    println!("building baseline entropy snapshot ...");
    let baselines = baseline_scan(&cfg.watch_dirs, cfg.thresholds.min_file_size);
    println!("baseline: {} files", baselines.len());

    // --- Watcher + engine --------------------------------------------------
    let mut watcher = FsWatcher::new().expect("create watcher");
    for d in &cfg.watch_dirs {
        watcher.watch(d).unwrap_or_else(|e| {
            eprintln!("failed to watch {}: {e}", d.display());
            std::process::exit(2);
        });
        println!("watching {}", d.display());
    }
    // FSEvents delivers the canary-deployment and baseline writes only after
    // the watch is installed. Discard everything that lands during this
    // startup grace period so the detector never alerts on itself.
    let ready_at = Instant::now() + Duration::from_millis(1500);
    let thresholds = cfg.thresholds.clone();
    let mut engine = Engine::new(
        baselines,
        canaries,
        thresholds,
        cfg.note_name_hints.clone(),
        cfg.note_content_markers.clone(),
    );
    let reporter = Reporter::new(&state_dir).expect("create reporter");
    let trusted = cfg.trusted_processes.clone();

    // Background lsof sampler: continuously records open handles under the
    // watched roots so attribution never blocks the event loop.
    let evidence_slot: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
    let (sampler, sampler_handle) =
        AttributionSampler::start(cfg.watch_dirs.clone(), evidence_slot.clone());

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc_handler(move || stop.store(true, Ordering::SeqCst));
    }

    println!("RansomGuard active. Ctrl-C to stop.\n");
    let mut recent_rows: Vec<OpenFile> = Vec::new();
    // One response (suspend + forensics) per attack episode; canary storms
    // from a single encryptor must not produce dozens of incident folders.
    let mut last_response = Instant::now() - Duration::from_secs(3600);

    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        let events = watcher.drain(now);
        if now < ready_at {
            // Still inside the startup grace period: drain and discard.
            continue;
        }
        for ev in events {
            handle_event(
                &mut engine,
                &reporter,
                &trusted,
                &state_dir,
                args.no_suspend,
                &sampler,
                &evidence_slot,
                &mut recent_rows,
                &mut last_response,
                ev,
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    sampler.shutdown();
    let _ = sampler_handle.join();
    println!(
        "\nRansomGuard stopped. Event log: {}",
        state_dir.join("ransomguard-events.jsonl").display()
    );
}

#[allow(clippy::too_many_arguments)]
fn handle_event(
    engine: &mut Engine,
    reporter: &Reporter,
    trusted: &[String],
    state_dir: &Path,
    no_suspend: bool,
    sampler: &AttributionSampler,
    evidence_slot: &Arc<Mutex<Vec<PathBuf>>>,
    recent_rows: &mut Vec<OpenFile>,
    last_response: &mut Instant,
    ev: FsEvent,
) {
    let Some(alert) = engine.ingest(&ev) else {
        return;
    };

    // Warning-level signals are logged only.
    if alert.level != AlertLevel::Critical {
        reporter.report(&alert, &[]);
        return;
    }

    // Response cooldown: a single encryptor trips many canaries/window
    // alerts in quick succession; the first one drives the response.
    let within_cooldown = last_response.elapsed() < RESPONSE_COOLDOWN;

    // Hand the latest evidence to the sampler (its exact-path queries then
    // cover files even when the +D root scan momentarily comes up empty).
    let evidence_paths: Vec<PathBuf> = alert.evidence.iter().map(PathBuf::from).collect();
    if let Ok(mut slot) = evidence_slot.lock() {
        *slot = evidence_paths.clone();
    }

    // Attribution comes from the continuously-refreshed background snapshot,
    // so the event loop never blocks on lsof.
    recent_rows.clear();
    recent_rows.extend(sampler.snapshot());

    let mut actions = Vec::new();
    let mut suspended: Vec<(u32, String)> = Vec::new();

    let mut pids: HashSet<(u32, String)> = recent_rows
        .iter()
        .map(|r| (r.pid, r.command.clone()))
        .collect();

    let trusted_hits: Vec<String> = pids
        .iter()
        .filter(|(_, cmd)| is_trusted(cmd, trusted))
        .map(|(pid, cmd)| format!("{cmd}(pid {pid})"))
        .collect();
    if !trusted_hits.is_empty() {
        actions.push(format!(
            "归因命中可信备份/压缩进程 [{}], 不执行挂起",
            trusted_hits.join(", ")
        ));
        pids.retain(|(_, cmd)| !is_trusted(cmd, trusted));
    }

    if within_cooldown {
        actions.push("响应冷却期内的后续告警, 仅记录不重复挂起/取证".into());
        reporter.report(&alert, &actions);
        return;
    }

    if !no_suspend {
        for (pid, cmd) in &pids {
            if is_trusted(cmd, trusted) {
                continue;
            }
            actions.push(suspend_safely(*pid, cmd));
            suspended.push((*pid, cmd.clone()));
        }
    } else {
        actions.push("--no-suspend 已启用, 仅记录现场".into());
    }
    if pids.is_empty() {
        actions
            .push("未能通过 lsof 归因到具体进程 (句柄采样窗口内无打开文件, 或需要更高权限)".into());
    }

    let incident_dir = state_dir.join("incidents").join(timestamp_dir());
    let scene = serde_json::json!({
        "alert": alert,
        "attribution": recent_rows.iter().map(|r| serde_json::json!({
            "pid": r.pid, "command": r.command, "path": r.path,
        })).collect::<Vec<_>>(),
        "suspended": suspended,
    });
    if let Err(e) = capture_forensics(&incident_dir, &suspended, recent_rows, &scene) {
        actions.push(format!("取证写入失败: {e}"));
    } else {
        actions.push(format!("现场已固化: {}", incident_dir.display()));
    }
    *last_response = Instant::now();
    reporter.report(&alert, &actions);
}

fn timestamp_dir() -> String {
    chrono::Local::now()
        .format("incident-%Y%m%d-%H%M%S%.3f")
        .to_string()
}

fn ctrlc_handler<F: Fn() + Send + 'static>(f: F) {
    // Minimal self-contained SIGINT setup via libc on Unix.
    extern "C" fn trampoline(_sig: libc::c_int) {
        // The flag is set through the global below.
        if let Some(h) = take_handler() {
            h();
        }
    }
    set_handler(Box::new(f));
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        let handler: extern "C" fn(libc::c_int) = trampoline;
        sa.sa_sigaction = handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

use std::sync::OnceLock;

type SignalHandler = Box<dyn Fn() + Send>;
type HandlerCell = std::sync::Mutex<Option<SignalHandler>>;

static HANDLER: OnceLock<HandlerCell> = OnceLock::new();
fn handler_slot() -> &'static HandlerCell {
    HANDLER.get_or_init(|| std::sync::Mutex::new(None))
}
fn set_handler(b: SignalHandler) {
    *handler_slot().lock().unwrap() = Some(b);
}
fn take_handler() -> Option<Box<dyn Fn() + Send>> {
    handler_slot().lock().unwrap().take()
}
