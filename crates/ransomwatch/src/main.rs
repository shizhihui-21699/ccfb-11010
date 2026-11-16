use clap::{Parser, Subcommand};
use ransomwatch::config::Config;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "ransomwatch",
    version,
    about = "Terminal-side early detection for ransomware-like file activity",
    long_about = "Monitors directories for the file-activity patterns of ransomware: plaintext \
                  being rewritten into high-entropy data, bulk extension changes, ransom-note \
                  files, and reads or writes of planted decoy files.  On detection it suspends \
                  the responsible process tree and captures a forensic bundle.\n\n\
                  It is designed not to fire on backup jobs, repository checkouts, or \
                  compression/archiving: compressed containers are recognised by header and \
                  excluded from entropy scoring, and bulk *creation* is distinguished from bulk \
                  *rewriting*."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Directory to watch (repeatable).  Overrides a config file's [watch]
    /// paths when given.
    #[arg(short, long = "path", global = true)]
    paths: Vec<PathBuf>,

    /// TOML configuration file.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Detect, log and attribute, but never suspend processes or write
    /// evidence.
    #[arg(long, global = true)]
    dry_run: bool,

    /// Log every observed change, not only signals.
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Append events to this file (in addition to stderr).
    #[arg(long, global = true)]
    log: Option<PathBuf>,

    /// Write evidence bundles here instead of ./ransomwatch-evidence.
    #[arg(long, global = true)]
    evidence_dir: Option<PathBuf>,

    /// Disable decoy files.
    #[arg(long, global = true)]
    no_decoys: bool,

    /// Override the high-entropy threshold (bits/byte; default 7.2).
    #[arg(long, global = true)]
    high_entropy: Option<f64>,

    /// Exit shortly after the first incident (useful for scripted tests).
    #[arg(long, global = true)]
    exit_after_incident: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Run the monitor (the default when no subcommand is given).
    Run,
    /// Place decoy files under the configured roots and exit.
    Decoys,
    /// Print the effective configuration as TOML.
    PrintConfig,
    /// Validate the configuration and show what the detector will do.
    Check,
}

fn main() {
    let cli = Cli::parse();
    let mut cfg = match &cli.config {
        Some(p) => match Config::from_file(p) {
            Ok(c) => c,
            Err(e) => die(&e.to_string()),
        },
        None => Config::default(),
    };
    if !cli.paths.is_empty() {
        cfg.watch.paths = cli.paths.clone();
    }
    if cfg.watch.paths.is_empty() {
        die("no watch paths: pass --path <DIR> or set [watch] paths in a config file");
    }
    if cli.verbose {
        cfg.log.verbose = true;
    }
    if let Some(file) = &cli.log {
        cfg.log.path = Some(file.clone());
    }
    if let Some(dir) = &cli.evidence_dir {
        cfg.response.evidence_dir = Some(dir.clone());
    }
    if cli.no_decoys {
        cfg.decoy.enabled = false;
    }
    if let Some(h) = cli.high_entropy {
        cfg.detection.high_entropy = h;
    }
    if cli.dry_run {
        cfg.response.dry_run = true;
    }

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => run(cfg, cli.exit_after_incident),
        Command::Decoys => decoys(cfg),
        Command::PrintConfig => print!("{}", cfg.to_toml()),
        Command::Check => check(cfg),
    }
}

fn die(msg: &str) -> ! {
    eprintln!("ransomwatch: {msg}");
    std::process::exit(2)
}

fn run(cfg: Config, exit_after_incident: bool) {
    let mut engine = match ransomwatch::Engine::new(cfg) {
        Ok(e) => e,
        Err(e) => die(&e.to_string()),
    };
    let stop = engine.stop_flag();
    install_signal_handlers(stop.clone());
    if exit_after_incident {
        engine.set_exit_after_incident(true);
    }
    if let Err(e) = engine.run() {
        die(&e.to_string());
    }
}

/// SIGINT/SIGTERM set the engine's stop flag.  The handler only touches an
/// atomic, which is async-signal-safe.
fn install_signal_handlers(stop: Arc<AtomicBool>) {
    static FLAG: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();
    let _ = FLAG.set(stop);
    extern "C" fn handler(_: libc::c_int) {
        if let Some(f) = FLAG.get() {
            f.store(true, Ordering::SeqCst);
        }
    }
    unsafe {
        libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
    }
}

fn decoys(cfg: Config) {
    let placement = ransomwatch::decoy::PlacementConfig {
        roots: &cfg.watch.paths,
        count_per_root: cfg.decoy.count_per_root,
        names: &cfg.decoy.names,
        file_bytes: cfg.decoy.file_bytes,
        subdir: &cfg.decoy.subdir,
        adopt_existing: true,
    };
    match ransomwatch::decoy::place(&placement) {
        Ok(set) => {
            for f in &set.files {
                println!("{}", f.path.display());
            }
            eprintln!("placed {} decoy file(s)", set.files.len());
        }
        Err(e) => die(&e.to_string()),
    }
}

fn check(cfg: Config) {
    println!("watch paths:");
    let mut missing = 0;
    for p in &cfg.watch.paths {
        let ok = p.is_dir();
        if !ok {
            missing += 1;
        }
        println!("  {} [{}]", p.display(), if ok { "ok" } else { "MISSING" });
    }
    let d = &cfg.detection;
    println!("\nDetection");
    println!(
        "  high-entropy cut-off        {:.2} bits/byte (plaintext assumed below {:.2})",
        d.high_entropy, d.plain_entropy
    );
    println!("  sliding window              {}", d.window);
    println!("  entropy burst               {} files", d.entropy_burst_files);
    println!("  rewrite burst               {} files", d.rewrite_burst_files);
    println!("  rename burst                {} files (one extension must reach {:.0}%)", d.rename_burst_files, d.extension_dominance * 100.0);
    println!("  ransomware-extension burst  {} files", d.ransom_ext_files);
    println!("  delete burst                {} files", d.delete_burst_files);
    println!("  mass-modification           {} paths", d.mass_touch_files);
    println!("  incident score              {}", d.incident_score);
    println!("\nDecoys");
    println!(
        "  {} per root under ./{}/ ({})",
        cfg.decoy.count_per_root,
        cfg.decoy.subdir,
        if cfg.decoy.enabled { "enabled" } else { "disabled" }
    );
    println!(
        "  trip on read={} write={} rename={} delete={}",
        cfg.decoy.trip_on_read,
        cfg.decoy.trip_on_write,
        cfg.decoy.trip_on_rename,
        cfg.decoy.trip_on_delete
    );
    println!("\nResponse");
    println!(
        "  suspend={} dry_run={}",
        cfg.response.suspend, cfg.response.dry_run
    );
    println!(
        "  evidence dir: {}",
        cfg.response
            .evidence_dir
            .as_ref()
            .map(|d| d.display().to_string())
            .unwrap_or_else(|| "./ransomwatch-evidence (default)".into())
    );
    println!(
        "\nplatform: process control {}\nuid {} (root: {})",
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            "available"
        } else {
            "UNAVAILABLE"
        },
        ransomwatch::sys::current_uid(),
        ransomwatch::sys::is_root()
    );
    println!(
        "\nallowed process-name substrings: {} (see `print-config` for the list)",
        cfg.allow_processes.len()
    );
    println!("ignored directory names: {}", cfg.ignore_dirs.len());
    println!("ignored suffixes: {}", cfg.ignore_suffixes.len());
    if missing > 0 {
        eprintln!("\n{missing} configured watch path(s) do not exist");
        std::process::exit(1);
    }
}
