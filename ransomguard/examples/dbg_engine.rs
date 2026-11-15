use ransomguard::config::{Config, Thresholds};
use ransomguard::engine::{AlertLevel, CanarySet, Engine};
use ransomguard::watcher::FsWatcher;
use std::time::{Duration, Instant};

fn main() {
    let dir = std::env::args().nth(1).unwrap();
    let cfg = Config::merged_defaults();
    let mut w = FsWatcher::new().unwrap();
    w.watch(std::path::Path::new(&dir)).unwrap();
    let baselines = ransomguard::watcher::baseline_scan(&[std::path::PathBuf::from(&dir)], 64);
    let t = Thresholds::default();
    println!(
        "thresholds: entropy_count={} window={}s crit={}",
        t.entropy_event_count, t.window_secs, t.score_critical
    );
    let mut engine = Engine::new(
        baselines,
        CanarySet::default(),
        t,
        cfg.note_name_hints,
        cfg.note_content_markers,
    );
    std::thread::sleep(Duration::from_millis(600));
    let start = Instant::now();
    let mut count = 0;
    while start.elapsed().as_secs() < 25 {
        for ev in w.drain(Instant::now()) {
            count += 1;
            if let Some(a) = engine.ingest(&ev) {
                let lvl = if a.level == AlertLevel::Critical {
                    "CRITICAL"
                } else {
                    "warning"
                };
                println!(
                    "[{:6.2}s] ALERT {} {} {} after {} events",
                    start.elapsed().as_secs_f64(),
                    a.signal,
                    a.score,
                    lvl,
                    count
                );
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    println!("total events: {}, alerts: {}", count, engine.alerts.len());
}
