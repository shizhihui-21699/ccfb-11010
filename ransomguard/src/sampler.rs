//! Background open-handle sampler.
//!
//! Inline `lsof` on an alert is a race: the writer may be between handles,
//! and sleeping inside the event loop blocks event consumption. This thread
//! polls `lsof +D` over the watched roots on a fixed cadence and keeps the
//! most recent non-empty snapshot, so the response path always has fresh
//! attribution data without blocking.

use crate::process::{lsof_under_roots, OpenFile};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// How often the sampler runs. Tight enough that a 200ms+ held handle is
/// virtually guaranteed to be observed.
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Snapshots older than this are discarded as stale.
const MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct AttributionSampler {
    inner: Arc<Mutex<Option<Sample>>>,
    stop: Arc<AtomicBool>,
}

struct Sample {
    rows: Vec<OpenFile>,
    at: std::time::Instant,
}

impl AttributionSampler {
    pub fn start(
        roots: Vec<PathBuf>,
        evidence_owner: Arc<Mutex<Vec<PathBuf>>>,
    ) -> (Self, JoinHandle<()>) {
        let inner = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_inner = inner.clone();
        let worker_stop = stop.clone();
        let handle = thread::Builder::new()
            .name("lsof-sampler".into())
            .spawn(move || {
                while !worker_stop.load(Ordering::SeqCst) {
                    let canon_roots: Vec<PathBuf> =
                        roots.iter().filter_map(|r| r.canonicalize().ok()).collect();
                    let evidence = evidence_owner.lock().unwrap().clone();
                    if !canon_roots.is_empty() {
                        let rows = lsof_under_roots(&canon_roots, &evidence);
                        let now = std::time::Instant::now();
                        let mut guard = worker_inner.lock().unwrap();
                        if !rows.is_empty() {
                            *guard = Some(Sample { rows, at: now });
                        } else if let Some(s) = guard.as_ref() {
                            if now.duration_since(s.at) > MAX_AGE {
                                *guard = None;
                            }
                        }
                    }
                    // Sleep in small slices so shutdown stays responsive.
                    let waited = std::time::Instant::now();
                    while waited.elapsed() < POLL_INTERVAL && !worker_stop.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            })
            .expect("spawn lsof sampler thread");
        (Self { inner, stop }, handle)
    }

    /// Most recent open-handle rows under the watched roots, if fresh.
    pub fn snapshot(&self) -> Vec<OpenFile> {
        let guard = self.inner.lock().unwrap();
        match guard.as_ref() {
            Some(s) if s.at.elapsed() <= MAX_AGE => s.rows.clone(),
            _ => Vec::new(),
        }
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}
