//! Filesystem watching on top of `notify` (FSEvents on macOS).
//!
//! Two responsibilities beyond raw events:
//! 1. Debounce per path — editors write a file in several rapid operations;
//!    we keep the last event and flush after a quiet period.
//! 2. Pair rename halves — FSEvents emits `from` and `to` as separate events
//!    without a stable id; consecutive FROM/TO events inside the debounce
//!    window are reconstructed into one `Renamed { from }`.

use crate::engine::{FsEvent, FsEventKind};
use notify::event::{Event, EventKind};
use notify::{RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

/// Per-path quiet period before an event is considered mature. Kept short so
/// burst attacks raise the window signal quickly; the engine's own windowing
/// absorbs any residual duplicate events.
const DEBOUNCE: Duration = Duration::from_millis(120);

#[derive(Clone)]
struct Pending {
    path: PathBuf,
    kind: FsEventKind,
    at: Instant,
}

pub struct FsWatcher {
    watcher: notify::RecommendedWatcher,
    rx: Receiver<notify::Result<Event>>,
    pending: HashMap<PathBuf, Pending>,
    rename_from: Option<(PathBuf, Instant)>,
}

impl FsWatcher {
    pub fn new() -> std::io::Result<Self> {
        let (tx, rx) = channel();
        let watcher = notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        })
        .map_err(io_err)?;
        Ok(Self {
            watcher,
            rx,
            pending: HashMap::new(),
            rename_from: None,
        })
    }

    pub fn watch(&mut self, dir: &std::path::Path) -> std::io::Result<()> {
        self.watcher
            .watch(dir, RecursiveMode::Recursive)
            .map_err(io_err)
    }

    /// Non-blocking: drain everything currently queued and return matured
    /// events (paths quiet for at least DEBOUNCE). Call in a loop with a
    /// short sleep.
    pub fn drain(&mut self, now: Instant) -> Vec<FsEvent> {
        while let Ok(res) = self.rx.try_recv() {
            match res {
                Ok(ev) => self.handle_raw(ev, now),
                Err(e) => eprintln!("watcher error: {e:?}"),
            }
        }
        self.flush(now)
    }

    fn handle_raw(&mut self, ev: Event, now: Instant) {
        let Some(path) = ev.paths.into_iter().next() else {
            return;
        };
        match ev.kind {
            EventKind::Create(_) => {
                self.pending.insert(
                    path.clone(),
                    Pending {
                        path: path.clone(),
                        kind: FsEventKind::Created,
                        at: now,
                    },
                );
            }
            EventKind::Modify(notify::event::ModifyKind::Name(mode)) => {
                use notify::event::RenameMode;
                match mode {
                    RenameMode::From => {
                        self.rename_from = Some((path, now));
                    }
                    RenameMode::To => {
                        if let Some((from, at)) = self.rename_from.take() {
                            self.pending.insert(
                                path.clone(),
                                Pending {
                                    path: path.clone(),
                                    kind: FsEventKind::Renamed { from },
                                    at: now.max(at),
                                },
                            );
                        } else {
                            // Orphaned TO half: treat as creation.
                            self.pending.insert(
                                path.clone(),
                                Pending {
                                    path: path.clone(),
                                    kind: FsEventKind::Created,
                                    at: now,
                                },
                            );
                        }
                    }
                    RenameMode::Both => {
                        // notify sometimes resolves the pair itself; the two
                        // paths are given in event order.
                        self.pending.insert(
                            path.clone(),
                            Pending {
                                path: path.clone(),
                                kind: FsEventKind::Created,
                                at: now,
                            },
                        );
                    }
                    _ => {}
                }
            }
            EventKind::Modify(_) => {
                self.pending.insert(
                    path.clone(),
                    Pending {
                        path: path.clone(),
                        kind: FsEventKind::Modified,
                        at: now,
                    },
                );
            }
            EventKind::Remove(_) => {
                self.pending.remove(&path);
                self.pending.insert(
                    path.clone(),
                    Pending {
                        path: path.clone(),
                        kind: FsEventKind::Deleted,
                        at: now,
                    },
                );
            }
            EventKind::Any | EventKind::Access(_) | EventKind::Other => {}
        }
    }

    fn flush(&mut self, now: Instant) -> Vec<FsEvent> {
        let mut matured = Vec::new();
        let mut mature_paths = Vec::new();
        for (p, pending) in &self.pending {
            if now.duration_since(pending.at) >= DEBOUNCE {
                mature_paths.push(p.clone());
            }
        }
        for p in mature_paths {
            if let Some(pending) = self.pending.remove(&p) {
                matured.push(FsEvent {
                    path: pending.path,
                    kind: pending.kind,
                    ts: chrono::Local::now().timestamp(),
                });
            }
        }
        matured
    }
}

fn io_err(e: notify::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Recursively snapshot existing files for baseline entropy.
pub fn baseline_scan(
    roots: &[PathBuf],
    min_size: u64,
) -> HashMap<PathBuf, crate::engine::FileBaseline> {
    let mut map = HashMap::new();
    for root in roots {
        for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.len() < min_size {
                continue;
            }
            let p = entry
                .path()
                .canonicalize()
                .unwrap_or_else(|_| entry.path().to_path_buf());
            let entropy = crate::entropy::file_entropy(&p);
            map.insert(
                p,
                crate::engine::FileBaseline {
                    size: meta.len(),
                    entropy,
                },
            );
        }
    }
    map
}
