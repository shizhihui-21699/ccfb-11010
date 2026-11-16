//! Event source: a thin wrapper over `notify` that reduces every backend
//! event to "this path was touched at this time".
//!
//! We deliberately do *not* try to interpret backend event kinds.  FSEvents
//! reports renames as two unrelated paths, editors save through
//! temp-file-then-rename, and different backends disagree about what a "create"
//! is.  Instead, every notification marks the path dirty and a reconciler
//! re-stats it and diffs against what it knew before.  That makes the same
//! logic work across macOS FSEvents, Linux inotify and the polling fallback.

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct Touch {
    pub path: PathBuf,
    pub at: Instant,
    /// Backend hinted that a rescan may be needed (events were dropped).
    pub rescan: bool,
}

pub struct WatchHandle {
    // Dropping the watcher stops the stream.
    _watcher: Box<dyn Watcher + Send>,
}

/// Start watching `roots` recursively.  Notifications arrive on `rx`.
///
/// The returned handle must be kept alive for the lifetime of the watch;
/// dropping it stops event delivery.
pub fn start(roots: &[PathBuf]) -> anyhow::Result<(WatchHandle, Receiver<Touch>)> {
    let (tx, rx): (Sender<Touch>, Receiver<Touch>) = channel();

    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(ev) => {
                let rescan = ev.need_rescan();
                let empty = ev.paths.is_empty();
                for path in ev.paths {
                    let _ = tx.send(Touch {
                        path,
                        at: Instant::now(),
                        rescan,
                    });
                }
                if empty && rescan {
                    // A pure rescan notification has no paths; surface it with
                    // an empty root so the reconciler can ask for a full walk.
                    let _ = tx.send(Touch {
                        path: PathBuf::new(),
                        at: Instant::now(),
                        rescan: true,
                    });
                }
            }
            Err(err) => {
                // Watch errors are usually "path disappeared"; the reconciler
                // will notice on its own.  Nothing actionable here.
                let _ = err;
            }
        })?;

    for root in roots {
        if !root.exists() {
            anyhow::bail!("watch path does not exist: {}", root.display());
        }
        watcher
            .watch(Path::new(root), RecursiveMode::Recursive)
            .map_err(|e| anyhow::anyhow!("cannot watch {}: {e}", root.display()))?;
    }

    Ok((
        WatchHandle {
            _watcher: Box::new(watcher),
        },
        rx,
    ))
}
