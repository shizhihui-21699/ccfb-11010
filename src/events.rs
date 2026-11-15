//! Normalisation of raw `notify` events into the small vocabulary the detector
//! reasons about.
//!
//! FSEvents on macOS is noisy: one `write()` can produce `Create(File)`,
//! `Modify(Data)`, and `Modify(Metadata)` for the same path, and a rename
//! produces separate events for the old and the new name. Rather than trying to
//! interpret each event, the detector treats events as *hints* and re-derives the
//! file's state from `stat` + a content sample. This module is the thin layer
//! that turns `notify::Event` into one of the four hints.

use notify::event::{CreateKind, EventKind, ModifyKind, RemoveKind, RenameMode};
use notify::Event;
use std::path::PathBuf;

/// What a raw event suggests happened to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint {
    /// The path may have appeared.
    Appeared,
    /// The path's data or metadata may have changed.
    Changed,
    /// The path may have been removed.
    Removed,
    /// An explicit rename pair was reported.
    Renamed,
}

/// One normalised observation. `from`/`to` are both set only for an explicit
/// rename pair; otherwise `path` carries the single affected path.
#[derive(Debug, Clone)]
pub struct Observed {
    pub hint: Hint,
    pub path: PathBuf,
    pub rename_to: Option<PathBuf>,
}

/// Convert a raw event into zero or more observations.
///
/// Access-only events (opens, closes, reads) are dropped: FSEvents does not
/// report them for regular files anyway, and decoy read detection is done by the
/// fd poller instead.
pub fn normalise(ev: &Event) -> Vec<Observed> {
    let mut out = Vec::new();
    match ev.kind {
        EventKind::Access(_) => {}
        EventKind::Create(CreateKind::Folder) | EventKind::Remove(RemoveKind::Folder) => {
            // Directory churn itself is not a signal; contents produce their own
            // events. An attacker creating a staging directory is not, by itself,
            // evidence of encryption.
        }
        EventKind::Create(_) => {
            for p in &ev.paths {
                out.push(Observed { hint: Hint::Appeared, path: p.clone(), rename_to: None });
            }
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) if ev.paths.len() >= 2 => {
            out.push(Observed {
                hint: Hint::Renamed,
                path: ev.paths[0].clone(),
                rename_to: Some(ev.paths[1].clone()),
            });
        }
        EventKind::Modify(ModifyKind::Name(_)) => {
            // macOS often reports the old and new name as separate events.
            for p in &ev.paths {
                out.push(Observed { hint: Hint::Changed, path: p.clone(), rename_to: None });
            }
        }
        EventKind::Modify(ModifyKind::Data(_)) | EventKind::Modify(ModifyKind::Any) => {
            for p in &ev.paths {
                out.push(Observed { hint: Hint::Changed, path: p.clone(), rename_to: None });
            }
        }
        EventKind::Modify(ModifyKind::Metadata(_)) => {
            // Permission/atime changes are not content changes, but a
            // truncate-to-zero shows up here too on some backends, so pass it on
            // and let the stat comparison decide whether anything changed.
            for p in &ev.paths {
                out.push(Observed { hint: Hint::Changed, path: p.clone(), rename_to: None });
            }
        }
        EventKind::Remove(_) => {
            for p in &ev.paths {
                out.push(Observed { hint: Hint::Removed, path: p.clone(), rename_to: None });
            }
        }
        EventKind::Any | EventKind::Other | EventKind::Modify(ModifyKind::Other) => {
            for p in &ev.paths {
                out.push(Observed { hint: Hint::Changed, path: p.clone(), rename_to: None });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{AccessKind, AccessMode, DataChange, MetadataKind};
    use std::path::PathBuf;

    fn ev(kind: EventKind, paths: &[&str]) -> Event {
        Event {
            kind,
            paths: paths.iter().map(PathBuf::from).collect(),
            attrs: Default::default(),
        }
    }

    #[test]
    fn drops_access_events() {
        let e = ev(EventKind::Access(AccessKind::Open(AccessMode::Read)), &["/a"]);
        assert!(normalise(&e).is_empty());
    }

    #[test]
    fn content_modify_is_a_change() {
        let e = ev(
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            &["/a"],
        );
        let o = normalise(&e);
        assert_eq!(o.len(), 1);
        assert_eq!(o[0].hint, Hint::Changed);
    }

    #[test]
    fn rename_both_carries_both_paths() {
        let e = ev(EventKind::Modify(ModifyKind::Name(RenameMode::Both)), &["/a", "/b"]);
        let o = normalise(&e);
        assert_eq!(o.len(), 1);
        assert_eq!(o[0].hint, Hint::Renamed);
        assert_eq!(o[0].rename_to.as_deref(), Some(std::path::Path::new("/b")));
    }

    #[test]
    fn metadata_change_still_inspected() {
        let e = ev(
            EventKind::Modify(ModifyKind::Metadata(MetadataKind::WriteTime)),
            &["/a"],
        );
        assert_eq!(normalise(&e).len(), 1);
    }

    #[test]
    fn folder_events_ignored() {
        let e = ev(EventKind::Create(CreateKind::Folder), &["/dir"]);
        assert!(normalise(&e).is_empty());
    }
}
