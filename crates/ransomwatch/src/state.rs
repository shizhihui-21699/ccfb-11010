//! File knowledge base: what we knew about each path before it changed.
//!
//! The detection logic is diff-based.  For every path that FSEvents tells us
//! about, we compare the current `(inode, size, mtime)` against what we last
//! recorded.  That lets us distinguish:
//!
//! * create        — no prior record, no matching inode anywhere
//! * content write — same inode, size/mtime changed
//! * rename        — inode matches a path that just disappeared
//! * removal       — path gone and no inode reappeared (yet)
//!
//! and, crucially, it gives us the *prior* entropy of the file so that
//! "plaintext became ciphertext" is measurable rather than guessed.

use crate::format::KnownFormat;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileKey {
    pub dev: u64,
    pub ino: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMeta {
    pub key: FileKey,
    pub size: u64,
    /// Modification time in nanoseconds since the epoch.
    pub mtime_ns: i128,
    /// Change time in nanoseconds since the epoch (catches rename-perm-change).
    pub ctime_ns: i128,
}

impl FileMeta {
    pub fn from_metadata(m: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            key: FileKey {
                dev: m.dev(),
                ino: m.ino(),
            },
            size: m.size(),
            mtime_ns: (m.mtime() as i128) * 1_000_000_000 + m.mtime_nsec() as i128,
            ctime_ns: (m.ctime() as i128) * 1_000_000_000 + m.ctime_nsec() as i128,
        }
    }
}

/// Cheap classification of a file's current content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentClass {
    /// Recognised plaintext (UTF-8/UTF-16 text) or a structured low-entropy
    /// document we sampled.
    Plain,
    /// Recognised compressed/archive container: high entropy is expected.
    CompressedContainer,
    /// Recognised non-compressed binary (PDF, SQLite, media...).
    Binary,
    /// No recognised header, entropy at or above the high-entropy threshold.
    HighEntropy,
    /// No recognised header, entropy below threshold.
    Opague,
    /// Not sampled (too small, ignored, unreadable).
    Unsampled,
}

#[derive(Clone, Debug)]
pub struct FileRecord {
    pub meta: FileMeta,
    pub entropy: Option<f32>,
    pub printable: f32,
    pub format: Option<KnownFormat>,
    pub digest: [u8; 16],
    pub class: ContentClass,
    /// Have we already counted this incarnation as ciphertext?  Avoids
    /// re-counting a file that is sampled repeatedly during one long write.
    pub counted_as_ciphertext: bool,
    pub last_sample: Instant,
    pub last_seen: Instant,
    pub first_seen: Instant,
    /// Whether the file has been renamed since we first saw it.
    pub renamed_count: u32,
}

impl FileRecord {
    pub fn new(meta: FileMeta, now: Instant) -> Self {
        Self {
            meta,
            entropy: None,
            printable: 0.0,
            format: None,
            digest: [0u8; 16],
            class: ContentClass::Unsampled,
            counted_as_ciphertext: false,
            last_sample: now - Duration::from_secs(3600),
            last_seen: now,
            first_seen: now,
            renamed_count: 0,
        }
    }

    pub fn is_plaintext(&self) -> bool {
        self.class == ContentClass::Plain
    }
}

/// A recently vanished path, retained so a reappearing inode can be recognised
/// as a rename rather than a delete+create.
#[derive(Clone, Debug)]
pub struct Grave {
    pub record: FileRecord,
    pub path: PathBuf,
    pub died_at: Instant,
}

pub struct FileStore {
    /// Live records, keyed by absolute path.
    pub files: HashMap<PathBuf, FileRecord>,
    /// Recently deleted/renamed-away paths, keyed by inode.
    graveyard: HashMap<FileKey, Grave>,
    /// How long a grave is kept for rename pairing.
    pub grave_ttl: Duration,
    /// Total live records (kept in sync with `files.len()`; used for caps).
    pub live: usize,
}

impl FileStore {
    pub fn new(grave_ttl: Duration) -> Self {
        Self {
            files: HashMap::new(),
            graveyard: HashMap::new(),
            grave_ttl,
            live: 0,
        }
    }

    pub fn get(&self, path: &Path) -> Option<&FileRecord> {
        self.files.get(path)
    }

    pub fn insert(&mut self, path: PathBuf, rec: FileRecord) {
        if self.files.insert(path, rec).is_none() {
            self.live += 1;
        }
    }

    /// Forget a path; if `keep_grave`, remember it by inode for rename pairing.
    pub fn remove(&mut self, path: &Path, keep_grave: bool, now: Instant) -> Option<FileRecord> {
        let rec = self.files.remove(path)?;
        self.live = self.live.saturating_sub(1);
        if keep_grave {
            self.graveyard.insert(
                rec.meta.key,
                Grave {
                    record: rec.clone(),
                    path: path.to_path_buf(),
                    died_at: now,
                },
            );
        }
        Some(rec)
    }

    /// Look up (and take) a grave for an inode that just reappeared.
    pub fn take_grave(&mut self, key: FileKey, now: Instant) -> Option<Grave> {
        let g = self.graveyard.remove(&key)?;
        if now.duration_since(g.died_at) <= self.grave_ttl {
            Some(g)
        } else {
            None
        }
    }

    pub fn peek_grave(&self, key: FileKey) -> Option<&Grave> {
        self.graveyard.get(&key)
    }

    pub fn purge_graves(&mut self, now: Instant) {
        let ttl = self.grave_ttl;
        self.graveyard
            .retain(|_, g| now.duration_since(g.died_at) <= ttl);
    }

    /// Drop records for paths under `root` that have not been seen for `ttl`.
    pub fn purge_stale(&mut self, root: &Path, now: Instant, ttl: Duration) {
        let before = self.files.len();
        self.files.retain(|p, r| {
            !(p.starts_with(root) && now.duration_since(r.last_seen) > ttl)
        });
        self.live = self.live.saturating_sub(before - self.files.len());
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Stat a path into a `FileMeta`, returning `None` if it does not exist.
pub fn stat(path: &Path) -> Option<FileMeta> {
    std::fs::metadata(path)
        .ok()
        .map(|m| FileMeta::from_metadata(&m))
}
