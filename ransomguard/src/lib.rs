//! RansomGuard — terminal-side early ransomware detection.
//!
//! Signals:
//! * **entropy surge** — many files rewritten to high-entropy content within
//!   a short rolling window,
//! * **extension churn** — mass renames swapping/cropping extensions,
//! * **ransom notes** — name + content marker detection,
//! * **canary files** — honeyfiles whose very first touch alerts instantly.
//!
//! On a critical alert the responsible process (via `lsof` attribution) is
//! frozen with SIGSTOP and a forensic snapshot is written to the state dir.

pub mod canary;
pub mod config;
pub mod engine;
pub mod entropy;
pub mod process;
pub mod report;
pub mod sampler;
pub mod watcher;
