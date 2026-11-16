//! `ransomwatch` — terminal-side early detection for ransomware-like file
//! activity.
//!
//! The library is split so the decision logic stays testable without a real
//! filesystem or a real encryption run:
//!
//! | module | responsibility |
//! |---|---|
//! | [`entropy`] | sampling bytes and estimating Shannon entropy |
//! | [`format`] | magic-byte sniffing, ransomware extensions, note language |
//! | [`state`] | what we knew about each path before it changed |
//! | [`detect`] | sliding-window signals and incident scoring |
//! | [`decoy`] | honeytoken placement and trip detection |
//! | [`watch`]  | filesystem event source (FSEvents / inotify / poll) |
//! | [`engine`] | reconcile, sample, feed the detector, run response |
//! | [`respond`] | attribution, SIGSTOP, forensic bundle |
//! | [`sys`]    | process introspection and signals |
//! | [`config`] | defaults, TOML loading, CLI overrides |

pub mod config;
pub mod decoy;
pub mod detect;
pub mod engine;
pub mod entropy;
pub mod format;
pub mod respond;
pub mod state;
pub mod sys;
pub mod util;
pub mod watch;

pub use config::Config;
pub use engine::Engine;
