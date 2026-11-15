//! ransomwatch — endpoint-side early ransomware detection.
//!
//! The library is split so each concern can be tested in isolation:
//!
//! * [`entropy`] — content classification (is this ciphertext?).
//! * [`events`] — turns `notify` events into four simple hints.
//! * [`detect`] — the sliding-window scorer that decides *whether this is an
//!   outbreak*, which is what separates ransomware from a backup run.
//! * [`decoy`] — canary files that fire without any scoring.
//! * [`procinfo`] / [`attr`] — who wrote it: process metadata, trust model and
//!   open-file attribution.
//! * [`forensics`] — the incident record and evidence copy.
//! * [`respond`] — suspend the suspect, preserve the scene.
//! * [`config`], [`util`] — configuration and small helpers.

pub mod attr;
pub mod config;
pub mod decoy;
pub mod detect;
pub mod entropy;
pub mod events;
pub mod forensics;
pub mod procinfo;
pub mod respond;
pub mod util;
