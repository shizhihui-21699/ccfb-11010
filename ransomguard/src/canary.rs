//! Canary (honeyfile) deployment.
//!
//! Each watched root gets a dedicated canary directory containing plausible
//! bait files. No legitimate software ever reads or writes inside it, so any
//! touch — read, write, rename, delete — is treated as a critical signal.
//! A manifest in the state directory records the deployed paths.

use crate::engine::CanarySet;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const CANARY_DIR_NAME: &str = ".ransomguard-canary";

#[derive(Debug, Serialize, Deserialize)]
struct CanaryManifest {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
}

fn bait_content(name: &str) -> Vec<u8> {
    let mut v = format!("RANSOMGUARD CANARY FILE — do not edit.\nFile: {name}\n\n").into_bytes();
    // Deterministic, non-secret filler so the bait looks like real content.
    let filler = b"quarterly earnings, client contacts, vacation plan, family photos. ";
    while v.len() < 4096 {
        v.extend_from_slice(filler);
    }
    v
}

/// Deploy canaries for every watched root (idempotent) and merge with
/// operator-supplied extra canaries. Writes the manifest under `state_dir`.
pub fn deploy(
    watch_roots: &[PathBuf],
    names: &[String],
    extra_canaries: &[PathBuf],
    state_dir: &Path,
) -> std::io::Result<CanarySet> {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();

    for root in watch_roots {
        let cdir = root.join(CANARY_DIR_NAME);
        std::fs::create_dir_all(&cdir)?;
        dirs.push(cdir.clone());
        for name in names {
            let p = cdir.join(name);
            if !p.exists() {
                std::fs::write(&p, bait_content(name))?;
            }
            files.push(p);
        }
    }

    for extra in extra_canaries {
        if let Some(parent) = extra.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        if !extra.exists() {
            std::fs::write(extra, bait_content(&extra.display().to_string()))?;
        }
        files.push(extra.clone());
    }

    let manifest = CanaryManifest {
        files: files.clone(),
        dirs: dirs.clone(),
    };
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(
        state_dir.join("canaries.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;

    Ok(CanarySet { files, dirs })
}

pub fn load(state_dir: &Path) -> Option<CanarySet> {
    let raw = std::fs::read(state_dir.join("canaries.json")).ok()?;
    let m: CanaryManifest = serde_json::from_slice(&raw).ok()?;
    Some(CanarySet {
        files: m.files,
        dirs: m.dirs,
    })
}
