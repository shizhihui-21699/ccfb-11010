//! Shannon-entropy based content classification.
//!
//! Ransomware-encrypted (or otherwise random) content sits near 8 bits/byte,
//! while source code, logs and office documents typically sit between 3.5 and
//! 5.5 bits/byte. Already-compressed archives (gz/zip/zst/...) are also
//! high-entropy, which is why the engine treats them separately instead of
//! crying wolf on every backup run.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Default threshold above which content is considered "high entropy".
/// Calibrated in `tests/integration.rs` against real content classes.
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.4;

/// A rewrite that jumps by at least this many bits/byte counts as an
/// entropy surge even if the absolute value stays below the absolute cutoff.
pub const ENTROPY_DELTA_THRESHOLD: f64 = 1.5;

const HEAD_BYTES: u64 = 32 * 1024;
const TAIL_BYTES: u64 = 32 * 1024;
const MIN_SAMPLE_SIZE: u64 = 64;

/// Shannon entropy in bits/byte.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut e = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            e -= p * p.log2();
        }
    }
    e
}

/// Sample head + tail of a file and return its entropy.
///
/// Returns `Ok(None)` for files too small to classify meaningfully or files
/// that cannot be read (already deleted, permission denied, ...).
pub fn file_entropy(path: &Path) -> Option<f64> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if len < MIN_SAMPLE_SIZE {
        return None;
    }
    let cap = HEAD_BYTES + TAIL_BYTES;
    let buf = if len <= cap {
        let mut buf = vec![0u8; len as usize];
        f.read_exact(&mut buf).ok()?;
        buf
    } else {
        let mut buf = vec![0u8; cap as usize];
        f.read_exact(&mut buf[..HEAD_BYTES as usize]).ok()?;
        f.seek(SeekFrom::Start(len - TAIL_BYTES)).ok()?;
        f.read_exact(&mut buf[HEAD_BYTES as usize..]).ok()?;
        buf
    };
    // Head + tail sampling: ransomware rewrites whole files, so both ends
    // carry random payload; head-only sampling would be fooled by files that
    // keep a structured header in front of encrypted content.
    Some(shannon_entropy(&buf))
}

/// Extensions of formats that are *expected* to look high-entropy.
/// Files newly created with these suffixes are excluded from the entropy
/// surge counter (they still count toward extension-churn analysis).
pub const TRUSTED_HIGH_ENTROPY_EXTENSIONS: &[&str] = &[
    ".gz", ".tgz", ".bz2", ".xz", ".zst", ".zip", ".7z", ".lz4", ".tar", ".dmg", ".pkg", ".jpg",
    ".jpeg", ".png", ".gif", ".mp4", ".mov", ".mkv", ".pdf", ".woff2", ".wasm",
];

pub fn is_trusted_high_entropy_type(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    TRUSTED_HIGH_ENTROPY_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert!((shannon_entropy(b"aaaaaaaaaaaa") - 0.0).abs() < 1e-9);
        // Uniform over all 256 byte values -> 8.0 bits/byte.
        let uniform: Vec<u8> = (0u32..256).map(|i| i as u8).cycle().take(4096).collect();
        assert!((shannon_entropy(&uniform) - 8.0).abs() < 0.01);
    }

    #[test]
    fn text_is_low_entropy() {
        let text =
            b"Dear team,\nThe quarterly report is attached. Please review before Friday's meeting."
                .repeat(64);
        assert!(shannon_entropy(&text) < 6.0);
    }
}
