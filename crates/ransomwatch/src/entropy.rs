//! Content sampling and byte-entropy estimation.
//!
//! Reading a whole multi-gigabyte file on every write notification is not
//! affordable, and it is not necessary: the transforms we care about
//! (encryption, compression) rewrite the entire byte stream, so a handful of
//! evenly spread chunks is representative.  We read a head, middle and tail
//! chunk and feed them into a 256-bin Shannon entropy histogram (bits/byte).

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;

/// How much to read when sampling a file.
#[derive(Clone, Copy, Debug)]
pub struct SampleConfig {
    pub head_bytes: usize,
    pub mid_bytes: usize,
    pub tail_bytes: usize,
}

impl Default for SampleConfig {
    fn default() -> Self {
        Self {
            head_bytes: 16 * 1024,
            mid_bytes: 16 * 1024,
            tail_bytes: 16 * 1024,
        }
    }
}

impl SampleConfig {
    pub fn small() -> Self {
        Self {
            head_bytes: 8 * 1024,
            mid_bytes: 0,
            tail_bytes: 8 * 1024,
        }
    }

    pub fn max_bytes(&self) -> u64 {
        (self.head_bytes + self.mid_bytes + self.tail_bytes) as u64
    }
}

/// Result of sampling one file.
#[derive(Clone, Debug, Default)]
pub struct ContentSample {
    pub size: u64,
    /// Shannon entropy of the sampled bytes, in bits/byte (0.0..=8.0).
    pub entropy: f32,
    /// Fraction of sampled bytes that are printable ASCII / whitespace.
    pub printable: f32,
    /// Truncated digest of the sample (size + chunk offsets + bytes).
    pub digest: [u8; 16],
    /// First bytes of the file (for magic sniffing and note scanning).
    pub head: Vec<u8>,
}

impl ContentSample {
    pub fn digest_hex(&self) -> String {
        hex16(&self.digest)
    }
}

pub fn hex16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn read_at_best_effort(f: &File, off: u64, len: usize) -> io::Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        match f.read_at(&mut buf[filled..], off + filled as u64) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Sample a file's content.
///
/// Chunks are read with `pread` so the file offset is not disturbed (and we do
/// not race with a writer's own seek position).
pub fn sample_file(path: &Path, cfg: SampleConfig) -> io::Result<ContentSample> {
    let f = File::open(path)?;
    let meta = f.metadata()?;
    let size = meta.len();

    let mut chunks: Vec<(u64, Vec<u8>)> = Vec::with_capacity(3);
    let head_len = cfg.head_bytes.min(size as usize);
    let head = read_at_best_effort(&f, 0, head_len)?;
    if !head.is_empty() {
        chunks.push((0, head));
    }

    if size > 2 * cfg.max_bytes() && cfg.mid_bytes > 0 {
        let mid_off = size / 2;
        let mid = read_at_best_effort(&f, mid_off, cfg.mid_bytes)?;
        if !mid.is_empty() {
            chunks.push((mid_off, mid));
        }
    }

    if size > cfg.head_bytes as u64 && cfg.tail_bytes > 0 {
        let tail_len = cfg.tail_bytes.min(size as usize);
        let tail_off = size - tail_len as u64;
        let tail = read_at_best_effort(&f, tail_off, tail_len)?;
        if !tail.is_empty() {
            chunks.push((tail_off, tail));
        }
    }

    let mut hist = [0u64; 256];
    let mut printable = 0u64;
    let mut total = 0u64;
    let mut hasher = Sha256::new();
    hasher.update(size.to_le_bytes());
    for (off, bytes) in &chunks {
        hasher.update(off.to_le_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        for &b in bytes {
            hist[b as usize] += 1;
            total += 1;
            if (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
                printable += 1;
            }
        }
    }

    let digest_full = hasher.finalize();
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&digest_full[..16]);

    let head_bytes = chunks.first().map(|(_, b)| b.clone()).unwrap_or_default();

    Ok(ContentSample {
        size,
        entropy: shannon_entropy(&hist, total),
        printable: if total == 0 {
            0.0
        } else {
            printable as f32 / total as f32
        },
        digest,
        head: head_bytes,
    })
}

fn shannon_entropy(hist: &[u64; 256], total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let n = total as f64;
    let mut h = 0.0f64;
    for &c in hist.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h as f32
}

/// Convenience for tests and small in-memory buffers.
pub fn entropy_of(bytes: &[u8]) -> f32 {
    let mut hist = [0u64; 256];
    for &b in bytes {
        hist[b as usize] += 1;
    }
    shannon_entropy(&hist, bytes.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn zeroes_have_zero_entropy() {
        assert!(entropy_of(&[0u8; 100_000]) < 0.001);
    }

    #[test]
    fn english_text_is_low() {
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(500);
        let e = entropy_of(text.as_bytes());
        assert!(e > 3.5 && e < 5.2, "text entropy {e}");
    }

    #[test]
    fn uniform_random_is_near_eight() {
        let mut buf = vec![0u8; 100_000];
        // xorshift, no external rand dependency
        let mut x: u64 = 0x9e3779b97f4a7c15;
        for b in buf.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x >> 24) as u8;
        }
        let e = entropy_of(&buf);
        assert!(e > 7.9, "random entropy {e}");
    }

    #[test]
    fn sampling_detects_low_to_high_transition() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("doc.txt");
        std::fs::write(&p, "hello world ".repeat(5000)).unwrap();
        let before = sample_file(&p, SampleConfig::default()).unwrap();
        assert!(before.entropy < 5.0);

        let mut f = std::fs::File::create(&p).unwrap();
        let mut x: u64 = 12345;
        for _ in 0..100_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            f.write_all(&[(x >> 24) as u8]).unwrap();
        }
        let after = sample_file(&p, SampleConfig::default()).unwrap();
        assert!(after.entropy > 7.9, "after entropy {}", after.entropy);
        assert_ne!(before.digest, after.digest);
    }

    #[test]
    fn changed_content_changes_digest() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("a.bin");
        std::fs::write(&p, vec![7u8; 50_000]).unwrap();
        let a = sample_file(&p, SampleConfig::default()).unwrap();
        std::fs::write(&p, vec![8u8; 50_000]).unwrap();
        let b = sample_file(&p, SampleConfig::default()).unwrap();
        assert_ne!(a.digest, b.digest);
    }
}
