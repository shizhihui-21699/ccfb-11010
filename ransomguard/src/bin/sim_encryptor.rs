//! Simulated file encryptor for testing RansomGuard — test directories only.
//!
//! Generates a random-looking keystream with a deterministic, seeded
//! xoshiro256++ PRNG and XOR-rewrites files in place, then optionally
//! renames them with a hostile suffix and drops a ransom-note file.
//! It refuses to run outside an explicit, already-existing target directory
//! and never follows symlinks.

use clap::Parser;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "sim_encryptor",
    about = "Test-only ransomware simulator (touches only the given directory)"
)]
struct Args {
    /// Directory whose files will be rewritten. Must already exist.
    #[arg(long)]
    target: PathBuf,

    /// Append this extension to every processed file (e.g. `.locked`).
    #[arg(long, default_value = ".locked")]
    ext: String,

    /// Do NOT rename files after rewriting (default: mass-rename to ext).
    #[arg(long, default_value_t = false)]
    no_rename: bool,

    /// Do NOT drop a README-style ransom note in the target root.
    #[arg(long, default_value_t = false)]
    no_note: bool,

    /// Skip hidden files and directories (lets an entropy-only test avoid
    /// the canary directory).
    #[arg(long)]
    skip_hidden: bool,

    /// Delay between files in milliseconds (0 = as fast as possible).
    #[arg(long, default_value_t = 0)]
    delay_ms: u64,

    /// Keep each output file's handle open for this many milliseconds after
    /// writing, so `lsof`-based attribution can observe the active handle
    /// (real encryptors hold files open for the duration of encryption).
    #[arg(long, default_value_t = 0)]
    hold_open_ms: u64,

    /// PRNG seed for reproducible runs.
    #[arg(long, default_value_t = 0x517a_4e45_5354_5345)]
    seed: u64,

    /// Only process up to N files (0 = all).
    #[arg(long, default_value_t = 0)]
    limit: usize,

    /// Process hidden files (including any `.ransomguard-canary` directory)
    /// last. This mirrors an attack whose mass-encryption phase trips the
    /// entropy/extension detectors before it reaches the honeyfiles, giving
    /// poll-based attribution time to lock onto the process.
    #[arg(long)]
    hidden_last: bool,
}

struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    fn new(seed: u64) -> Self {
        // SplitMix64 seeding.
        let mut s = [0u64; 4];
        let mut x = seed;
        for slot in s.iter_mut() {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            *slot = z ^ (z >> 31);
        }
        Self { s }
    }

    fn next(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }
}

fn is_hidden(path: &std::path::Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| s.starts_with('.'))
            .unwrap_or(false)
    })
}

fn main() {
    let args = Args::parse();

    // Hard guard rails: existing directory, no root, no home.
    if !args.target.is_dir() {
        eprintln!(
            "refusing to run: target {} is not an existing directory",
            args.target.display()
        );
        std::process::exit(2);
    }
    let target = match args.target.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot resolve target: {e}");
            std::process::exit(2);
        }
    };
    let home = std::env::var("HOME").ok().map(PathBuf::from);
    if target.parent().is_none() || home.as_ref() == Some(&target) {
        eprintln!("refusing to run against {target:?}: too broad a blast radius");
        std::process::exit(2);
    }

    let mut files: Vec<PathBuf> = Vec::new();
    for entry in walkdir::WalkDir::new(&target)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if args.skip_hidden && is_hidden(entry.path()) {
            continue;
        }
        files.push(entry.path().to_path_buf());
    }
    files.sort();
    if args.hidden_last {
        // Stable partition: visible files keep their sorted order first,
        // hidden entries (e.g. a `.ransomguard-canary` directory) move last.
        let (visible, hidden): (Vec<PathBuf>, Vec<PathBuf>) =
            files.into_iter().partition(|p| !is_hidden(p));
        files = visible;
        files.extend(hidden);
    }
    if args.limit > 0 {
        files.truncate(args.limit);
    }

    println!(
        "sim_encryptor: {} files under {} (seed {:#x})",
        files.len(),
        target.display(),
        args.seed
    );

    let mut rng = Xoshiro256::new(args.seed);
    let mut processed = 0usize;
    for path in &files {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        let mut out = Vec::with_capacity(data.len());
        let mut counter = 0u64;
        let mut block = rng.next();
        for (i, byte) in data.iter().enumerate() {
            if i % 8 == 0 {
                block = rng.next() ^ counter;
                counter += 1;
            }
            out.push(byte ^ ((block >> ((i % 8) * 8)) & 0xff) as u8);
        }
        // Write to a sibling temp file then rename, like real malware does.
        // The handle is deliberately held open when --hold-open-ms is set,
        // giving poll-based attribution a chance to observe it.
        let tmp = path.with_extension(format!("simtmp{}", rng.next() % 1_000_000));
        let mut tf = match std::fs::File::create(&tmp) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if tf.write_all(&out).is_err() {
            continue;
        }
        if args.hold_open_ms > 0 {
            std::thread::sleep(Duration::from_millis(args.hold_open_ms));
        }
        drop(tf);
        let _ = std::fs::rename(&tmp, path);

        let mut renamed_to = None;
        if !args.no_rename {
            let new_name = match path.file_name() {
                Some(n) => {
                    let mut s = n.to_os_string();
                    s.push(&args.ext);
                    path.with_file_name(s)
                }
                None => path.clone(),
            };
            if std::fs::rename(path, &new_name).is_ok() {
                renamed_to = Some(new_name);
            }
        }
        processed += 1;
        println!(
            "encrypted {}{}",
            path.display(),
            renamed_to
                .as_ref()
                .map(|p| format!(" -> {}", p.display()))
                .unwrap_or_default()
        );
        if args.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(args.delay_ms));
        }
    }

    if !args.no_note {
        let note = target.join("README_DECRYPT_YOUR_FILES.txt");
        let body = "YOUR FILES HAVE BEEN ENCRYPTED\n\nAll your files were encrypted with \
                    AES-256 and RSA-2048. To recover them you must pay the ransom in Bitcoin. \
                    Send BTC to the wallet address below and contact us for the decryption key. \
                    Do not attempt to remove this program.\n";
        if let Ok(mut f) = std::fs::File::create(&note) {
            let _ = f.write_all(body.as_bytes());
            println!("dropped note {}", note.display());
        }
    }
    println!("sim_encryptor done: {processed} files processed");
}
