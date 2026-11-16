//! `ransom-sim` — a deliberately guarded workload generator for testing
//! `ransomwatch`.
//!
//! Every write is refused unless the target is inside the directory passed on
//! the command line *and* that directory looks like a scratch/test area (its
//! name contains one of the configured markers, e.g. "test", "sandbox", "tmp").
//! There is no "force" flag.  This is test tooling, not a ransomware binary:
//! it does not hold keys to ransom, does not touch anything outside its target,
//! and refuses to run against a directory that looks like real user data.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use walkdir::WalkDir;

/// Extensions the simulator will encrypt.  Deliberately limited to documents
/// and source so a mis-targeted run is survivable.
const ENCRYPTABLE: &[&str] = &[
    "txt", "md", "csv", "json", "xml", "yaml", "yml", "log", "html", "htm", "tex", "rtf", "rst",
    "rs", "py", "js", "ts", "go", "c", "h", "cpp", "java", "rb", "php", "sql", "sh", "toml",
    "ini", "cfg", "conf", "doc", "docx", "xls", "xlsx", "pdf", "ppt", "pptx", "odt", "ods",
];

#[derive(Parser)]
#[command(
    name = "ransom-sim",
    version,
    about = "Guarded ransomware / benign-workload simulator for ransomwatch testing",
    long_about = "Generates realistic malicious and benign file activity inside a scratch \
                  directory so the detector's happy path and its false-positive behaviour can be \
                  exercised end to end.  Refuses to operate outside a directory whose name \
                  contains test/sandbox/scratch/tmp."
)]
struct Cli {
    /// Target directory (must be a scratch/test directory).
    #[arg(short, long)]
    dir: PathBuf,

    /// Refuse anyway, if you are sure the directory is disposable.  (Still
    /// cannot escape --dir.)
    #[arg(long)]
    allow_any_dir: bool,

    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Encrypt documents in place: same path, ciphertext content.  This is the
    /// pattern that catches key-less "encrypt in place" variants and is the
    /// strongest entropy signal.
    Inplace {
        /// How many files to rewrite.
        #[arg(long, default_value_t = 200)]
        files: usize,
        /// Pause between files, in milliseconds.
        #[arg(long, default_value_t = 3)]
        delay_ms: u64,
        /// Also overwrite the original with zeroes first (defeats naive
        /// content-preservation checks).
        #[arg(long)]
        shred: bool,
    },
    /// Encrypt each document to a new file and append a ransom extension,
    /// then delete the original — the classic behaviour.
    EncryptRename {
        #[arg(long, default_value_t = 200)]
        files: usize,
        #[arg(long, default_value_t = 3)]
        delay_ms: u64,
        /// Ransomware-family-style extension.
        #[arg(long, default_value = "locked")]
        ext: String,
        /// Write a ransom note per directory.
        #[arg(long, default_value_t = true)]
        note: bool,
    },
    /// Rename many files to a uniform new extension without touching content.
    ExtOnly {
        #[arg(long, default_value_t = 100)]
        files: usize,
        #[arg(long, default_value = "encrypted")]
        ext: String,
    },
    /// Drop ransom notes only.
    Notes,
    /// One read of every decoy file found (open/read/close), which the
    /// honeytoken detector is meant to catch.
    DecoyProbe {
        /// How many times to read each decoy.
        #[arg(long, default_value_t = 1)]
        rounds: u32,
        #[arg(long, default_value_t = 100)]
        delay_ms: u64,
    },
    /// Delete many files.
    Delete {
        #[arg(long, default_value_t = 100)]
        files: usize,
    },
    /// Large-volume write without touching the tree's semantics (simulates an
    /// archiver's scratch output, for calibration).
    WriteVolume {
        #[arg(long, default_value_t = 32)]
        megabytes: usize,
    },
    /// Obvious decoy writer: encrypt the decoys themselves.
    EncryptDecoys {
        #[arg(long, default_value = "locked")]
        ext: String,
    },
    /// Populate the target directory with N plaintext documents.
    Populate {
        #[arg(long, default_value_t = 200)]
        files: usize,
        /// Directory-scan depth: use "docs/year/month" style layout.
        #[arg(long, default_value_t = true)]
        nested: bool,
    },
    /// Write a plausible ransom note into the target root.
    DropNote,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("ransom-sim: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let dir = std::fs::canonicalize(&cli.dir)
        .map_err(|e| anyhow::anyhow!("cannot resolve {}: {e}", cli.dir.display()))?;
    guard(&dir, cli.allow_any_dir)?;
    match cli.mode {
        Mode::Populate { files, nested } => populate(&dir, files, nested),
        Mode::Inplace {
            files,
            delay_ms,
            shred,
        } => inplace(&dir, files, delay_ms, shred),
        Mode::EncryptRename {
            files,
            delay_ms,
            ext,
            note,
        } => encrypt_rename(&dir, files, delay_ms, &ext, note),
        Mode::ExtOnly { files, ext } => ext_only(&dir, files, &ext),
        Mode::Notes => drop_notes(&dir),
        Mode::DropNote => drop_note(&dir),
        Mode::DecoyProbe { rounds, delay_ms } => decoy_probe(&dir, rounds, delay_ms),
        Mode::Delete { files } => delete_some(&dir, files),
        Mode::WriteVolume { megabytes } => write_volume(&dir, megabytes),
        Mode::EncryptDecoys { ext } => encrypt_decoys(&dir, &ext),
    }
}

/// Refuse to touch anything that does not look like a scratch directory.
fn guard(dir: &Path, allow_any: bool) -> anyhow::Result<()> {
    if dir.parent().is_none() || dir == Path::new("/") {
        anyhow::bail!("refusing to operate on the filesystem root");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if let Some(home) = &home {
        if dir == *home || dir.parent() == Some(home.as_path()) {
            anyhow::bail!(
                "refusing to operate on {} (home directory or a direct child of it)",
                dir.display()
            );
        }
    }
    for forbidden in ["/Applications", "/Library", "/System", "/Users", "/etc", "/usr", "/var"] {
        if dir.starts_with(forbidden) && dir.components().count() <= 3 {
            anyhow::bail!("refusing to operate inside {forbidden}");
        }
    }
    let name = dir
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let markers = ["test", "sandbox", "scratch", "tmp", "temp", "demo", "fixture", "canary"];
    if !allow_any && !markers.iter().any(|m| name.contains(m)) {
        anyhow::bail!(
            "{} does not look like a scratch/test directory (name must contain one of {:?}); \
             pass --allow-any-dir to override",
            dir.display(),
            markers
        );
    }
    Ok(())
}

/// Guarantee a path is inside the guarded directory before any destructive op.
fn within(root: &Path, path: &Path) -> anyhow::Result<()> {
    if !path.starts_with(root) {
        anyhow::bail!("refusing to touch {} outside {}", path.display(), root.display());
    }
    // Refuse symlinks that point outside the tree.
    if let Ok(md) = std::fs::symlink_metadata(path) {
        if md.file_type().is_symlink() {
            let target = std::fs::canonicalize(path)?;
            if !target.starts_with(root) {
                anyhow::bail!("refusing to follow symlink out of tree: {}", path.display());
            }
        }
    }
    Ok(())
}

fn encryptable(path: &Path) -> bool {
    let Some(ext) = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    ENCRYPTABLE.contains(&ext.as_str())
}

fn collect_docs(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| encryptable(p))
        .filter(|p| {
            // Never touch our own decoy area by accident; there is a separate
            // mode for that.
            !p.to_string_lossy().contains("__rw_decoys")
        })
        .collect()
}

fn collect_all_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| !p.to_string_lossy().contains("__rw_decoys"))
        .collect()
}

/// Deterministic-per-file keystream so repeat runs behave identically.  This
/// is NOT secure encryption; it only needs to look like it.
fn cipher_file(root: &Path, path: &Path, ext: Option<&str>, shred: bool) -> anyhow::Result<PathBuf> {
    within(root, path)?;
    let data = std::fs::read(path)?;
    let mut buf = data.clone();
    let mut seed = [0u8; 32];
    let mut nonce = [0u8; 12];
    // Fill from the path hash so runs are reproducible.
    let h = {
        use std::hash::{Hash, Hasher};
        let mut s = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut s);
        s.finish()
    };
    for (i, b) in seed.iter_mut().enumerate() {
        *b = ((h >> ((i % 8) * 8)) & 0xff) as u8 ^ (i as u8).wrapping_mul(31);
    }
    for (i, b) in nonce.iter_mut().enumerate() {
        *b = ((h >> ((i % 8) * 8)) & 0xff) as u8 ^ 0x9e;
    }
    let mut cipher = ChaCha20::new(&seed.into(), &nonce.into());
    cipher.apply_keystream(&mut buf);

    let target = match ext {
        Some(e) => path.with_extension(format!("{}.{e}", path.extension().unwrap_or_default().to_string_lossy())),
        None => path.to_path_buf(),
    };
    if shred {
        // Overwrite plaintext before writing ciphertext in place.
        let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
        f.write_all(&vec![0u8; data.len()])?;
        f.sync_all()?;
        drop(f);
    }
    std::fs::write(&target, &buf)?;
    if target != path {
        within(root, path)?;
        std::fs::remove_file(path)?;
    }
    Ok(target)
}

fn populate(root: &Path, files: usize, nested: bool) -> anyhow::Result<()> {
    let words = vec![
        "report", "invoice", "budget", "memo", "contract", "summary", "notes", "plan", "review",
        "analysis", "schedule", "policy", "agenda", "draft", "final",
    ];
    for i in 0..files {
        let sub = if nested {
            format!("docs/{}/{}", 2020 + i % 5, i % 12 + 1)
        } else {
            String::new()
        };
        let dir = root.join(&sub);
        std::fs::create_dir_all(&dir)?;
        let word = words[i % words.len()];
        let ext = ["txt", "md", "csv"][i % 3];
        let p = dir.join(format!("{word}_{i:04}.{ext}"));
        let body = format!(
            "# {word} {i}\n\nThis document contains ordinary prose and numbers.\n\
             Line item,amount,owner\n{}\n",
            (0..60)
                .map(|j| format!("row {j}, {}, user{}", j * 17 + i, j % 7))
                .collect::<Vec<_>>()
                .join("\n")
        );
        within(root, &p)?;
        std::fs::write(&p, body)?;
    }
    eprintln!("populated {files} document(s) under {}", root.display());
    Ok(())
}

fn inplace(root: &Path, files: usize, delay_ms: u64, shred: bool) -> anyhow::Result<()> {
    let docs = collect_docs(root);
    let n = files.min(docs.len());
    for p in docs.iter().take(n) {
        cipher_file(root, p, None, shred)?;
        if delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
    }
    eprintln!("rewrote {n}/{files} files in place under {}", root.display());
    Ok(())
}

fn encrypt_rename(
    root: &Path,
    files: usize,
    delay_ms: u64,
    ext: &str,
    note: bool,
) -> anyhow::Result<()> {
    let docs = collect_docs(root);
    let n = files.min(docs.len());
    let mut dirs = std::collections::HashSet::new();
    for p in docs.iter().take(n) {
        if let Some(d) = p.parent() {
            dirs.insert(d.to_path_buf());
        }
        cipher_file(root, p, Some(ext), false)?;
        if delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
    }
    if note {
        for d in dirs {
            within(root, &d)?;
            let note_path = d.join(format!("HOW_TO_DECRYPT_{ext}.txt"));
            std::fs::write(&note_path, note_body(ext))?;
        }
    }
    eprintln!(
        "encrypted and renamed {n}/{files} files with .{ext} under {}",
        root.display()
    );
    Ok(())
}

fn ext_only(root: &Path, files: usize, ext: &str) -> anyhow::Result<()> {
    let docs = collect_all_files(root);
    let n = files.min(docs.len());
    for p in docs.iter().take(n) {
        within(root, p)?;
        let newp = p.with_extension(format!(
            "{}.{ext}",
            p.extension().unwrap_or_default().to_string_lossy()
        ));
        within(root, &newp)?;
        std::fs::rename(p, &newp)?;
    }
    eprintln!("renamed {n}/{files} files to .{ext}");
    Ok(())
}

fn note_body(ext: &str) -> String {
    format!(
        "!!! YOUR FILES HAVE BEEN ENCRYPTED !!!\n\n\
         All your documents, photos, databases and other important files have been encrypted\n\
         with the strongest algorithm and a unique key generated for this machine.\n\n\
         The only way to recover your files is to buy our decryption tool.\n\
         Send 0.05 bitcoin to the bitcoin address below and email the transaction id.\n\n\
         bitcoin address: bc1qexampleaddressdonotsendfunds\n\
         contact: example@onion.invalid\n\n\
         Do not rename or modify the encrypted files (.{ext}); doing so will destroy them.\n\
         You have 72 hours before the price will be doubled.\n"
    )
}

fn drop_notes(root: &Path) -> anyhow::Result<()> {
    let note = root.join("HOW_TO_DECRYPT.txt");
    within(root, &note)?;
    std::fs::write(&note, note_body("locked"))?;
    eprintln!("wrote {}", note.display());
    Ok(())
}

fn drop_note(root: &Path) -> anyhow::Result<()> {
    drop_notes(root)
}

fn decoy_probe(root: &Path, rounds: u32, delay_ms: u64) -> anyhow::Result<()> {
    let mut decoys = Vec::new();
    for e in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if e.file_type().is_file() && e.path().to_string_lossy().contains("__rw_decoys") {
            decoys.push(e.into_path());
        }
    }
    if decoys.is_empty() {
        anyhow::bail!("no decoy files found under {}", root.display());
    }
    for _ in 0..rounds {
        for p in &decoys {
            within(root, p)?;
            let mut f = std::fs::File::open(p)?;
            let mut buf = Vec::new();
            use std::io::Read;
            f.read_to_end(&mut buf)?;
            if delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
        }
    }
    eprintln!("read {} decoy file(s) {} time(s)", decoys.len(), rounds);
    Ok(())
}

fn delete_some(root: &Path, files: usize) -> anyhow::Result<()> {
    let docs = collect_all_files(root);
    let n = files.min(docs.len());
    for p in docs.iter().take(n) {
        within(root, p)?;
        std::fs::remove_file(p)?;
    }
    eprintln!("deleted {n}/{files} files");
    Ok(())
}

fn write_volume(root: &Path, megabytes: usize) -> anyhow::Result<()> {
    let p = root.join("archive_output.bin");
    within(root, &p)?;
    let mut f = std::fs::File::create(&p)?;
    let mut x: u64 = 0x1234_5678;
    let chunk = vec![0u8; 1024 * 1024];
    let _ = chunk;
    for _ in 0..megabytes {
        let mut buf = vec![0u8; 1024 * 1024];
        for b in buf.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x >> 24) as u8;
        }
        f.write_all(&buf)?;
    }
    f.sync_all()?;
    eprintln!("wrote {megabytes} MiB to {}", p.display());
    Ok(())
}

fn encrypt_decoys(root: &Path, ext: &str) -> anyhow::Result<()> {
    let mut decoys = Vec::new();
    for e in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if e.file_type().is_file() && e.path().to_string_lossy().contains("__rw_decoys") {
            decoys.push(e.into_path());
        }
    }
    for p in &decoys {
        cipher_file(root, p, Some(ext), false)?;
    }
    eprintln!("encrypted {} decoy file(s)", decoys.len());
    Ok(())
}

/* stub removed */
