//! Content classification for written files.
//!
//! The central measurement is the zero-order byte entropy `H0`, but entropy alone
//! cannot tell ciphertext from compressed data: gzip/zip/xz payloads and AES
//! output are both ~7.99 bits/byte. What separates them in practice is that
//! compressors emit a recognisable container header and keep the file's
//! extension/type stable, while an encryptor replaces a document's bytes with an
//! opaque blob that carries no header at all.
//!
//! So the classifier combines:
//!   1. a container/format sniff on the first bytes (`magic`),
//!   2. `H0` (how uniform the byte distribution is),
//!   3. a chi-square uniformity score (`chi2_z`), which rejects "high entropy but
//!      structured" encodings such as base64 or hex dumps,
//!   4. the printable-ASCII ratio (text stays text),
//!   5. a per-chunk analysis ([`analyze_regions`]), so a file that is only
//!      *partly* encrypted — head-only or every other block — is still seen.
//!
//! Everything else in the detector works off [`Sample::class`].

use crate::config::EntropyConfig;

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// What the bytes look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentClass {
    /// Zero-length file.
    Empty,
    /// Printable text: source code, logs, CSV, JSON, most documents.
    TextLike,
    /// Low/medium entropy, not text (UTF-16 text, sqlite, executables, images
    /// with an unrecognised header).
    Structured,
    /// A recognised archive/compression/media/office container.
    Container(&'static str),
    /// High entropy (>= 7.0) but below the ciphertext band.
    HighEntropy,
    /// Indistinguishable from ciphertext: uniform, headerless, high entropy.
    Opaque,
    /// Partially encrypted: the sampled regions disagree sharply — some are
    /// ciphertext, others are still text. Ransomware that encrypts only the
    /// first block of each file produces exactly this shape, and so does a file
    /// being written by an encryptor that has not finished yet.
    PartialOpaque,
}

impl ContentClass {
    /// True only for the strict "looks like ciphertext" class.
    pub fn is_opaque(self) -> bool {
        matches!(self, ContentClass::Opaque)
    }

    /// True when the content contains ciphertext, whether all of it or part.
    pub fn has_ciphertext(self) -> bool {
        matches!(self, ContentClass::Opaque | ContentClass::PartialOpaque)
    }

    pub fn is_container(self) -> bool {
        matches!(self, ContentClass::Container(_))
    }

    pub fn is_textish(self) -> bool {
        matches!(
            self,
            ContentClass::TextLike | ContentClass::Structured | ContentClass::Empty
        )
    }

    pub fn label(self) -> String {
        match self {
            ContentClass::Empty => "empty".into(),
            ContentClass::TextLike => "text".into(),
            ContentClass::Structured => "structured".into(),
            ContentClass::Container(n) => format!("container:{}", n),
            ContentClass::HighEntropy => "high-entropy".into(),
            ContentClass::Opaque => "opaque".into(),
            ContentClass::PartialOpaque => "partial-opaque".into(),
        }
    }
}

/// Entropy statistics for one content sample.
#[derive(Debug, Clone)]
pub struct Sample {
    pub bytes: usize,
    /// Per-region classes, in sample order. More than one entry means the sample
    /// was read as separate chunks (head/middle/tail) and the regions disagreed.
    pub regions: Vec<ContentClass>,
    pub h0: f64,
    pub chi2_z: f64,
    pub printable: f64,
    pub distinct: usize,
    pub magic: Option<&'static str>,
    pub class: ContentClass,
}

impl Sample {
    pub fn is_ciphertext_like(&self) -> bool {
        self.class.is_opaque()
    }
}

/// Compute `H0`, chi-square z and the printable ratio over `bytes`.
pub fn analyze(bytes: &[u8], cfg: &EntropyConfig) -> Sample {
    let n = bytes.len();
    if n == 0 {
        return Sample {
            bytes: 0,
            regions: Vec::new(),
            h0: 0.0,
            chi2_z: 0.0,
            printable: 1.0,
            distinct: 0,
            magic: None,
            class: ContentClass::Empty,
        };
    }
    let mut counts = [0u64; 256];
    let mut printable = 0u64;
    for &b in bytes {
        counts[b as usize] += 1;
        if (9..=13).contains(&b) || (32..=126).contains(&b) {
            printable += 1;
        }
    }
    let nf = n as f64;
    let mut h0 = 0.0f64;
    let mut distinct = 0usize;
    for &c in counts.iter() {
        if c > 0 {
            distinct += 1;
            let p = c as f64 / nf;
            h0 -= p * p.log2();
        }
    }
    // Pearson chi-square against a uniform 256-symbol distribution.
    let expected = nf / 256.0;
    let chi2: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();
    // Standardised: (chi2 - dof) / sqrt(2*dof), dof = 255.
    let chi2_z = (chi2 - 255.0) / (2.0f64 * 255.0).sqrt();
    let magic = detect_magic(bytes);
    let printable_ratio = printable as f64 / nf;

    let class = if let Some(name) = magic {
        ContentClass::Container(name)
    } else if h0 >= cfg.high_entropy_h0
        && chi2_z <= cfg.uniform_chi2_z_max
        && distinct >= cfg.min_distinct_for_opaque
    {
        ContentClass::Opaque
    } else if h0 >= cfg.high_entropy_floor {
        ContentClass::HighEntropy
    } else if printable_ratio >= cfg.text_printable_ratio && h0 < cfg.text_max_h0 {
        ContentClass::TextLike
    } else {
        ContentClass::Structured
    };

    Sample {
        bytes: n,
        regions: Vec::new(),
        h0,
        chi2_z,
        printable: printable_ratio,
        distinct,
        magic,
        class,
    }
}

/// Classify one contiguous region. Used to detect partially-encrypted files,
/// where the whole-file average hides that half the bytes are ciphertext.
fn classify_region(bytes: &[u8], cfg: &EntropyConfig) -> ContentClass {
    if bytes.is_empty() {
        return ContentClass::Empty;
    }
    let s = analyze(bytes, cfg);
    s.class
}

/// Combine per-region classes into a whole-file verdict.
///
/// A file where part of the bytes are ciphertext and part are not is *more*
/// suspicious than either alone: no legitimate writer produces that shape.
///
/// The rule is deliberately narrow but alignment-tolerant. Intermittent
/// encryption (every other 4 KiB block) does not know where our sampling
/// boundaries fall, so some sampled regions straddle an encrypted block and its
/// plaintext neighbour. Those read as `Structured` after averaging, not
/// `Opaque`. Requiring one clearly-`Opaque` region *and* one clearly-not region
/// catches the aligned case immediately; accepting `Structured` as the "not
/// opaque yet" half catches the straddled case. A container region vetoes the
/// whole verdict, because an archive appended to a document is normal and must
/// never read as encryption.
pub fn combine_regions(regions: &[ContentClass]) -> Option<ContentClass> {
    if regions.len() < 2 {
        return None;
    }
    if regions.iter().any(|c| c.is_container()) {
        return None;
    }
    let opaque = regions.iter().filter(|c| c.is_opaque()).count();
    if opaque == 0 {
        return None;
    }
    let boundary = regions.iter().any(|c| matches!(
        c,
        ContentClass::TextLike | ContentClass::Structured | ContentClass::HighEntropy
    ));
    if boundary {
        return Some(ContentClass::PartialOpaque);
    }
    None
}

/// Read at most `cfg.sample_bytes` from a file as evenly-spaced chunks.
///
/// Returns the concatenated sample, the file size observed while reading, and
/// the byte ranges of each chunk inside the returned sample.
///
/// Chunking is the core of partial/intermittent encryption detection:
/// ransomware that encrypts only the head of each file, or every other block
/// ("intermittent encryption", used by BlackCat/ALPHV, LockFile and others),
/// leaves most of the bytes untouched. A single whole-file entropy average
/// hides that; many small regions make it visible. Eight chunks of ~8 KiB at
/// evenly spaced offsets is enough to catch both patterns while keeping the read
/// budget at `sample_bytes`.
pub fn read_sample_regions(
    path: &Path,
    cfg: &EntropyConfig,
) -> std::io::Result<(Vec<u8>, u64, Vec<std::ops::Range<usize>>)> {
    const TARGET_CHUNK: u64 = 4 * 1024;
    const MAX_CHUNKS: usize = 16;
    const MIN_CHUNKS: usize = 4;

    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let cap = cfg.sample_bytes as u64;
    let mut out = Vec::with_capacity(len.min(cap) as usize);

    if len <= cap {
        // Small enough to read whole. Still split it into regions: intermittent
        // encryption on a 5 KiB file is exactly the case a whole-file average
        // hides, and these are common (config files, CSV exports, small docs).
        f.read_to_end(&mut out)?;
        let n = out.len();
        let regions = split_into_regions(n, TARGET_CHUNK as usize);
        return Ok((out, len, regions));
    }

    // Fewer, larger chunks for files that are barely bigger than the budget:
    // a 70 KiB file should be read as 4 chunks of 17 KiB, not 16 of 4 KiB spread
    // over nearly the same bytes.
    let n_chunks = ((cap / TARGET_CHUNK).clamp(MIN_CHUNKS as u64, MAX_CHUNKS as u64)) as usize;
    let n_chunks = n_chunks.min(((len / TARGET_CHUNK).max(MIN_CHUNKS as u64)) as usize).max(1);
    let mut chunk = cap / n_chunks as u64;
    // Leave room so evenly spaced chunks do not overlap on small caps.
    let stride = (len.saturating_sub(chunk)) / (n_chunks as u64 - 1).max(1);
    chunk = chunk.max(1).min(stride.max(1));

    let mut regions = Vec::with_capacity(n_chunks);
    for i in 0..n_chunks {
        let pos = if n_chunks == 1 {
            0
        } else {
            (stride * i as u64).min(len.saturating_sub(chunk))
        };
        f.seek(SeekFrom::Start(pos))?;
        let mut buf = vec![0u8; chunk as usize];
        let got = read_up_to(&mut f, &mut buf)?;
        if got == 0 {
            continue;
        }
        let start = out.len();
        out.extend_from_slice(&buf[..got]);
        regions.push(start..out.len());
    }
    Ok((out, len, regions))
}

/// Split `0..n` into evenly sized regions, at most `MAX_CHUNKS`, each at least
/// `TARGET_CHUNK` where possible. Returns a single region when the buffer is too
/// small to split meaningfully.
fn split_into_regions(n: usize, target: usize) -> Vec<std::ops::Range<usize>> {
    if n == 0 {
        return Vec::new();
    }
    if n < target {
        // Smaller than one chunk: a single region is the only honest answer.
        // The Vec is the return type's shape, not an accident of this branch.
        #[allow(clippy::single_range_in_vec_init)]
        return vec![0..n];
    }
    // Two regions of a 5 KiB file are each ~2.5 KiB, which is still enough to
    // tell ciphertext from prose (H0 over 2 KiB of keystream stays ≈ 7.90).
    let count = (n / target).clamp(2, 16);
    let size = n / count;
    (0..count)
        .map(|i| {
            let start = i * size;
            let end = if i == count - 1 { n } else { start + size };
            start..end
        })
        .collect()
}

/// Analyze a file sample including per-region verdicts.
///
/// This is the entry point the detector uses. `analyze` alone looks at the whole
/// buffer, which cannot see that half of a file is ciphertext; this can.
pub fn analyze_regions(
    sample: &[u8],
    regions: &[std::ops::Range<usize>],
    cfg: &EntropyConfig,
) -> Sample {
    let mut s = analyze(sample, cfg);
    if regions.len() < 2 {
        return s;
    }
    let per: Vec<ContentClass> = regions
        .iter()
        .filter_map(|r| sample.get(r.start..r.end))
        .map(|chunk| classify_region(chunk, cfg))
        .collect();
    s.regions = per.clone();
    if let Some(combined) = combine_regions(&per) {
        s.class = combined;
    }
    s
}

/// Read and analyze in one step, with region awareness.
pub fn inspect_file(path: &Path, cfg: &EntropyConfig) -> std::io::Result<(Sample, u64)> {
    let (bytes, len, regions) = read_sample_regions(path, cfg)?;
    let s = analyze_regions(&bytes, &regions, cfg);
    Ok((s, len))
}

fn read_up_to(f: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Recognise container/format headers. Returns a short format name.
///
/// Deliberately generous: recognising a format is how we *avoid* flagging normal
/// compression and media files, so a false positive here costs little and a
/// missed format costs a false alarm.
pub fn detect_magic(b: &[u8]) -> Option<&'static str> {
    if b.is_empty() {
        return None;
    }
    let starts = |sig: &[u8]| b.len() >= sig.len() && &b[..sig.len()] == sig;
    let starts_ci = |sig: &[u8]| {
        b.len() >= sig.len() && b[..sig.len()].eq_ignore_ascii_case(sig)
    };

    // Compression / archives.
    if starts(&[0x1f, 0x8b]) {
        return Some("gzip");
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        return Some("zip");
    }
    if starts(b"BZh") {
        return Some("bzip2");
    }
    if starts(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some("xz");
    }
    if starts(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some("zstd");
    }
    if starts(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        return Some("7z");
    }
    if starts(b"Rar!\x1a\x07") {
        return Some("rar");
    }
    if starts(&[0x04, 0x22, 0x4d, 0x18]) {
        return Some("lz4");
    }
    if starts(b"MSCF") {
        return Some("cab");
    }
    if b.len() > 262 && &b[257..262] == b"ustar" {
        return Some("tar");
    }
    if starts(b"!<arch>") {
        return Some("ar");
    }
    if starts(b"hsqs") {
        return Some("squashfs");
    }
    // Apple disk images: trailer 'koly', but the header is often all zero.
    if b.len() >= 512 && &b[0..4] == b"\0\0\0\0" && b.iter().take(256).all(|&x| x == 0) {
        return Some("dmg-empty-header");
    }

    // Media.
    if starts(&[0xff, 0xd8, 0xff]) {
        return Some("jpeg");
    }
    if starts(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Some("png");
    }
    if starts(b"GIF87a") || starts(b"GIF89a") {
        return Some("gif");
    }
    if starts(b"RIFF") && b.len() >= 12 {
        match &b[8..12] {
            b"WEBP" => return Some("webp"),
            b"WAVE" => return Some("wav"),
            b"AVI " => return Some("avi"),
            _ => {}
        }
    }
    if b.len() >= 12 && &b[4..8] == b"ftyp" {
        return Some("iso-media");
    }
    if starts(b"ID3") || starts(&[0xff, 0xfb]) || starts(&[0xff, 0xf3]) || starts(&[0xff, 0xf2])
    {
        return Some("mpeg-audio");
    }
    if starts(b"fLaC") {
        return Some("flac");
    }
    if starts(b"OggS") {
        return Some("ogg");
    }
    if starts(b"icns") {
        return Some("icns");
    }
    if starts(&[0x00, 0x01, 0x00, 0x00]) || starts(b"OTTO") || starts(b"true") || starts(b"ttcf")
    {
        return Some("font");
    }
    if starts(b"wOFF") || starts(b"wOF2") {
        return Some("webfont");
    }
    // Documents.
    if starts(b"%PDF-") {
        return Some("pdf");
    }
    if starts(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return Some("ole-document");
    }
    if starts(b"{\\rtf") {
        return Some("rtf");
    }
    if starts(b"SQLite format 3\0") {
        return Some("sqlite");
    }
    if starts(&[0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66]) {
        return Some("sqlite");
    }
    // Crypto containers that are legitimate on an endpoint.
    if starts_ci(b"age-encryption.org/") {
        return Some("age");
    }
    if starts(b"-----BEGIN PGP MESSAGE-----")
        || starts(b"-----BEGIN PGP SIGNATURE-----")
        || starts(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || starts(b"-----BEGIN RSA PRIVATE KEY-----")
        || starts(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    {
        return Some("pem");
    }
    if starts(&[0xef, 0xbb, 0xbf]) {
        return Some("bom-text");
    }
    if b.len() >= 2 && (&b[0..2] == b"\xff\xfe" || &b[0..2] == b"\xfe\xff") {
        return Some("utf16-text");
    }
    None
}

/// Extensions that normally hold low-entropy content. A file with one of these
/// extensions that suddenly looks like ciphertext is a strong signal.
pub fn is_document_ext(ext: &str) -> bool {
    const DOC: &[&str] = &[
        "doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "xlt", "xltx", "ppt",
        "pptx", "pptm", "pps", "ppsx", "pdf", "txt", "rtf", "odt", "ods", "odp", "odg", "csv",
        "tsv", "md", "markdown", "pages", "numbers", "key", "wps", "wpd", "hwp", "dwg", "dxf",
        "psd", "ai", "indd", "epub", "mobi", "azw", "azw3", "tex", "log", "json", "xml", "yaml",
        "yml", "toml", "ini", "cfg", "conf", "html", "htm", "htmL", "php", "js", "jsx", "ts",
        "tsx", "py", "rb", "java", "c", "cc", "cpp", "h", "hpp", "go", "rs", "sh", "sql",
        "mdb", "accdb", "eml", "msg", "pst", "ost", "vsd", "vsdx", "one", "xps", "oxps", "sav",
        "dbf", "fmp", "qbb", "qbm", "qbw", "qbx", "qby", "sdf", "vcf", "vcs", "ics", "svg",
        "srt", "vtt", "sub", "ass", "srt", "tex", "bib", "cls", "sty", "rmd", "ipynb", "xlsb",
        "xltm", "ppam", "potx", "doc", "wri", "wps", "ofd", "ceb", "cebx", "caJ", "caj",
    ];
    DOC.iter().any(|d| d.eq_ignore_ascii_case(ext))
}

/// Extensions that legitimately hold high-entropy payloads (compressors, media,
/// installers). Used to keep `ext_churn` quiet when a backup or archive tool
/// renames into these.
pub fn is_archive_ext(ext: &str) -> bool {
    const ARCH: &[&str] = &[
        "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "7z", "rar", "zip", "zipx", "tar",
        "lz4", "lz", "lzma", "cab", "dmg", "iso", "img", "sparsebundle", "pkg", "mpkg", "deb",
        "rpm", "apk", "jar", "war", "ear", "whl", "egg", "nupkg", "vsix", "xpi", "crx", "ipa",
        "aab", "msi", "exe", "bin", "xz", "br", "z",
    ];
    ARCH.iter().any(|a| a.eq_ignore_ascii_case(ext))
}

/// Media/office/binary extensions that are already high entropy by nature.
pub fn is_media_or_binary_ext(ext: &str) -> bool {
    const MEDIA: &[&str] = &[
        "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "avif", "tif", "tiff", "bmp",
        "raw", "cr2", "nef", "arw", "dng", "psd", "mp3", "m4a", "aac", "flac", "wav", "aiff",
        "ogg", "opus", "wma", "mp4", "m4v", "mov", "avi", "mkv", "wmv", "flv", "webm", "mpg",
        "mpeg", "3gp", "ttf", "otf", "woff", "woff2", "eot", "dylib", "so", "dll", "o", "a",
        "class", "pyc", "wasm", "car", "app", "framework", "bundle", "sqlite", "db", "realm",
        "pak", "sav", "dat", "sketch", "fig", "xd", "blend", "fbx", "obj", "stl",
    ];
    MEDIA.iter().any(|m| m.eq_ignore_ascii_case(ext))
}

/// Any extension we consider "normal" for a business document directory. Used
/// when judging whether a *new* extension is unusual.
pub fn is_known_ext(ext: &str) -> bool {
    is_document_ext(ext) || is_archive_ext(ext) || is_media_or_binary_ext(ext)
}

/// A new extension that plausibly belongs to a ransomware family: short, random
/// looking, or one of the well-known markers.
pub fn is_suspicious_new_ext(ext: &str) -> bool {
    const MARKERS: &[&str] = &[
        "locked", "lock", "encrypted", "encrypt", "crypt", "crypto", "crypted", "ransom",
        "ransomed", "wcry", "wncry", "wcry2", "ryk", "ryuk", "maze", "darkside", "conti",
        "lockbit", "blackcat", "alphv", "hive", "revil", "sodinokibi", "phobos", "dharma",
        "stop", "djvu", "zepto", "cerber", "petya", "notpetya", "badrabbit", "avoslocker",
        "babuk", "akira", "play", "royal", "blackbasta", "clop", "cl0p", "esxiargs", "vault",
        "karma", "medusa", "qilin", "rhysida", "8base", "noescape", "mallox", "targetcompany",
        "elbie", "lol", "duck", "kann", "basta", "support", "enc", "crypt1", "cryp1", "crinf",
        "r5a", "xrtn", "xtbl", "breaking_bad", "heisenberg", "pays", "pay", "restore",
        "unlock", "recover",
    ];
    if MARKERS.iter().any(|m| ext.eq_ignore_ascii_case(m)) {
        return true;
    }
    // Short random-looking tokens: 3..=12 chars, no vowels-only words, mixed case
    // or digits. `tar.gz` style dots never reach here (extension() takes the last).
    let alnum = ext.len() >= 3
        && ext.len() <= 12
        && ext.chars().all(|c| c.is_ascii_alphanumeric());
    if !alnum {
        return false;
    }
    // Heuristic: looks like a random token (contains a digit and has no common
    // English suffix) or is all-lowercase gibberish of length 5-8.
    let has_digit = ext.chars().any(|c| c.is_ascii_digit());
    let letters: Vec<char> = ext.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let alternating = letters.len() >= 4
        && letters
            .windows(2)
            .filter(|w| (w[0].is_ascii_uppercase()) != (w[1].is_ascii_uppercase()))
            .count()
            >= 3;
    has_digit || alternating
}

/// A file whose name ends in `<document stem>.<document ext>.<unknown ext>` —
/// `report.docx.locked` — is the single most reliable ransomware naming pattern,
/// and it is what separates "encrypted by ransomware" from "compressed by
/// backup". Returns the (inner document extension, outer extension).
pub fn stacked_document_ext(name: &str) -> Option<(String, String)> {
    let path = std::path::Path::new(name);
    let outer = path.extension()?.to_string_lossy().to_lowercase();
    let inner_path = path.with_extension("");
    let inner = inner_path.extension()?.to_string_lossy().to_lowercase();
    if outer.is_empty() || inner.is_empty() {
        return None;
    }
    // `tar.gz` is a legitimate stacked archive, not a ransom marker.
    if is_archive_ext(&outer) && is_archive_ext(&inner) {
        return None;
    }
    // Editor/tool backup suffixes are stacked by design and carry no ransom
    // meaning. `.bak`/`.old`/`.orig` are what a cautious user or an installer
    // produces, not what ransomware does.
    const BENIGN_STACK: &[&str] = &[
        "bak", "backup", "old", "orig", "original", "save", "sav", "copy", "tmp",
        "temp", "swp", "swo", "lck", "lockfile", "part", "partial", "crdownload",
        "download", "disabled", "dist", "sample", "template", "tpl", "in", "td",
        "bak2", "rej", "patch", "diff", "prev", "versioned", "v1", "v2",
    ];
    if BENIGN_STACK.iter().any(|b| b.eq_ignore_ascii_case(&outer)) {
        return None;
    }
    if is_document_ext(&inner) && !is_known_ext(&outer) {
        return Some((inner, outer));
    }
    None
}

/// Ransom-note filename patterns. Returns a strength 0..=2.
pub fn note_name_strength(name: &str) -> u8 {
    let n = name.to_lowercase();
    let strong = [
        "readme_restore",
        "read_me_restore",
        "how_to_recover",
        "how_to_decrypt",
        "how_to_restore",
        "restore_files",
        "recover_files",
        "decrypt_files",
        "decrypt_instructions",
        "decryption_instructions",
        "your_files_are_encrypted",
        "files_encrypted",
        "readme_locked",
        "readme_encrypted",
        "unlock_files",
        "unlock_your_files",
        "recover_your_files",
        "help_decrypt",
        "help_restore",
        "!!!readme",
        "!!!read_me",
        "notice_of_encryption",
        "important_readme",
        "critical_readme",
    ];
    if strong.iter().any(|s| n.contains(s)) {
        return 2;
    }
    let keywords = [
        "readme", "read_me", "decrypt", "decryptor", "restore", "recover", "unlock", "ransom",
        "encrypted", "encryption", "private_key", "your_files", "payment", "bitcoin",
    ];
    let hits = keywords.iter().filter(|k| n.contains(*k)).count();
    if hits >= 2 {
        return 2;
    }
    // A terse "!README.TXT" is a hint on its own, but not proof: real notes name
    // the encryption or the recovery, and a plain project readme must stay quiet.
    if hits == 1 && n.starts_with('!') {
        return 2;
    }
    if hits == 1 {
        return 1;
    }
    0
}

/// Score how much ransom-note language a byte sample contains (0..).
pub fn note_content_hits(sample: &str) -> usize {
    const TERMS: &[&str] = &[
        "bitcoin",
        "btc",
        "monero",
        "xmr",
        "cryptocurrency",
        "decrypt",
        "decryption",
        "private key",
        "your files",
        "your data",
        "have been encrypted",
        "was encrypted",
        "are encrypted",
        "encrypted by",
        "ransom",
        "payment",
        "wallet",
        "tor browser",
        ".onion",
        "onion address",
        "do not try",
        "do not contact",
        "recover your files",
        "restore your files",
        "unlock your files",
        "download the decryptor",
        "decryption tool",
        "unique id",
        "personal id",
        "deadline",
        "48 hours",
        "72 hours",
        "contact us",
        "email us",
    ];
    let lower = sample.to_lowercase();
    TERMS.iter().filter(|t| lower.contains(*t)).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EntropyConfig;


    fn cfg() -> EntropyConfig {
        EntropyConfig::default()
    }

    fn gzip_like(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        while v.len() < n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.truncate(n);
        v
    }

    #[test]
    fn text_is_text() {
        let s = analyze(b"hello world, this is a plain text document.\n".repeat(80).as_slice(), &cfg());
        assert_eq!(s.class, ContentClass::TextLike);
        assert!(s.h0 < 5.0);
        assert!(!s.is_ciphertext_like());
    }

    #[test]
    fn chinese_text_is_not_opaque() {
        let raw = "财务部门季度报告客户资料合同汇总预算明细工资表".repeat(200);
        let s = analyze(raw.as_bytes(), &cfg());
        assert!(!s.is_ciphertext_like());
        assert!(matches!(s.class, ContentClass::Structured | ContentClass::TextLike));
    }

    #[test]
    fn random_is_opaque() {
        let s = analyze(&gzip_like(8192), &cfg());
        assert!(s.is_ciphertext_like());
        assert!(s.h0 >= 7.85);
    }

    #[test]
    fn compressed_payload_with_magic_is_container() {
        let mut v = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        v.extend_from_slice(&gzip_like(8192));
        let s = analyze(&v, &cfg());
        assert_eq!(s.class, ContentClass::Container("gzip"));
        assert!(!s.is_ciphertext_like());
    }

    #[test]
    fn base64_is_not_opaque() {
        let b64: String = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk="
            .repeat(50);
        let s = analyze(b64.as_bytes(), &cfg());
        assert!(!s.is_ciphertext_like(), "h0={} z={}", s.h0, s.chi2_z);
    }

    #[test]
    fn partial_encryption_is_visible() {
        let cfg = cfg();
        // A file whose middle chunk is ciphertext and whose head/tail are prose.
        let mut buf = Vec::new();
        let text = b"the quarterly report records revenue per department. ".repeat(200);
        buf.extend_from_slice(&text);
        let start = buf.len();
        buf.extend_from_slice(&gzip_like(8192));
        let end = buf.len();
        buf.extend_from_slice(&text);
        let regions = vec![0..start, start..end, end..buf.len()];
        let s = analyze_regions(&buf, &regions, &cfg);
        assert_eq!(s.class, ContentClass::PartialOpaque, "regions={:?}", s.regions);
        assert!(s.class.has_ciphertext());
        assert!(!s.class.is_opaque(), "partial must not claim full opacity");
    }

    #[test]
    fn uniform_regions_are_not_partial() {
        let cfg = cfg();
        let text = b"the quarterly report records revenue per department. ".repeat(200);
        let buf = text.clone();
        let n = buf.len();
        let regions = vec![0..n / 3, n / 3..2 * n / 3, 2 * n / 3..n];
        let s = analyze_regions(&buf, &regions, &cfg);
        assert_eq!(s.class, ContentClass::TextLike);
    }

    #[test]
    fn container_region_never_becomes_partial() {
        let cfg = cfg();
        let mut buf = b"the quarterly report records revenue. ".repeat(100);
        let start = buf.len();
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        gz.extend_from_slice(&gzip_like(4096));
        buf.extend_from_slice(&gz);
        let end = buf.len();
        buf.extend_from_slice(&b"more prose follows here. ".repeat(100));
        let regions = vec![0..start, start..end, end..buf.len()];
        let s = analyze_regions(&buf, &regions, &cfg);
        assert!(
            !s.class.has_ciphertext(),
            "an appended archive must not read as ciphertext: {:?}",
            s.regions
        );
    }

    /// Intermittent encryption (BlackCat/ALPHV style): every other 4 KiB block is
    /// ciphertext, the rest stays plaintext. A whole-file average hides it; this
    /// test guards the chunking that makes it visible.
    #[test]
    fn intermittent_encryption_detected_from_chunks() {
        let cfg = EntropyConfig::default();
        let text = b"the quarterly report records revenue per department. ".repeat(40_000);
        let enc = gzip_like(text.len());
        let mut buf = text.clone();
        for off in (0..buf.len()).step_by(8192) {
            let end = (off + 4096).min(buf.len());
            buf[off..end].copy_from_slice(&enc[off..end]);
        }
        let tmp = std::env::temp_dir().join(format!("rw-intermittent-{}.bin", std::process::id()));
        std::fs::write(&tmp, &buf).unwrap();
        let (sample, _, regions) = read_sample_regions(&tmp, &cfg).unwrap();
        let s = analyze_regions(&sample, &regions, &cfg);
        std::fs::remove_file(&tmp).ok();
        assert_eq!(s.class, ContentClass::PartialOpaque, "regions={:?}", s.regions);
        assert!(s.class.has_ciphertext());
    }

    /// Small files are the common case in a document share, and they were
    /// missed before: a 5 KiB file is read whole, so a single whole-file H0 of
    /// ~7.78 read as `HighEntropy`, not ciphertext. Splitting even small buffers
    /// into two regions fixes it without destabilising plain files.
    #[test]
    fn small_file_intermittent_encryption_detected() {
        let cfg = EntropyConfig::default();
        let text = b"Quarterly report body with prose text. ".repeat(120);
        let enc = gzip_like(text.len());
        let mut buf = text.clone();
        for off in (0..buf.len()).step_by(8192) {
            let end = (off + 4096).min(buf.len());
            buf[off..end].copy_from_slice(&enc[off..end]);
        }
        let tmp = std::env::temp_dir().join(format!("rw-small-if-{}.bin", std::process::id()));
        std::fs::write(&tmp, &buf).unwrap();
        let (sample, _, regions) = read_sample_regions(&tmp, &cfg).unwrap();
        let s = analyze_regions(&sample, &regions, &cfg);
        std::fs::remove_file(&tmp).ok();
        assert!(regions.len() >= 2, "expected >=2 regions, got {:?}", s.regions);
        assert_eq!(s.class, ContentClass::PartialOpaque, "regions={:?}", s.regions);
    }

    #[test]
    fn small_plain_file_is_not_partial() {
        let cfg = EntropyConfig::default();
        let text = b"Quarterly report body with prose text. ".repeat(120);
        let tmp = std::env::temp_dir().join(format!("rw-small-plain-{}.bin", std::process::id()));
        std::fs::write(&tmp, &text).unwrap();
        let (sample, _, regions) = read_sample_regions(&tmp, &cfg).unwrap();
        let s = analyze_regions(&sample, &regions, &cfg);
        std::fs::remove_file(&tmp).ok();
        assert_eq!(s.class, ContentClass::TextLike, "regions={:?}", s.regions);
    }

    #[test]
    fn head_only_encryption_detected_from_chunks() {
        let cfg = EntropyConfig::default();
        let text = b"the quarterly report records revenue per department. ".repeat(40_000);
        let enc = gzip_like(text.len());
        let mut buf = text.clone();
        buf[..65536].copy_from_slice(&enc[..65536]);
        let tmp = std::env::temp_dir().join(format!("rw-headonly-{}.bin", std::process::id()));
        std::fs::write(&tmp, &buf).unwrap();
        let (sample, _, regions) = read_sample_regions(&tmp, &cfg).unwrap();
        let s = analyze_regions(&sample, &regions, &cfg);
        std::fs::remove_file(&tmp).ok();
        assert_eq!(s.class, ContentClass::PartialOpaque, "regions={:?}", s.regions);
    }

    #[test]
    fn magic_variants() {
        assert_eq!(detect_magic(b"PK\x03\x04abc"), Some("zip"));
        assert_eq!(detect_magic(b"%PDF-1.7"), Some("pdf"));
        assert_eq!(detect_magic(b"\xfd7zXZ\x00"), Some("xz"));
        assert_eq!(detect_magic(b"BZh9"), Some("bzip2"));
        assert_eq!(detect_magic(b"\x89PNG\r\n\x1a\n"), Some("png"));
        assert_eq!(detect_magic(b"not a magic header"), None);
    }

    #[test]
    fn note_names() {
        assert_eq!(note_name_strength("HOW_TO_RECOVER_FILES.txt"), 2);
        assert_eq!(note_name_strength("README_RESTORE_FILES.TXT"), 2);
        assert_eq!(note_name_strength("!README!.txt"), 2);
        assert_eq!(note_name_strength("readme.md"), 1);
        assert_eq!(note_name_strength("quarterly-report.docx"), 0);
    }

    #[test]
    fn note_language() {
        let t = "All your files have been encrypted. Send 2 bitcoin to wallet. \
                 Visit the .onion address and use the decryption tool. Do not contact police.";
        assert!(note_content_hits(t) >= 4);
        assert_eq!(note_content_hits("plain quarterly report"), 0);
    }

    #[test]
    fn stacked_extensions() {
        assert_eq!(
            stacked_document_ext("report.docx.locked"),
            Some(("docx".into(), "locked".into()))
        );
        assert_eq!(
            stacked_document_ext("budget.xlsx.a1b2"),
            Some(("xlsx".into(), "a1b2".into()))
        );
        // Legitimate stacked archives stay quiet.
        assert_eq!(stacked_document_ext("archive.tar.gz"), None);
        assert_eq!(stacked_document_ext("backup.tgz"), None);
        assert_eq!(stacked_document_ext("plain.txt"), None);
        assert_eq!(stacked_document_ext("plain.txt.bak"), None);
    }

    #[test]
    fn suspicious_exts() {
        assert!(is_suspicious_new_ext("locked"));
        assert!(is_suspicious_new_ext("WNCRY"));
        assert!(is_suspicious_new_ext("a1b2"));
        assert!(!is_suspicious_new_ext("gz"));
        assert!(!is_suspicious_new_ext("txt"));
        assert!(!is_suspicious_new_ext("tar"));
    }

    #[test]
    fn ext_taxonomy() {
        assert!(is_document_ext("docx"));
        assert!(is_archive_ext("gz"));
        assert!(is_media_or_binary_ext("jpg"));
        assert!(!is_known_ext("locked"));
        assert!(is_known_ext("pdf"));
    }
}
