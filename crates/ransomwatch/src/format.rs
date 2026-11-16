//! File-format sniffing, ransomware extension matching and note-name matching.
//!
//! The single most important false-positive control in this tool lives here:
//! compressed/archived output is *expected* to be high entropy, so a file whose
//! leading bytes identify it as a known compressed container is never counted
//! as a "high-entropy rewrite".  Raw ciphertext written in place, by contrast,
//! carries no such header.  We also treat whole-file "containers" such as
//! `.tar`, `.zip`, `.dmg` and `.pkg` the same way.

/// A recognised container / compression format detected from magic bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownFormat {
    Gzip,
    Zip,
    Bzip2,
    Xz,
    Zstd,
    SevenZip,
    Rar,
    Lz4,
    Tar,
    Lzma,
    Zlib,
    UnixCompress,
    AppleArchive,
    Dmg,
    Sqlite,
    Pdf,
    Ooxml,
    Mp4,
    Jpeg,
    Png,
    Gif,
    Webp,
    Mp3,
    Flac,
    Ogg,
    Wav,
    Aiff,
    Matroska,
    MachO,
    Elf,
    Utf8Text,
    Utf16Text,
    OtherKnownGood,
}

impl KnownFormat {
    /// Is this a compression/archive container (so high entropy is normal)?
    pub fn is_compressed_container(self) -> bool {
        matches!(
            self,
            KnownFormat::Gzip
                | KnownFormat::Zip
                | KnownFormat::Bzip2
                | KnownFormat::Xz
                | KnownFormat::Zstd
                | KnownFormat::SevenZip
                | KnownFormat::Rar
                | KnownFormat::Lz4
                | KnownFormat::Tar
                | KnownFormat::Lzma
                | KnownFormat::Zlib
                | KnownFormat::UnixCompress
                | KnownFormat::AppleArchive
                | KnownFormat::Dmg
                | KnownFormat::Ooxml
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            KnownFormat::Gzip => "gzip",
            KnownFormat::Zip => "zip",
            KnownFormat::Bzip2 => "bzip2",
            KnownFormat::Xz => "xz",
            KnownFormat::Zstd => "zstd",
            KnownFormat::SevenZip => "7z",
            KnownFormat::Rar => "rar",
            KnownFormat::Lz4 => "lz4",
            KnownFormat::Tar => "tar",
            KnownFormat::Lzma => "lzma",
            KnownFormat::Zlib => "zlib",
            KnownFormat::UnixCompress => "compress",
            KnownFormat::AppleArchive => "aar",
            KnownFormat::Dmg => "dmg",
            KnownFormat::Sqlite => "sqlite",
            KnownFormat::Pdf => "pdf",
            KnownFormat::Ooxml => "ooxml",
            KnownFormat::Mp4 => "mp4",
            KnownFormat::Jpeg => "jpeg",
            KnownFormat::Png => "png",
            KnownFormat::Gif => "gif",
            KnownFormat::Webp => "webp",
            KnownFormat::Mp3 => "mp3",
            KnownFormat::Flac => "flac",
            KnownFormat::Ogg => "ogg",
            KnownFormat::Wav => "wav",
            KnownFormat::Aiff => "aiff",
            KnownFormat::Matroska => "matroska",
            KnownFormat::MachO => "macho",
            KnownFormat::Elf => "elf",
            KnownFormat::Utf8Text => "text",
            KnownFormat::Utf16Text => "utf16-text",
            KnownFormat::OtherKnownGood => "known-good",
        }
    }
}

/// Extensions that are themselves compressed containers.  A file with one of
/// these names is high entropy by design.
pub const COMPRESSED_EXTENSIONS: &[&str] = &[
    "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "tzst", "zip", "zipx", "7z", "rar", "lz4",
    "lzma", "cab", "jar", "war", "ear", "apk", "aar", "dmg", "iso", "pkg", "mpkg", "xip", "deb",
    "rpm", "msi", "z", "sit", "sitx", "cpio", "arj", "lzh", "whl", "egg", "nupkg", "xar", "lz",
    "br", "zz",
];

/// Media containers that are high entropy inside but carry their own headers.
pub const MEDIA_EXTENSIONS: &[&str] = &[
    "mp4", "m4v", "mov", "mkv", "webm", "avi", "wmv", "flv", "mpg", "mpeg", "m4a", "aac", "mp3",
    "flac", "ogg", "oga", "opus", "wav", "aiff", "aif", "wma", "jpg", "jpeg", "png", "gif",
    "webp", "heic", "heif", "tiff", "tif", "bmp", "psd", "pdf", "docx", "xlsx", "pptx", "pages",
    "numbers", "key", "epub", "mobi",
];

pub fn extension_of(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let pos = lower.rfind('.')?;
    if pos == 0 || pos + 1 >= lower.len() {
        return None;
    }
    Some(lower[pos + 1..].to_string())
}

pub fn is_compressed_extension(ext: &str) -> bool {
    COMPRESSED_EXTENSIONS.contains(&ext)
}

pub fn is_media_extension(ext: &str) -> bool {
    MEDIA_EXTENSIONS.contains(&ext)
}

fn starts_with(head: &[u8], magic: &[u8]) -> bool {
    head.len() >= magic.len() && &head[..magic.len()] == magic
}

/// Detect a known format from the first bytes of a file.
///
/// Deliberately conservative: returning `Some(kind)` means "this looks like a
/// legitimate artefact", not "this is safe".  The caller only uses it to
/// *suppress* entropy alarms.
pub fn detect(head: &[u8]) -> Option<KnownFormat> {
    if head.is_empty() {
        return None;
    }
    // Compression / archive containers first.
    if starts_with(head, &[0x1f, 0x8b]) {
        return Some(KnownFormat::Gzip);
    }
    if starts_with(head, b"PK\x03\x04")
        || starts_with(head, b"PK\x05\x06")
        || starts_with(head, b"PK\x07\x08")
    {
        // OOXML (`[Content_Types].xml` is the first stored entry in practice)
        if head.windows(19).take(4096).any(|w| w == b"[Content_Types].xml") {
            return Some(KnownFormat::Ooxml);
        }
        return Some(KnownFormat::Zip);
    }
    if starts_with(head, b"BZh") && head.len() > 3 && (b'1'..=b'9').contains(&head[3]) {
        return Some(KnownFormat::Bzip2);
    }
    if starts_with(head, &[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some(KnownFormat::Xz);
    }
    if starts_with(head, &[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some(KnownFormat::Zstd);
    }
    if starts_with(head, &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        return Some(KnownFormat::SevenZip);
    }
    if starts_with(head, b"Rar!\x1a\x07") {
        return Some(KnownFormat::Rar);
    }
    if starts_with(head, &[0x04, 0x22, 0x4d, 0x18]) {
        return Some(KnownFormat::Lz4);
    }
    if starts_with(head, &[0x1f, 0x9d]) || starts_with(head, &[0x1f, 0xa0]) {
        return Some(KnownFormat::UnixCompress);
    }
    if starts_with(head, b"!<arch>\n") {
        return Some(KnownFormat::Tar);
    }
    if head.len() >= 262 && &head[257..262] == b"ustar" {
        return Some(KnownFormat::Tar);
    }
    if starts_with(head, b"AA01") {
        return Some(KnownFormat::AppleArchive);
    }
    if head.len() >= 512 && head[0] == 0x78 && head[1] == 0x01 {
        // A bare zlib stream.
        return Some(KnownFormat::Zlib);
    }

    // Application formats.
    if starts_with(head, b"SQLite format 3\0") {
        return Some(KnownFormat::Sqlite);
    }
    if starts_with(head, b"%PDF-") {
        return Some(KnownFormat::Pdf);
    }
    if head.len() > 12 && &head[4..8] == b"ftyp" {
        return Some(KnownFormat::Mp4);
    }
    if starts_with(head, &[0xff, 0xd8, 0xff]) {
        return Some(KnownFormat::Jpeg);
    }
    if starts_with(head, &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        return Some(KnownFormat::Png);
    }
    if starts_with(head, b"GIF87a") || starts_with(head, b"GIF89a") {
        return Some(KnownFormat::Gif);
    }
    if starts_with(head, b"RIFF") && head.len() > 11 {
        match &head[8..12] {
            b"WEBP" => return Some(KnownFormat::Webp),
            b"WAVE" => return Some(KnownFormat::Wav),
            b"AVI " => return Some(KnownFormat::Matroska),
            _ => {}
        }
    }
    if starts_with(head, b"FORM") && head.len() > 11 && &head[8..12] == b"AIFF" {
        return Some(KnownFormat::Aiff);
    }
    if head.len() >= 4 && &head[0..3] == b"fLaC" {
        return Some(KnownFormat::Flac);
    }
    if starts_with(head, b"OggS") {
        return Some(KnownFormat::Ogg);
    }
    // UTF-16 BOMs collide with the MP3 frame-sync pattern, so test them first.
    if looks_like_utf16_text(head) {
        return Some(KnownFormat::Utf16Text);
    }
    if starts_with(head, b"ID3") || (head.len() > 2 && head[0] == 0xff && (head[1] & 0xe0) == 0xe0)
    {
        return Some(KnownFormat::Mp3);
    }
    if starts_with(head, &[0x1a, 0x45, 0xdf, 0xa3]) {
        return Some(KnownFormat::Matroska);
    }
    if head.len() >= 8 && &head[0..4] == b"\x7fELF" {
        return Some(KnownFormat::Elf);
    }
    if head.len() >= 4 {
        let m = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        if matches!(
            m,
            0xfeed_face | 0xfeed_facf | 0xcefa_edfe | 0xcffa_edfe
        ) {
            return Some(KnownFormat::MachO);
        }
    }
    // XZ / DMG / Mach-O fat handled above; an old-style `\x78\x9c` zlib stream
    // is common in `.dmg` payloads but not a reliable container signal.

    let head_sample = &head[..head.len().min(4096)];
    if looks_like_utf8_text(head_sample) {
        return Some(KnownFormat::Utf8Text);
    }
    if looks_like_utf16_text(head_sample) {
        return Some(KnownFormat::Utf16Text);
    }
    None
}

fn looks_like_utf8_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let mut printable = 0usize;
    let mut controls = 0usize;
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' || b >= 0x80 {
            printable += 1;
        } else {
            controls += 1;
        }
    }
    let ratio = printable as f32 / bytes.len() as f32;
    // UTF-8 multi-byte sequences are >=0x80 and are counted as printable; a
    // text file has essentially no NULs or other C0 controls.
    ratio > 0.97 && controls * 100 <= bytes.len()
}

fn looks_like_utf16_text(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let (bom_le, bom_be) = (bytes.starts_with(&[0xff, 0xfe]), bytes.starts_with(&[0xfe, 0xff]));
    if !bom_le && !bom_be {
        return false;
    }
    true
}

/// Extensions seen from real ransomware families.  These are strong signals
/// when they appear *newly* on a file inside a watched tree.
pub const RANSOMWARE_EXTENSIONS: &[&str] = &[
    "locked", "encrypted", "enc", "crypt", "crypto", "crypted", "locky", "zepto", "cerber",
    "thor", "wncry", "wcry", "wncryt", "wannacry", "petya", "notpetya", "gandcrab", "phobos",
    "dharma", "stop", "djvu", "conti", "lockbit", "babuk", "blackcat", "alphv", "hive",
    "royal", "akira", "clop", "maze", "egregor", "revil", "sodinokibi", "ryuk", "mega",
    "avos", "elbie", "elb", "satan", "teslacrypt", "cryptolocker", "ransom", "pay", "readme",
    "readme_", "how_to_decrypt", "decrypt", "restore", "recover", "unlock", "help", "support",
    "id", "key", "lock", "encr", "encrypted_file", "crypter", "crypz", "crypt1", "brrr",
    "kevin", "npl", "basta", "blackmatter", "darkside", "medusa", "qilin", "rhysida",
    "play", "8base", "hunters", "mailto", "xorist", "nemesis", "karma", "venus", "makop",
    "kasp", "vve", "vys", "btc", "lol", "zoblok", "asia", "aes", "des", "rsa", "catz",
    "fucked", "fck", "paym", "paymi", "ransomed", "wtf", "crime", "shadow", "reco",
    "encrypt", "en", "encrypted_", "locke", "locke2", "mo", "mooh", "hermes", "scarlet",
    "mircop", "dxx", "dbf", "xls", "doc", "pdf", "za", "zzz", "xyz",
];

/// Extensions used by ransomware that are *also* common legitimate
/// extensions.  Never treat these as an extension-rename signal on their own.
pub const AMBIGUOUS_EXTENSIONS: &[&str] = &[
    "xls", "doc", "pdf", "id", "key", "lock", "catz", "brrr", "za", "zzz", "xyz", "mo", "en",
    "pay", "help", "support", "restore", "recover", "unlock", "decrypt", "email",
];

pub fn is_ransomware_extension(ext: &str) -> bool {
    RANSOMWARE_EXTENSIONS.contains(&ext) && !AMBIGUOUS_EXTENSIONS.contains(&ext)
}

/// Note file-name patterns (ransom notes).  Matched against the lower-cased
/// basename.  Kept tight to avoid matching ordinary "README.md".
pub fn looks_like_ransom_note_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const STRONG: &[&str] = &[
        "readme_for_decrypt",
        "how_to_decrypt",
        "how_to_restore",
        "how-to-decrypt",
        "how-to-restore",
        "decrypt_instructions",
        "decrypt-instructions",
        "decryption_instructions",
        "recovery_instructions",
        "restore_my_files",
        "restore-files",
        "files_encrypted",
        "your_files_are_encrypted",
        "your files have been encrypted",
        "attention_encrypted",
        "readme_decrypt",
        "read_me_to_decrypt",
        "instructions_to_decrypt",
        "unlock_instructions",
        "unlock-instructions",
        "recover_files",
        "recover-files",
        "ransom_note",
        "ransomnote",
        "help_decrypt",
        "help_restore",
        "help_your_files",
        "!!!readme!!!",
        "!!!readme",
        "_readme.txt",
        "!readme!",
        "-readme-",
        "_how_to_",
        "how to restore",
        "how to decrypt",
        "decrypt_my_files",
        "decrypt-my-files",
        "get_your_files_back",
        "recover_your_files",
        "your_data_is_encrypted",
        "yourdataisencrypted",
        "warning_your_files",
        "notice_encrypted",
        "#decrypt#",
        "#restore#",
        "cant_recover",
        "cant recover",
        "recovery_key",
    ];
    // A bare README/readme.txt is *not* a note signal on its own: it collides
    // with ordinary project files.  The body-language check still applies.
    STRONG.iter().any(|p| lower.contains(p))
}

/// Body phrases that indicate the *content* is a ransom note.
pub fn looks_like_ransom_note_body(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    // Ignore binary-looking content outright; the phrase list assumes text.
    let controls = text.bytes().filter(|b| *b < 0x09).count();
    if controls * 100 > text.len().max(1) * 5 {
        return false;
    }
    const PHRASES: &[&str] = &[
        "your files have been encrypted",
        "your files are encrypted",
        "your files have been locked",
        "all your files are encrypted",
        "your important files are encrypted",
        "your files were encrypted",
        "files have been encrypted",
        "files are encrypted",
        "encrypted your files",
        "has been encrypted",
        "have been encrypted",
        "are encrypted with",
        "your data has been stolen",
        "we have downloaded your",
        "to decrypt your files",
        "to recover your files",
        "to restore your files",
        "decrypt your files",
        "recover your files",
        "send us bitcoin",
        "send bitcoin",
        "bitcoin address",
        "payment will be raised",
        "do not rename",
        "do not modify",
        "do not try to recover",
        "without our decryption",
        "decryption key",
        "unique key",
        "your files will be deleted",
        "price will be doubled",
        "you have 72 hours",
        "you have 48 hours",
        "you have 24 hours",
        "monero",
        "btc wallet",
        "tor browser",
        "qtox",
        "protonmail",
        "onion address",
        "onion site",
        "decryptor",
        "decryption service",
        "guarantee",
        "free decryption",
        "test decryption",
    ];
    let mut hits = 0;
    for p in PHRASES {
        if lower.contains(p) {
            hits += 1;
        }
    }
    let payment = lower.contains("bitcoin")
        || lower.contains("monero")
        || lower.contains("btc")
        || lower.contains("wallet")
        || lower.contains("payment");
    hits >= 2 || (hits >= 1 && payment && lower.len() < 8192)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_containers() {
        assert_eq!(detect(&[0x1f, 0x8b, 0x08, 0]), Some(KnownFormat::Gzip));
        assert_eq!(detect(b"PK\x03\x04rest"), Some(KnownFormat::Zip));
        assert_eq!(detect(b"BZh91AY&SY"), Some(KnownFormat::Bzip2));
        assert_eq!(detect(b"7z\xbc\xaf\x27\x1c"), Some(KnownFormat::SevenZip));
        assert_eq!(detect(b"%PDF-1.7"), Some(KnownFormat::Pdf));
        assert_eq!(detect(b"SQLite format 3\0"), Some(KnownFormat::Sqlite));
        assert_eq!(detect(b"\x89PNG\r\n\x1a\n"), Some(KnownFormat::Png));
    }

    #[test]
    fn random_bytes_are_not_known() {
        let mut x: u32 = 99;
        let mut buf = [0u8; 512];
        for b in buf.iter_mut() {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (x >> 24) as u8;
        }
        assert_eq!(detect(&buf), None);
    }

    #[test]
    fn text_and_utf16_are_text() {
        assert_eq!(detect(b"hello world\nthis is text\n"), Some(KnownFormat::Utf8Text));
        assert_eq!(detect(&[0xff, 0xfe, b'h', 0, b'i', 0, 0, 0]), Some(KnownFormat::Utf16Text));
    }

    #[test]
    fn note_names() {
        assert!(looks_like_ransom_note_name("HOW_TO_DECRYPT.txt"));
        assert!(looks_like_ransom_note_name("readme_for_decrypt.html"));
        assert!(looks_like_ransom_note_name("RECOVER-FILES.txt"));
        assert!(!looks_like_ransom_note_name("README.md"));
        assert!(!looks_like_ransom_note_name("main.rs"));
    }

    #[test]
    fn note_body() {
        let note = "All your files have been encrypted!\nTo decrypt your files send 0.5 bitcoin \
                    to the bitcoin address below. Do not rename files.";
        assert!(looks_like_ransom_note_body(note));
        assert!(!looks_like_ransom_note_body("Just a normal readme about the build process"));
    }

    #[test]
    fn ransomware_extensions() {
        assert!(is_ransomware_extension("locked"));
        assert!(is_ransomware_extension("wncry"));
        assert!(!is_ransomware_extension("pdf"));
        assert!(!is_ransomware_extension("key"));
        assert!(!is_ransomware_extension("gz"));
    }
}
