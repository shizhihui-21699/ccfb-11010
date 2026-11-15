# ransomwatch

Endpoint-side early detection for file-encrypting ransomware. It watches one or
more directories, decides whether the activity inside them looks like an
encryption sweep, and, when it does, freezes the suspect process and writes down
everything needed to investigate afterwards.

It is written for the moment before the damage is done: the goal is to catch the
first dozen files, not the first thousand.

## What it detects

Five signals, weighted and accumulated over a 30-second window:

| Signal | What it catches | Weight |
|---|---|---|
| `opaque_rewrite` | An existing text/structured file whose content is now ciphertext, wholly or partly | 5.0 |
| `stacked_extension` | A document renamed under an unknown extension — `report.docx.locked` | 6.0 |
| `opaque_new_document` | A new headerless high-entropy file wearing a document extension | 3.0 |
| `ransom_note` | A note-shaped filename, or note language (bitcoin, onion, "your files have been encrypted") | 6.0 |
| `bulk_rename` / `bulk_modify` | A burst of renames or modifications (counted **once**, not per file) | 3.0 / 2.0 |
| `decoy_touch` | Any change, rename, removal or untrusted open of a canary file | fires immediately |

An incident needs **score ≥ 8** *and* **≥ 3 distinct files** — except a ransom
note, which lowers that to 1 because the note itself is corroboration, and a
touched decoy, which bypasses scoring entirely and is always critical.

Because burst signals are counted once and single signals stay below the
threshold, no one signal can fire on its own. That is the property that keeps
backups quiet: a `tar -czf` run rewrites several hundred files in a second and
would clear any per-file score, but it produces no ciphertext, no ransom note and
no extension churn.

## Partial and intermittent encryption

A lot of modern ransomware does not encrypt a whole file: it encrypts the first
block, or every other block ("intermittent encryption", used by BlackCat/ALPHV,
LockFile and others) to go faster. A single entropy figure over the whole file
hides this — 50% ciphertext averaged with 50% prose lands at H0 ≈ 7.0, below the
`Opaque` threshold.

So files are analysed in **~4 KiB chunks, up to 16 regions**. Files larger than
the 64 KiB read budget are sampled at evenly spaced offsets; files smaller than
the budget are read whole and then split into regions. Each region is classified
on its own, and if at least one region is clearly ciphertext and at least one is
not, the file is `PartialOpaque` and carries the same weight as fully-encrypted
content.

Splitting small files matters more than it sounds: a 5 KiB file read whole has a
single H0 of ~7.78 when half-encrypted, which lands in `HighEntropy` and was
silently missed. Two regions of the same file read `opaque` + `high-entropy`,
which is unambiguous.

4 KiB is not arbitrary: it is the smallest chunk that stays statistically stable
(2 KiB of ciphertext still reads 7.90, but below that it gets noisy) and it is
small enough to land *inside* a 4 KiB ciphertext block, which is what makes
intermittent encryption visible. A container chunk vetoes the verdict, so a zip
archive appended to a document is never mistaken for encryption.

Verified end to end: a head-only encryption (64 KiB of 2 MB) and a BlackCat-style
every-other-4 KiB encryption both raise an `opaque_rewrite` incident.

## Why entropy alone cannot do this

Measured on this machine, gzip-compressed text and AES ciphertext both sit at
H0 ≈ 7.99 and a chi-square uniformity score near zero. **Compressed data and
encrypted data are byte-for-byte statistically indistinguishable.**

So the classifier does not rely on `H0` alone. A sample is `Opaque` (the class
that carries weight) only when *all* of these hold:

- there is **no recognised container header** (gzip, zip, bz2, xz, zstd, 7z,
  rar, tar, dmg, cab, jpeg, png, heic, mp4, pdf, sqlite, font, age, PGP, …),
- `H0 ≥ 7.85` bits/byte,
- the chi-square uniformity z-score is within 12 (base64 and hex dumps land in
  the thousands, so they are rejected despite high entropy),
- at least 170 of the 256 possible byte values occur.

With the header check alone, a backup's `.gz` files are `Container("gzip")`,
never `Opaque`. Without the chi-square check, base64 and hex would look like
ciphertext.

## Measured thresholds

These came from measurements on macOS 26 (arm64), and the values are in
`src/config.rs` where they can be tuned per site.

| Content | H0 | chi²  z | printable | class |
|---|---|---|---|---|
| English prose (64 KiB) | 4.17 | 48 986 | 1.00 | text |
| Chinese prose (64 KiB) | 5.14 | 23 975 | — | structured (not opaque) |
| base64 (4 KiB) | 5.99 | **544** | 1.00 | text (not opaque) |
| gzip of text (4 KiB) | 7.93 | 5.8 | 0.39 | **container** |
| zip archive | 8.00 | 1 613 | 0.39 | **container** |
| AES/XOR keystream (1 KiB) | 7.78 | 1.4 | 0.38 | **opaque** |
| AES/XOR keystream (4 KiB+) | 7.95–8.00 | ≈0 | 0.38 | **opaque** |

Two consequences shaped the design:

- **1 KiB is the floor for entropy evidence** (`entropy.min_file_bytes`). Below
  that, H0 is too noisy to accuse anything.
- **`pdf`, `jpg`, `mp4`, `dmg`, `zip`, `heic` etc. are high entropy by nature.**
  They are recognised by header, so they never read as `Opaque`; the stacked
  extension rule is what catches `photo.jpg.locked`, because `locked` is not a
  known extension even though `jpg` is.

## The decoys

Decoys are plausible-looking business documents (Chinese and English filenames)
planted in the watched directory at startup. Each carries a random canary token
in its body and a manifest entry recording `(dev, inode, size, sha256)` outside
the watched tree (`~/.ransomwatch/decoys`), so an encryptor sweeping the directory
cannot silently re-baseline them.

They trip on:

- **any byte change** — digest mismatch, no entropy judgement needed;
- **removal** — the file is gone;
- **replacement** — the inode changed, so the original was deleted and something
  else put in its place;
- **an untrusted open** — for read *and* for write.

That last one needs a note. **FSEvents does not report reads** — `cat file` and
`cat file > /dev/null` produce no event at all on macOS (verified). So "somebody
opened the decoy" can only come from polling open file descriptors. The watcher
sweeps every visible process's vnode fds through libproc twice a second (a full
sweep is ~2–40 ms for ~900 processes), and allows a short dedupe window so one
act of tampering yields one incident rather than three.

## Response: why SIGSTOP, not SIGKILL

Order is deliberate and fixed:

1. **Attribute** — find who wrote it. FSEvents says nothing about the writer, so
   attribution asks the kernel which processes hold the file open, and combines
   three layers: live holders, a background sweep's history from the last ~12 s
   (a fast encryptor closes its fd before the alert is raised), and holders of
   *ancestor directories* (a process walking a tree holds the directory far
   longer than any single file).
2. **Capture** — hash and classify the implicated files, snapshot the process
   tree (cmdline, cwd, uid, start time, code signature).
3. **Record** — write `incident.json`, `incident.txt`, `processes.json`,
   `files.json` and copy up to 16 evidence files. This happens *before*
   suspension, so the scene is on disk even if the freeze is refused.
4. **Suspend** — `SIGSTOP` the suspect and, optionally, its descendants.

Suspension rather than kill is the point: the process keeps its memory, its open
handles and its children. An operator can inspect, dump, detach a debugger, or
decide it was a false positive. `ransomwatch resume <path>` releases everything
an incident froze, and accepts an incident directory, the `incident.json` inside
it, or the incidents root itself.

## Not freezing the backup

Trust gates **suspension only — never alerting.** A trusted tool that somehow
touches a decoy still produces a critical record with full evidence; it is simply
not frozen, because freezing a backup agent mid-write is itself destructive.

Trust is evidence-based, and a name is not enough:

- **Curated tool list** (`tar`, `gzip`, `7z`, `ditto`, `rsync`, `zstd`, `backupd`,
  `restic`, `rclone`, …) is trusted **only when the executable lives in a system
  or vendor location** (`/usr/bin`, `/bin`, `/System`, `/Applications`,
  `/opt/homebrew`, `/usr/local`) — or carries a non-ad-hoc vendor signature.
  A copy in `/tmp`, `/var/folders`, `/Users/Shared` or `~/Downloads` is
  untrusted no matter whose name or signature it carries. `cp /usr/bin/gzip /tmp/evil`
  does not inherit trust.
- **Crypto tools** (`gpg`, `openssl`, `age`) are trusted *only when the file they
  produce carries a crypto container extension* (`.gpg`, `.age`, `.asc` …).
  `openssl` rewriting `report.docx` into `report.docx.locked` is not trusted.
- **Interpreters** (`bash`, `zsh`, `python3`, `node`, `osascript`, …) are never
  trusted, even if Apple-signed — otherwise every script would be exempt.
- A short `never_suspend` list (terminals, `launchd`, `WindowServer`) keeps an
  interactive session from freezing itself.

## Build and run

Requires Rust 1.88+ (edition 2021). macOS is the primary target; Linux works for
attribution via `/proc`, and the detector itself is platform-independent.

```bash
cargo build --release

# Watch a directory, suspend suspects, plant decoys.
./target/release/ransomwatch watch --root ~/Documents --response suspend

# Report only, no freezing.
./target/release/ransomwatch watch --root ~/Documents --response alert

# Exit after 30 s; non-zero if anything fired. For CI / tuning.
./target/release/ransomwatch watch --root DIR --duration 30 --fail-on-incident

# Print the full default config, then edit and pass --config.
./target/release/ransomwatch config > ransomwatch.toml
./target/release/ransomwatch watch --config ransomwatch.toml
```

Subcommands: `watch`, `scan` (one-shot content classification), `sim` (the
built-in test encryptor), `resume`, `config`, `decoys`.

## The simulator

`ransomwatch sim DIR` is the encryptor used by the acceptance tests. It is
confined by construction:

- it **refuses to run outside** a temporary/test directory (`/tmp`,
  `/private/var/folders`, paths containing `ransomwatch-test`), and refuses
  `$HOME` outright;
- it only touches files inside the directory you pass;
- it writes in 4 KiB chunks and holds the directory open, mimicking a real
  encryptor's fd behaviour;
- output is a deterministic ChaCha-style keystream XOR — headerless, uniform, and
  statistically indistinguishable from AES output, which is what the detector
  must recognise.

```bash
# Create 40 documents, encrypt them, rename to .locked, write a ransom note.
./target/release/ransomwatch sim /tmp/playground

# Encrypt in place, deleting originals.
./target/release/ransomwatch sim /tmp/playground --overwrite-only --remove-original
```

## Incident record

```
~/.ransomwatch/incidents/<timestamp>-<pid>-<hex>/
  incident.json     structured record
  incident.txt      operator summary
  processes.json    full process tree: cmdline, exe, cwd, uid, signature, held files
  files.json        implicated paths: stat, H0/class at capture, sha256, evidence copy
  evidence/         copies named <sha256>_<name>
~/.ransomwatch/incidents/incidents.jsonl   one JSON line per incident
```

## Known limits, stated plainly

- **A very fast encryptor can escape attribution.** FSEvents says nothing about
  which process wrote a path, so attribution is poll-based: live fds, a 100–300 ms
  background sweep, and ancestor-directory holders. A writer that opens, writes
  and closes a file within a few milliseconds can finish between two sweeps.
  Measured on this machine, files written with ≥100 ms between chunks are
  reliably attributed; a tight loop that rewrites a small file in under 10 ms may
  not be.

  The complete fix is `eslogger` (Endpoint Security), which reports the writing
  pid directly. It exists on macOS but **requires root** to open its client, so
  it is not the default path. If you run this as root on a fleet, that is the
  integration to add.

  Either way the incident still fires and evidence is still captured; what can
  be missing is the pid.
- **Permission-denied processes are invisible.** As a normal user, most system
  processes cannot be inspected; the detector sees only what it is allowed to.
  Run as root for full attribution.
- **FSEvents latency is real.** The macOS backend coalesces events; a burst of
  10 000 tiny files may be reported in a handful of events. Detection still
  works because the engine re-derives state from `stat` and content samples, but
  the first incident may arrive after more files than you would like.
- **Intermittent encryption with a block size smaller than 4 KiB, or at offsets
  that never coincide with a sampled chunk, can be missed.** Sampling covers
  64 KiB of a file at 16 points; an encryptor touching under 1/16 of the file in
  sub-4 KiB stripes might fall between the samples.
- **A network file server is not covered.** FSEvents on a mounted network volume
  is not reliable; usage on a share requires a different backend.
- **`tar`/`ditto` writes into the watched tree are quiet by design.** That is the
  intended trade-off: the tool is tuned to be silent through a real backup run,
  at the cost of not noticing an encryptor that produces well-formed archives.

## Source layout

| Module | Responsibility |
|---|---|
| `entropy.rs` | Content classification: H0, chi-square, header sniffing, note language |
| `events.rs` | `notify` events → four hints |
| `detect.rs` | Baseline, per-path state, sliding-window scoring, inode-based rename pairing |
| `decoy.rs` | Canary planting, tamper detection, open-fd polling |
| `attr.rs` | libproc/`/proc` fd enumeration, background holder tracking |
| `procinfo.rs` | Process metadata, code-signing inspection, trust model |
| `forensics.rs` | Incident record and evidence capture |
| `respond.rs` | Attribution → capture → record → suspend |
| `config.rs`, `util.rs` | Configuration and helpers |

## Tests

```bash
cargo test --lib                 # 47 unit tests: statistics, scoring, trust
cargo test --test e2e -- --test-threads=1   # live OS acceptance tests
```

The e2e tests run the real binary against a real directory and drive it with the
real simulator. The two most important are the false-positive tests: a full
backup workload (tar.gz, per-file gzip/bz2/xz, zip, ditto, rsync, `.bak` copies)
and ordinary editing must both produce **zero** incidents.

## Signals for a skeptical reviewer

Two things are worth checking independently if you are deciding whether to trust
this tool:

1. **`cargo test --lib` measures the statistics against ground truth.** The
   entropy tests assert specific H0 and chi-square outcomes for prose, CJK,
   base64, gzip containers and keystream, so a regression in the classifier
   fails a test rather than silently changing the false-positive rate.

2. **`cargo test --test e2e` drives the real binary against a real directory.** It
   asserts on the JSONL incident log, and it runs the two benign workloads that
   matter: a full backup (tar.gz, gzip, bzip2, xz, zip, ditto, rsync) and ordinary
   editing. Both must produce zero incidents. If you change the weights, run those
   two first.
