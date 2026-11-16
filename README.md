# ransomwatch

Terminal-side early detection for ransomware-like file activity, plus a
guarded workload simulator (`ransom-sim`) used to test it.

It watches one or more directory trees and looks for the five things that
distinguish an encryptor from ordinary file churn:

| what | signal |
|---|---|
| existing plaintext rewritten into high-entropy data | entropy burst of plaintext→ciphertext transitions |
| many files renamed onto one new extension | bulk extension change |
| ransom-note files appear | note-name and note-body matching |
| a decoy file is read, written, renamed or deleted | honeytoken trip |
| a lot of files rewritten / deleted in seconds | mass-modification, delete burst |

On an incident it **suspends (SIGSTOP) the process it can attribute the activity
to**, then writes a forensic bundle (process table, I/O counters, per-file
entropy and first bytes, decoy trips).

The hard part is not detection — it is not firing on backup and compression.
That is where most of the design effort went; see [Why it does not cry
wolf](#why-it-does-not-cry-wolf).

## Build

```sh
cargo build --release          # binaries in target/release/
```

## Use

```sh
# Watch a directory, place decoys, suspend the culprit, write evidence.
./target/release/ransomwatch --path ~/Documents --evidence-dir ~/incidents

# Same, but decide and report without ever suspending anything.
./target/release/ransomwatch --path ~/Documents --dry-run

# Validate configuration and see the effective thresholds.
./target/release/ransomwatch --path ~/Documents check

# Print a fully commented config to start from.
./target/release/ransomwatch --path ~/Documents print-config > ransomwatch.toml
./target/release/ransomwatch --config ransomwatch.toml
```

Subcommands:

```
run           the monitor (default)
decoys        place decoy files and exit
print-config  dump the effective configuration as TOML
check         validate paths and show what the detector will do
```

### Permissions

`ransomwatch` runs as the invoking user. `SIGSTOP` only works on processes the
user owns; to contain other users' processes run it as root. It never suspends
itself, its own ancestors, `pid 1`, or anything on the allow list.

### Exit and shutdown

`SIGINT` / `SIGTERM` stop the monitor cleanly. Suspended processes stay
suspended — that is the point of suspending them. Resume one by hand with
`kill -CONT <pid>` once you have finished collecting evidence.

## How detection works

### Entropy, but only where it is meaningful

For each changed file a sample is read (head + middle + tail, 16 KiB each) and
its Shannon entropy is computed. A rewrite from below the plaintext threshold
to above the high-entropy threshold is a `plaintext→ciphertext` transition. For
example, ordinary text sits near 4.1 bits/byte; ChaCha20/AES ciphertext sits at
7.9–8.0. Defaults:

```toml
[detection]
high_entropy = 7.20   # bits/byte
plain_entropy = 6.20
```

Entropy alone is not enough. The decision is **breadth in a time window**: five
or more *distinct* existing files crossing that boundary within ten seconds.
One file saved by an editor, or one file being written repeatedly, never fires.
Window counts are over distinct paths, so a loop over one file cannot inflate
them.

### Compression is excluded structurally, not by threshold

`gzip`, `zip`, `tar.gz`, `bzip2`, `xz`, `zstd`, `7z`, `ditto`, `lz4`, `.dmg`,
Java/Electron archives, and the other formats listed in `format.rs` all produce
8 bits/byte output. Rather than tune entropy thresholds around them — which
would let real ciphertext through — the first bytes are checked for known
container magic. A file that identifies as a compressed container is classified
`CompressedContainer` and **never enters an entropy counter**. Raw ciphertext
written in place has no such header.

This is why the benign suite covers `gzip -k`, `zip -r`, `tar czf`, `bzip2 -k`,
`ditto`, a password-protected `tar | openssl enc`, a browser-style download
(temp suffix then atomic rename), and a photo export of 40 JPEGs — none of them
fire.

### Renames are paired by inode

FSEvents reports the two halves of a rename as unrelated paths in arbitrary
order. The engine defers an unknown inode for 120 ms; by then the source's
removal has arrived and its inode is in a graveyard. The new path then matches
the grave and is reported as `Renamed`, so a bulk extension change is measured
rather than guessed. A rename counts toward a signal only when the extension
actually changed, and fires only when **one extension covers at least 60% of the
renamed set** — scattered `.bak`/`.tmp`/`.orig` renames do not.

### Bulk creation is not bulk rewriting

A `git clone`, `unzip`, or build tree creates hundreds of files. The burst
signals about rewriting only consider files that had a prior record, so
creation-heavy work is invisible to them. There are separate, lower-confidence
signals for "many existing files changed" and "many new header-less high-entropy
files", and an incident needs a **primary** signal (entropy burst, extension
change, ransom note, decoy write, …) plus a score, not just volume.

### Ransom notes

Note names are matched against a list of family patterns
(`HOW_TO_DECRYPT.txt`, `readme_for_decrypt`, `RECOVER-FILES`, …), but a bare
`README.md` is deliberately *not* a note. Body language is matched only for
small text files and needs two distinct phrases (or one plus payment
vocabulary), so an ordinary project README with the word "encrypt" does not
match.

A note alone is a strong signal; a note plus one corroborating signal opens an
incident immediately.

## Decoys

`ransomwatch` places a handful of files with plausible business names
(`annual_financial_report.csv`, `payroll_details_Q3.txt`, …) under
`<watched-root>/__rw_decoys/`. Their content is recognisable plaintext and
their atime is backdated, so three independent tripwires work:

1. **FSEvents** reports writes, renames and deletes on the decoy paths.
2. **atime** catches *reads*, which FSEvents does not report. APFS only
   refreshes atime when `atime < mtime`, which is exactly the state a decoy is
   placed in.
3. **Digest** catches a rewrite that preserved size and mtime.

Two details make reads usable without drowning in noise:

* The decoy directory gets `com.apple.metadata:com_apple_backup_excludeItem` so
  Spotlight and Time Machine leave it alone.
* A read trip is classified by who did it. If every process with read activity
  is a known backup or indexing tool (rsync, backuppd, mds, Spotlight, …) the
  trip is dropped. A decoy *read* also never suspends on its own: it is an
  intrusion signal that corroborates an encryption burst, not proof of one.
  A decoy **write**, rename or delete is decisive and fires immediately.

## Attribution and containment

There is no portable "who wrote this file" API. The response combines:

* **Open-for-write descriptors.** A live process holding an incident path (or
  any file in the watched tree) open `O_WRONLY` is the writer.
* **Write rate.** A sampler polls per-process I/O counters every 0.7 s with one
  `proc_pid_rusage` per pid (a few ms per sweep). At incident time it also takes
  a synchronous 250 ms probe, because an incident can open 100 ms after the
  first rewrites — before any periodic sample has a delta. Logical
  (syscall-level) write bytes are used because they move before buffered disk
  bytes do.
* **Process age.** Ransomware processes are seconds to minutes old; system
  daemons are hours old. A young process with the dominant write volume is a
  much better suspect than a chatty daemon, and it is the tie-breaker when
  volumes are similar.
* **Ancestry**, to surface the shell or script that started the writer.

A suspect is suspended only if it is a direct (not ancestry-only) suspect, is
still alive, and clears a confidence gate. Exited writers are reported —
"nothing was suspended" is logged if the encryptor finished before the response
ran.

Suspended processes remain in memory; nothing is killed, so the process image
and open files are still available to an analyst.

## Forensic bundle

One directory per incident, named `incident-<timestamp>`, containing:

* `incident.json` — signals with scores, ranked suspects with reasons, actions,
  per-file size/entropy/first bytes, decoy trips.
* `summary.txt` — the same for a human or a ticket.
* `manifest.json` — version, capture time, pids, signal kinds, whether anything
  was actually actuated.

The bundle never includes file contents beyond 16 sampled bytes; it records
metadata and sample digests so a file can be triaged after the fact.

## Configuration

All thresholds are tunable; `check` and `print-config` show the effective
values. An example is in [`ransomwatch.example.toml`](ransomwatch.example.toml).

Knobs that matter most in a real deployment:

| key | default | meaning |
|---|---|---|
| `detection.entropy_burst_files` | 5 | distinct plaintext→ciphertext files in the window |
| `detection.rename_burst_files` | 8 | renamed files with one dominant extension |
| `detection.extension_dominance` | 0.60 | fraction one extension must reach |
| `detection.window` | 10s | sliding window; shorter is faster and noisier |
| `response.suspend` | true | set false to report only |
| `response.dry_run` | false | detect and attribute, never actuate |
| `allow_processes` | backup/archiver/tooling list | never blamed |

## Testing

```sh
cargo test                 # unit tests: thresholds, formats, decoys, verdicts
./scripts/e2e.sh           # end-to-end: real binaries, real workloads
./scripts/e2e.sh gzip      # one scenario by name
```

The e2e suite runs 7 malicious scenarios (in-place encryption, encrypt-then-
rename, zero-shredding, extension-only, probe-then-encrypt, decoy writes,
note+encryption) and 15 benign ones (gzip, zip, tar, bzip2, ditto, rsync,
git clone, a build tree, opaque media writes, editor saves, a batch job,
browser downloads, photo export, an encrypted archive, file deletion). It
currently passes 22/22 with no false positives and no misses on this machine.

## `ransom-sim`

A test-only workload generator. It refuses to run on anything that does not
look like a scratch directory (name must contain `test`, `tmp`, `sandbox`,
`scratch`, `demo`, `fixture` or `canary`), refuses the filesystem root, the
home directory and its direct children, and never follows a symlink out of the
target tree. There is no flag that lifts the target-directory boundary.

```sh
ransom-sim --dir /tmp/my-test-dir populate --files 200
ransom-sim --dir /tmp/my-test-dir inplace --files 150 --delay-ms 40
ransom-sim --dir /tmp/my-test-dir encrypt-rename --files 150 --ext locked
ransom-sim --dir /tmp/my-test-dir ext-only --files 100 --ext wncry
ransom-sim --dir /tmp/my-test-dir decoy-probe
```

It is not ransomware: there is no key to sell, it only encrypts the document
extensions listed in its source, and it operates only inside `--dir`.

## Limits

* **Encryption in place is not preventable, only detectable.** By the time five
  files have crossed the entropy boundary, those files are gone. Suspension
  limits the damage from that point on; it does not undo it. Keep backups.
* **Attribution is heuristic.** A writer that closes every descriptor between
  files and finishes before the response runs leaves little trace beyond I/O
  counters and process age. It will be named in the bundle if sampled, but it
  cannot be suspended.
* **Coarse read attribution.** Read counters are per process, not per file, so
  a decoy read is attributed to "the processes reading something right now".
  The allow list is what keeps this quiet; extend it for your environment.
* **FSEvents can coalesce or drop events.** The engine re-walks the tree every
  five minutes (`scan.reconcile_interval`) to catch what the kernel dropped,
  and a `Rescan` flag triggers an immediate re-walk.
* **Hidden files are ignored.** `.`-prefixed files are mostly editor and OS
  bookkeeping. An encryptor that only touches dotfiles would be missed by the
  content signals; the decoy and note signals are unaffected.
* **Linux uses the same design** via inotify and `/proc`, but the shipped and
  tested target here is macOS. atime-based decoy reads depend on the Linux
  mount's `relatime`/`strictatime` setting.
