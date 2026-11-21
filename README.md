# ArchiveWolf

Analyser and hashcat hash converter for encrypted ZIP, RAR and 7-Zip archives.

[![CI](https://github.com/StrongWind1/ArchiveWolf/actions/workflows/ci.yml/badge.svg)](https://github.com/StrongWind1/ArchiveWolf/actions/workflows/ci.yml)
[![Licence: Apache-2.0 AND UnRAR AND Zlib AND Info-ZIP](https://img.shields.io/badge/licence-Apache--2.0%20AND%20UnRAR%20AND%20Zlib%20AND%20Info--ZIP-blue.svg)](#licence)

ArchiveWolf answers three questions about an encrypted archive, with one command for each:

| Command | Question | Answer |
| --- | --- | --- |
| [`info`](#info) | What is encrypted, and how? | The scheme and variant of every encrypted entry, with its parameters, and findings such as pseudo-encryption or a scheme that is weak |
| [`hash`](#hash) | What does hashcat need to test passwords against it? | A hash line for each scheme in the archive, for hashcat modes 46100 to 46900 |
| [`attack rar-13`](#attack-rar-13), [`attack zip-crypto`](#attack-zip-crypto) | Can it be opened without the password? | For the two schemes that fall without it: the key of a RAR 1.3 archive, and the three keys of a ZIP archive under traditional encryption |

The tool takes no password and tests none, starts no other program and unpacks nothing. It reads archives that may be built to break it, and is written for that.

> **The hash lines need a hashcat fork.** They are read only by hashcat modes 46100 to 46900, which live in [StrongWind1/hashcat](https://github.com/StrongWind1/hashcat) on the branches `feat/zip-modes`, `feat/rar-modes` and `feat/7z-modes`. Upstream hashcat does not read the lines, and neither does John the Ripper.

## Contents

- [Supported formats and schemes](#supported-formats-and-schemes)
- [Getting started](#getting-started)
- [Usage](#usage)
  - [info](#info)
  - [hash](#hash)
  - [attack rar-13](#attack-rar-13)
  - [attack zip-crypto](#attack-zip-crypto)
  - [Exit status](#exit-status)
- [What it does not do](#what-it-does-not-do)
- [Handling untrusted archives](#handling-untrusted-archives)
- [Releases](#releases)
- [Development](#development)
- [Security](#security)
- [Related tools](#related-tools)
- [Disclaimer](#disclaimer)
- [Licence](#licence)

## Supported formats and schemes

| Format | Scheme | What it is | Hash line | hashcat mode |
| --- | --- | --- | --- | --- |
| ZIP | `zip-crypto` | ZIP traditional encryption (ZipCrypto) | `$zip$1$` | 46100 |
| ZIP | `zip-winzip` | WinZip AES, AE-1 and AE-2, with 128, 192 and 256 bits | `$zip$2$` | 46200 |
| ZIP | `zip-pkware` | PKWARE strong encryption with a password and AES-128, 192 or 256 | `$zip$3$` | 46300, 46310, 46320, by key size |
| RAR | `rar-13` | RAR 1.3 and 1.4 | none | none: [`attack rar-13`](#attack-rar-13) |
| RAR | `rar-15` | RAR 1.5 | `$rar$15$` | 46500 |
| RAR | `rar-20` | RAR 2.0 | `$rar$20$` | 46600 |
| RAR | `rar-30` | RAR 3.x to 4.x, encrypted entries and encrypted headers | `$rar$30$` | 46700 |
| RAR | `rar-50` | RAR 5 and 7, encrypted entries and encrypted headers | `$rar$50$` | 46800 |
| 7-Zip | `7z-aes` | AES-256, encrypted folders and encrypted headers | `$7z$*` | 46900 |

Every scheme has one ID. A variant of it is the ID with its scope (`data` or `headers`) and its qualifiers behind it, as in `rar-50:headers:check`. `info` prints these IDs, and the fixtures and the hashcat modes use the same ones. The table shows the common case of each scheme: `info` names the exact variant of every entry.

Two schemes fall without the password, and `attack` is for them: `rar-13`, by a search of its keys, and `zip-crypto`, from known plaintext or from its encryption headers. The keys of `zip-crypto` also go to hashcat, as `$zip$4$` lines for modes 46400 and 46410, which search the password that gives them.

ZIP encryption to certificates is recognised and named. It gets no line, because no password opens it.

## Getting started

ArchiveWolf is unreleased: there are no tags, no crates.io release and no binaries to download yet. It is built from source.

```sh
git clone https://github.com/StrongWind1/ArchiveWolf
cd ArchiveWolf
cargo build --release
./target/release/archivewolf --version
```

The build needs Rust 1.95.0, which `rust-toolchain.toml` pins and `rustup` installs by itself. No dependency compiles C.

The usual way through the tool is three steps:

```sh
archivewolf info archive.zip                             # what is encrypted, and how
archivewolf hash --mode 46100 archive.zip > 46100.hash   # the hash lines of one hashcat mode
hashcat -m 46100 46100.hash wordlist.txt                 # with a hashcat built from the fork
```

## Usage

```text
archivewolf info   <PATHS>... [--entries] [--json]
archivewolf hash   <PATHS>... [--all] [--mode <MODE>] [--json]
archivewolf attack rar-13     <ARCHIVE> --output <FILE> [--budget <TIME>]
archivewolf attack zip-crypto <ARCHIVE>... [--known <PATH>]... [--output <FILE>] [--budget <TIME>]
```

Every command takes `-v` for more notes on standard error (`hash -v` says which entry each line comes from, and `-vv` which files a walk passes over), `-q` for errors only, and `--help` for all of its options.

How paths are read:

- A path is a file or a directory, and a directory is walked.
- An archive is recognised by its content and not by its name, also when it lies behind the program of a self-extracting archive.
- A ZIP archive is found from its end, so one that starts with something else is found too: the last volume of a split set, or an archive behind a script.
- A later volume of a set is an archive like any other and is reported with what it holds.
- Archives are reported in the order of their paths, each one once.

In the examples below, `archivewolf` stands for `./target/release/archivewolf`, run from the root of the repository on archives under `tests/fixtures`. The output is copied from that binary.

### info

`info` prints one block for each archive: the container, whether its headers are readable or encrypted, how many entries are encrypted, each variant with its parameters, and findings. For every line `hash` would write, it names the tag of the line, its hashcat mode, what the line proves and the entry it comes from. It prints no hash line. For a 7-Zip archive the unit is the folder, which is what 7-Zip encrypts.

```console
$ archivewolf info tests/fixtures/zip-winzip/gen_own_mixed_zc_aes.zip
tests/fixtures/zip-winzip/gen_own_mixed_zc_aes.zip   ZIP, 2 entries
  headers   readable
  entries   2 of 2 entries encrypted; coverage all
  schemes   mixed
            zip-crypto:check8  ZipCrypto, check byte 8 bits, CRC-32 (1 entry, 1 key group)
            zip-winzip:256:ae2  AE-2, AES-256, PBKDF2-HMAC-SHA1 1000, verifier 16 bits, authentication code 80 bits (1 entry, 1 key group)
  findings  more than one scheme in one archive: zip-crypto, zip-winzip
            zc.txt: zip-crypto falls without the password to 12 bytes of known plaintext
  line      $zip$1$, hashcat mode 46100, exact, from zc.txt
            $zip$2$, hashcat mode 46200, exact, from aes.txt
```

When the headers are encrypted, the entries cannot be told without the password, and the block says so:

```console
$ archivewolf info tests/fixtures/rar-50/v730_hp_m5.rar
tests/fixtures/rar-50/v730_hp_m5.rar   RAR 5
  headers   encrypted: names and sizes hidden
  scheme    rar-50:headers:check  AES-256, PBKDF2-HMAC-SHA256 2^15, check value 64 bits
  line      $rar$50$, hashcat mode 46800, exact, from the headers
```

A ZIP entry that is marked encrypted and is not is reported as pseudo-encrypted. The proof is that its data as it stands unpacks to the CRC-32 the archive stores:

```console
$ archivewolf info tests/fixtures/pseudo/pseudo_encrypted_zc.zip
tests/fixtures/pseudo/pseudo_encrypted_zc.zip   ZIP, 1 entry
  headers   readable
  entries   none of 1 entry encrypted, 1 pseudo-encrypted; coverage none
  findings  flag.txt: marked encrypted and not encrypted: the data as it stands unpacks to the stored CRC-32
  line      none: nothing is encrypted
```

An encrypted archive that gets no line says why, with a reason from a [fixed list](#when-no-line-is-written):

```console
$ archivewolf info tests/fixtures/rar-13/rar14-password-stored.rar
tests/fixtures/rar-13/rar14-password-stored.rar   RAR 1.4, 1 entry
  headers   readable
  entries   1 of 1 entry encrypted; coverage all
  scheme    rar-13  RAR 1.3 cipher, checksum 16 bits (1 entry, 1 key group)
  findings  SECRET.TXT: rar-13 falls without the password: `attack rar-13` searches its 2^23 keys
  line      none
  no line   rar-13: no-mode: no hashcat mode exists for rar-13: `attack rar-13` searches its key
```

`--entries` adds a row for each entry below the block:

```console
$ archivewolf info --entries tests/fixtures/zip-crypto/test05.zip
tests/fixtures/zip-crypto/test05.zip   ZIP, 2 entries
  headers   readable
  writer    info-zip
  entries   2 of 2 entries encrypted; coverage all
  scheme    zip-crypto:check8  ZipCrypto, check byte 8 bits, CRC-32 (2 entries, 1 key group)
  findings  test05_plain.txt, flag.txt: zip-crypto falls without the password to 12 bytes of known plaintext
  line      $zip$1$, hashcat mode 46100, exact, from test05_plain.txt
  list      #  kind  state      variant            group  method  packed  size  split  line           known  name
            0  file  encrypted  zip-crypto:check8      1  stored      44    32  no     $zip$1$ 46100  -      test05_plain.txt
            1  file  encrypted  zip-crypto:check8      1  stored      47    35  no     -              -      flag.txt
```

#### The rows of a block

| Row | Says |
| --- | --- |
| `headers` | Whether the headers are `readable` or `encrypted`. With encrypted headers, names and sizes are hidden |
| `writer` | ZIP only: the family of the program that wrote the `zip-crypto` entries, when the archive shows it |
| `entries` | How many entries are encrypted, and the coverage: `all`, `some` or `none` of what the archive lists, or `unknown` behind encrypted headers |
| `scheme`, `schemes` | Each variant with its parameters: cipher, key derivation and its cost, and what a password can be tested against. Entries of one key group share a derived key |
| `findings` | What is unusual or weak about the archive: the table below |
| `line` | Each line `hash` writes by default: its tag, its hashcat mode, what it proves and the entry it comes from |
| `no line` | Each scheme or entry that cannot give a line, with the reason |
| `list` | With `--entries`: a row for each entry |

An entry is in one of four states:

| State | When |
| --- | --- |
| `plain` | The format does not mark the entry as encrypted |
| `encrypted` | The format marks it, and nothing shows otherwise |
| `pseudo-encrypted` | ZIP only. The entry is marked, and its data as it stands unpacks to the CRC-32 the archive stores |
| `undetermined` | The entry is marked, and what is needed to say more could not be read |

#### Findings

Each finding has a fixed code, the entries it concerns and a sentence.

| Code | Meaning |
| --- | --- |
| `pseudo-encryption` | Entries are marked encrypted and are not |
| `mixed-schemes` | More than one scheme in one archive |
| `partial` | Some entries are encrypted and some are not |
| `weak-scheme` | A scheme that falls without the password: `zip-crypto` to known plaintext, `rar-13` to a search of its keys |
| `certificate` | Entries are encrypted to certificates, and no password opens them |
| `unknown-scheme` | An encryption identifier the tool does not know, with its raw value |
| `unsupported-parameters` | A known scheme with parameters outside what its own software accepts |
| `split-entry` | An encrypted entry continues in another volume |
| `incomplete` | The file ends before the archive does |
| `damaged` | The headers stop before the file does, or a header fails its checksum. Nothing is claimed of what was not read |
| `weak-check` | The best line the archive allows is `weak`. The sentence says how many bits it tests |
| `proof-not-run` | An entry is marked encrypted, and the proof of pseudo-encryption could not be run on it |
| `known-plaintext` | `zip-crypto`: the archive itself gives away eight bytes or more in a row of what was encrypted in an entry |
| `weak-header` | `zip-crypto`: the encryption headers give something away, in an archive with entries enough for `attack zip-crypto` to try |

#### JSON

`--json` writes one JSON object for each archive, on a line of its own. The object always holds the entries, in `entry_list`, so `--entries` changes nothing in it.

```console
$ archivewolf info --json tests/fixtures/rar-50/v730_hp_m5.rar
{"path":"tests/fixtures/rar-50/v730_hp_m5.rar","format":"rar","generation":"rar5","offset":0,"headers":"encrypted","entries":"hidden","coverage":"unknown","schemes":[{"scheme":"rar-50","variant":"rar-50:headers:check","cipher":"aes","key_bits":256,"kdf":{"name":"pbkdf2-hmac-sha256","rounds":32768},"check":[{"kind":"check-value","bits":64}]}],"mixed":false,"findings":[],"lines":[{"mode":46800,"tag":"$rar$50$","proves":"exact"}],"no_line":[],"entry_list":[]}
```

The text layout is for people and may change. The JSON object is the interface: its fields are those of the rows above, with `offset` for where the archive starts in the file, `mixed` for more than one scheme, and for each entry its state, variant, parameters, sizes and the line it gives.

### hash

`hash` writes hash lines to standard output, one on a line, and nothing else there. Notes go to standard error: a reminder that the lines hold encrypted data of the archive, a note for every scheme or entry without a line and for every line that proves less than a full check, each with the path of its archive, and at the end a count of the lines by mode. `-q` drops the notes.

```console
$ archivewolf hash tests/fixtures/zip-crypto/stored.zip tests/fixtures/rar-50/v500_hp_m3.rar tests/fixtures/7z-aes/7z_stored.7z
Note: hash lines hold encrypted data of their archives. Handle them with the same care as the archives.
$7z$*19**cefd04dc*1c**1*08fc89645bd2a05ed8088f2ca4395060*20*1c**e7e23b23a8cce6a5aaa56347c8871ccd247cde2bf4a84b878e720cbd776e61a4$/7z$
$rar$50$*0*7c6bbfc80aa28e577ce615613f5360fa*15*00000000000000000000000000000000*9cf287fee23b67c9*0*****$/rar$
$zip$1$*3*d6097b62a749aa05ccd7c7af/75/7c*75e9e068ea3ff4486eab4af6/75/57*e22ee8df46b98060a520619c/75/4e*0*7c59371b*6*6*9956fd970181$/zip$
archivewolf: 3 hash lines: 1 of mode 46100, 1 of mode 46800, 1 of mode 46900
```

The first and the last line of that output are on standard error. The three hash lines are short because the entries are small: a line carries the encrypted data a password is tested against, and can be more than a megabyte long.

| Option | Effect |
| --- | --- |
| none | One line for each scheme in an archive, from the entry whose line proves most and, among those, costs a cracker least |
| `--all` | A line for every encrypted entry or folder that can have one. It is for archives whose entries do not share one password |
| `--mode MODE` | Only the lines of that hashcat mode. A number that is no mode `hash` writes lines for is refused, with the modes there are |
| `--json` | One object for each line: the path of its archive, its entry, its scheme, its mode, the tag of the line, what it proves, and the line |

#### Using the lines with hashcat

hashcat takes one mode at a time, and a run over several archives gives lines for several modes. `hash` writes no file, so the lines of one mode are kept with a redirection. Here it keeps the one RAR 5 line of the three archives above:

```console
$ archivewolf hash --mode 46800 tests/fixtures/zip-crypto/stored.zip tests/fixtures/rar-50/v500_hp_m3.rar tests/fixtures/7z-aes/7z_stored.7z > 46800.hash
Note: hash lines hold encrypted data of their archives. Handle them with the same care as the archives.
archivewolf: 1 hash line: 1 of mode 46800
```

A hashcat built from the fork then takes the file with the same mode, for example `hashcat -m 46800 46800.hash wordlist.txt`.

#### What a line proves

`info` and the JSON of `hash` say what a line proves:

| Proof class | The password is confirmed by |
| --- | --- |
| `exact` | A checksum of the unpacked data, an authentication code over the data, or a 64-bit check value |
| `structural` | The stream unpacking to its size without error, or the decrypted bytes parsing as a header |
| `weak` | Check bytes, a verifier, or a checksum over fewer than four bytes, and no data beyond them |

`hash` names every weak line on standard error. A password found with one has to be confirmed by opening the archive:

```console
$ archivewolf hash tests/fixtures/zip-crypto/gen_7z_zipcrypto_lzma.zip
Note: hash lines hold encrypted data of their archives. Handle them with the same care as the archives.
tests/fixtures/zip-crypto/gen_7z_zipcrypto_lzma.zip: weak line: text40k.txt: hashcat has no decoder for compression method 14, so the line tests only the check bytes of 1 header: 8 bits. Confirm a password found with it by opening the archive.
$zip$1$*1*8b9b9c1c297968f12afa9a93/82*14*8296d51a*9c40*2f38*$/zip$
archivewolf: 1 hash line: 1 of mode 46100
```

#### When no line is written

An encrypted archive without a line is not a failure. The note gives the reason in brackets, and the exit status is 0:

```console
$ archivewolf hash tests/fixtures/rar-13/rar14-password-stored.rar
tests/fixtures/rar-13/rar14-password-stored.rar: no line: rar-13: no hashcat mode exists for rar-13: `attack rar-13` searches its key [no-mode]
archivewolf: no hash lines
```

Every case has one of these reasons, in the same words every time:

| Reason | Meaning |
| --- | --- |
| `no-mode` | No hashcat mode exists for the variant |
| `no-password` | No password opens the entry: it is encrypted to certificates |
| `unknown-scheme` | The encryption identifier is not known |
| `unsupported-parameters` | The scheme's own software refuses these parameters |
| `not-expressible` | The line format has no way to say what the archive holds |
| `over-limit` | The line would exceed what its mode loads |
| `split` | The data of the entry is not all in this file |
| `no-data` | Nothing in the entry can be tested: it is empty, or it has no check a password could be held against |
| `damaged` | The headers of the entry cannot be read |

#### How the lines are known to be right

The tool does not test passwords, so the proof that a line is right lies outside it, in three steps:

- The default test run holds one recorded line of every tag and every shape of line to its bytes (`tests/golden/`).
- `make test-extractors` compares the lines of every fixture with those of the extractors in the hashcat fork.
- `make test-hashcat` gives the recorded lines and their passwords to a hashcat binary and requires the crack.

The last two need the fork and run neither in the default test run nor in CI. `tests/golden/manifest.json` records what was checked and when.

### attack rar-13

RAR 1.3 derives a key of three bytes from the password, and a password can give 2^23 of them. `attack rar-13` tries them all. A key is tested by decrypting an entry, unpacking it and comparing its 16-bit checksum. Several keys can pass that, so they are narrowed over all entries and by what the entries decrypt to.

The result is the key, and a decrypted copy of the archive in the file `-o` names: the same entries with nothing encrypted, for an archive tool to unpack. No hashcat mode exists for this scheme, which is why the command writes a file.

```text
$ archivewolf attack rar-13 tests/fixtures/rar-13/rar14-password-stored.rar -o open.rar
archivewolf: testing 8388608 keys on SECRET.TXT (stored, 87 bytes), the only entry a key can be tested on
archivewolf: this takes under a second on 16 threads; the budget is 10 minutes
archivewolf: 8388608 of 8388608 keys tested: 145 pass the checksum of SECRET.TXT
KEY RECOVERED: RAR 1.3 key = 73 1f 3d (145 keys satisfy the 16-bit entry checksum; this is the only one that decrypts to recognisable content)
DECRYPTED: 1 RAR 1.3 entries → open.rar
Extract with: unrar x -- 'open.rar'
```

The three lines that start with `archivewolf:` go to standard error, and `-q` drops them. The time and the number of threads are those of the machine.

- **The output file** is created new. One that exists is never overwritten, a symbolic link is never followed, and no directory is made for it. All three are refused before the search starts.
- **Several keys.** When several keys are left and nothing tells them apart, all of them are printed, nothing is written and the exit status is 3. The same status says that no key fits.
- **The order of the work.** The first pass over the keys is made on the entry that is cheapest to test. The keys that pass it are then tested on the other entries.
- **Progress.** Before the pass starts, the command measures its own speed and says which entry it tests and how long that will take. While it runs it reports its progress.
- **Time.** The search unpacks an entry for every key, so its time grows with the size of the entry. On 16 cores it took under a second for the stored entry above, about half a minute for a compressed entry of 1 KB and about five minutes for one of 12 KB.
- **`--budget`** limits the time: a number with a unit, as in `90s`, `10m` or `2h`, or `none` for no limit. The default is ten minutes. A search that is measured to take longer than its budget is not started, because no key is known before the last one has been tried. A search that its budget ends has found nothing. Both give status 3, write nothing, and name a budget that would be enough.

### attack zip-crypto

ZIP traditional encryption turns a password into three keys of 32 bits, and the keys are all that decrypts. Twelve bytes of what was encrypted, eight of them in a row, give the keys back: the attack of Biham and Kocher. `attack zip-crypto` finds such bytes by itself where an archive gives them away, takes more from the user, and for some writers needs none at all, because their encryption headers are not random.

It works on the entries that `info` calls encrypted with `zip-crypto`. An entry that only carries the flag, with plain data or with a cipher of someone's own behind it, is left out and named.

#### With nothing but the archive

The command says what is known, prints a plan of the searches that allows with what each costs, and runs it:

```text
$ archivewolf attack zip-crypto tests/fixtures/zip-crypto/bkcrack-src_secrets.zip -o open.zip
measuring the speed of this machine: two seconds, once
tests/fixtures/zip-crypto/bkcrack-src_secrets.zip: 2 entries under zip-crypto, written by 7-Zip

what is known
  2 entries        1 check byte                                               certain
  1 entry          stored, type known from the name                           likely
  1 entry          nothing a search can start from

the plan, budget 15 minutes; 21,488 candidates a second on 16 threads with the avx512 kernel
   1  spiral.svg: signature of an XML file   20 bytes in a row, 584,306 candidates   about 27 seconds   likely
   2  spiral.svg: signature of an XML file   23 bytes in a row, 501,041 candidates   about 23 seconds   likely
   3  spiral.svg: signature of an XML file   20 bytes in a row, 580,033 candidates   about 27 seconds   likely

not in the plan
  advice.jpg   a JPEG image, packed: its content does not show in its stream

what would help most: one file that is in the archive, in any version (--known)

[1/3] spiral.svg: signature of an XML file
      reduction: 20 bytes in a row, 584,306 candidates; the run and what stands beside it are worth 160 bits
      search  [==========>                   ]  36 %   211,072 of 584,306   10 seconds so far, at most about 17 seconds more
      keys found at candidate 413,378 of 584,306
      proof: decrypts spiral.svg to its CRC-32 (200 bits speak for the keys, 112 are asked for)

keys found on spiral.svg (stored, signature of an XML file, 20 bytes in a row)
proved: decrypts spiral.svg to its CRC-32
the keys open 2 of 2 encrypted entries
wrote open.zip: 2 entries decrypted and still packed
keys c4490e28 b414a23d 91404b31
$zip$4$*0*c4490e28*b414a23d*91404b31$/zip$
$zip$4$*1*c4490e28*b414a23d*91404b31$/zip$
```

The last three lines are standard output: the keys, and the two lines of hashcat modes 46400 and 46410, which search the password that gives those keys. Everything above them goes to standard error, and `-q` drops it. The speed, the times and the number of threads are those of the machine.

What the command starts from by itself:

| Source | What it gives |
| --- | --- |
| The check bytes | One or two known bytes at the end of the encryption header of every entry |
| The packing method | The head of a Deflate stream that did not pack, and the start of a bzip2 or XZ stream |
| The name of a stored entry | The signature of the type the name says, from a table of 53 types that is held against real files of each |
| A copy that is not encrypted | The same entry in plain, in the same archive or in another that is given |

#### From the encryption headers alone

Twelve bytes stand in front of every entry and are encrypted with it: an encryption header of ten or eleven bytes that are meant to be random, and the check bytes behind them. For the writers below they are not random, and the archive gives its keys with no known byte of any file:

| Writer | Where its header bytes come from | The archive needs | Time |
| --- | --- | --- | --- |
| Info-ZIP `zip`: the `zip` command of Linux and of macOS, and `zip.exe` on Windows as Info-ZIP, GnuWin32, MinGW, Cygwin and MSYS2 build it | The `rand()` of its C library, seeded once with the time: glibc, which Cygwin and MSYS2 share, macOS, musl, the runtime of Windows and that of Borland are searched | 4 entries | Seconds, and half a minute with exactly four |
| WinRAR 2.90 to 3.20 and 4.20 to 7.23, for a ZIP archive under what it calls ZIP legacy encryption | The header of Info-ZIP, whose code WinRAR carries: the `rand()` of Borland up to 3.20 and that of Windows from 4.20 on, seeded once with the time and the process number | 4 entries | Seconds |
| minizip, and the many programs that are built on it | The same generator and another seed. It leaves no mark of itself, so a writer that is not known is asked the same question | 4 entries | Seconds |
| Double Commander | The generator of Free Pascal, which its zip plugin never seeds: one sequence, the same on every machine | 4 entries | A second |
| SharpZipLib up to 1.3.0, DotNetZip and Aspose.ZIP, on .NET Core 2.0 to .NET 5 | The generator of .NET, made anew for each entry | 5 entries | About a minute |
| The same on the .NET Framework and on .NET Core 1.0 and 1.1 | The same generator, seeded for each entry with the clock of Windows | Entries written over twelve steps of that clock or more, which is a fifth of a second | Half a minute to some minutes |
| The zip library of ComponentOne (`C1.Zip`) | A generator of .NET that is seeded for each entry with the millisecond of the clock: one of a thousand headers, on every runtime | Entries written in three different milliseconds or more shortly after each other, or in thirteen at any time | Seconds |
| The ZipArchive library of Artpol | `rand()`, seeded for each entry with the time in seconds | Entries written in two different seconds or more | Seconds |
| zip utils and XZip | `rand()`, seeded for each entry with the clock of Windows and the handle of the desktop window | Entries written over two steps of that clock or more, by a program in the session of a user | Seconds |

```text
$ archivewolf attack zip-crypto -q tests/fixtures/zip-crypto/gen_infozip_six.zip
keys b4fd7fc8 9cc4f2bc 92c95100
$zip$4$*0*b4fd7fc8*9cc4f2bc*92c95100$/zip$
$zip$4$*1*b4fd7fc8*9cc4f2bc*92c95100$/zip$
```

- A writer that drew a header for a file it then gave up, as `zip` does, is allowed for.
- Ten equal bytes at the start of every header are `yeka/zip`. They are no path of their own, and filter every key of another search.
- zip utils is measured on archives that a program wrote in the session of a user, on two machines with Windows Server 2022: the handle of the desktop window is the same there. An archive that a service wrote has another handle and is not found.
- WinRAR 3.51 to 4.01 takes its header bytes from a hash of two clocks and is not reached. 5.50 and 5.61 encrypt a ZIP archive with AES unless the legacy option is set by hand.
- Aspose.ZIP and the library of ComponentOne leave no mark of their own in the directory: an archive of a writer that is not known is asked their question as a guess.
- On .NET 6 and later the generator of SharpZipLib, DotNetZip and Aspose.ZIP cannot be predicted, and 7-Zip and the `tar` of Windows draw from a secure source. Bandizip was measured too: none of the generators above gives its headers.
- `info` says which of these an archive shows, as the finding `weak-header`.

#### Giving it what you know

| Option | Takes |
| --- | --- |
| `--known <PATH>` | A file, a folder or an archive that may hold content of the archive. What fits is found by size and CRC-32, also a file that is only similar to an entry |
| `--bytes <ENTRY[@POS]=HEX>` | Known bytes of an entry in hex, at a position or anywhere. A position below zero counts from the end |
| `--text <ENTRY[@POS]=STR>`, `--text16` | The same as text, or as text in UTF-16 |
| `--starts <ENTRY=STR>`, `--ends <ENTRY=STR>` | The text an entry starts or ends with |
| `--class <ENTRY=CLASS>` | Every byte of the entry is of this class: `text`, `ascii` or `utf16` |
| `--type <ENTRY=TYPE>` | The entry is a file of this type, whatever its name says |
| `--catalogue <FILE>` | A list of files that exist elsewhere, with their CRC-32 and size. The entries that are such files are named, for the user to find one |
| `--keys <X> <Y> <Z>` | Keys from an earlier run. They are tested on every entry, and nothing is searched |

A file that the archive holds packed is of use only when it is packed again as the writer did it. The command packs a file of `--known` with zlib at every setting and with the Deflate of Info-ZIP `zip` at every level, 31 packers in all, and compares sizes. Both packers are ports that are held to streams the real programs wrote.

#### The plan and its limits

Attempts are ordered by what they cost for the chance they have. An attempt that is measured to take longer than what is left of the budget is not started.

| Option | Effect |
| --- | --- |
| `--plan` | Print the plan and stop |
| `--entry <PATTERN>` | Only attempts on these entries |
| `--only <PATH,...>` | Only these paths: `run`, `short-run`, `header`, `header-once` |
| `--no-guess` | Only claims that are certain or derived |
| `--deep` | Also the attempts that take hours: runs with one byte that is not known |
| `--budget <TIME>` | For the whole command: a number with a unit, as in `90s`, `15m` or `2h`, or `none`. The default is fifteen minutes |
| `--attempt-budget <TIME>` | For one attempt. Without it an attempt may take what is left of the budget |
| `--threads <N>` | How many threads search. All there are, when it is not given |
| `--slice <K/N>` | This machine's part of every search, when several machines share the work |

#### The result

- **Proof.** Keys are reported as proved when they decrypt an entry to its CRC-32 and enough speaks for them besides: 112 bits in all, counted from the run, the bytes beside it, the check bytes of other entries, the CRC-32, and the CRC-32 of every other entry the keys open as well. A CRC-32 alone is 32 bits against 96 bits of keys, so keys that have less are reported as `unproved`, with status 3.
- **The password.** When the keys are those of a password of six bytes or fewer, the password is printed too. It is worked out from the keys by arithmetic: no candidate is tested. A longer one is for hashcat, with the `$zip$4$` lines.
- **`-o <FILE>`** writes the archive without its password: the entries the keys open are decrypted and stay packed, the others are copied as they are. The file is created new, as with `attack rar-13`.
- **`--json`** writes the result as one JSON object. With `-v`, what happens on the way is a stream of events on standard error, one object on a line.

#### Stopping and going on

`--state <FILE>` keeps how far the searches came: which attempts ended, and the candidate the running one has reached, written every ten seconds. `--resume` goes on from that file: attempts that ended without keys are not run again, and the one that was running starts where it was. A run that is stopped or dies loses ten seconds of search at most. The file is created new, and a state of other archives is refused.

#### What the command writes

The speed of the machine is measured once, in two seconds, and kept in `$XDG_CACHE_HOME/archivewolf` (or `~/.cache/archivewolf`). A run whose searches take half a minute or more and go a quarter faster or slower than that corrects it, so a measurement that was taken while the machine was busy does not stand. The same measurement chooses the kernel: a scalar one that runs anywhere, one for AVX2 and one for AVX-512, of which the fastest on the machine is the one that searches.

Beside the files that `-o` and `--state` name, that is the only thing the tool ever writes.

### Exit status

| Status | Meaning |
| --- | --- |
| 0 | Every input was processed, and an attack that was asked for succeeded |
| 1 | Nothing was processed: no archive was found in the given paths, the result could not be written, or an attack could not start |
| 2 | At least one input could not be processed: a path cannot be read, an archive does not parse, or it hit an internal error. The others are still reported |
| 3 | An attack ended without a result: no key was found, several keys are left and nothing tells them apart, keys were found that nothing proves, or its budget ended it |

When several apply, 2 comes before 3 and 3 before 0. Status 1 is returned only when nothing was processed at all: a path that does not exist beside an archive that is processed gives 2. A command line that cannot be parsed exits with the status of the argument parser, which is also 2.

## What it does not do

- **Test a password or crack.** It takes no password, no wordlist and no candidates. hashcat does that, with the lines. `attack zip-crypto` prints a password of six bytes or fewer that it works out from keys it has found, and tests none.
- **Run another program.**
- **Unpack an archive or recover file content.** No entry is written to disk, and nothing is reconstructed from a CRC-32. What an attack writes is an archive, with its entries still packed.
- **Write lines for other tools.** The lines are those of modes 46100 to 46900 of the hashcat fork.
- **Repair pseudo-encryption.** `info` proves it and names the entries. No cleaned copy of the archive is written.
- **Check the integrity of unencrypted entries, or look inside entries.** An archive stored in an archive is one entry.
- **Change its input.**
- **Handle other formats.** ZIP, RAR and 7-Zip only.

## Handling untrusted archives

The tool reads files that may be built to break it.

- **No unsafe code in the tool.** `#![forbid(unsafe_code)]` holds for this crate: the library declares it, and `Cargo.toml` forbids `unsafe_code` for every target, so the crate does not compile with an `unsafe` block in it.
- **One exception, which reads no archive.** The key search of `attack zip-crypto` is a crate of its own, `crates/zip-crypto`, with no dependency. Its two vector kernels, for AVX2 and for AVX-512, each take `unsafe` in three places: for the call into code that needs the instruction set, for the loads and stores, and for the table look-ups. The crate is given key stream bytes and numbers, never a file.
- **The dependencies** are crates from crates.io, and several of them use `unsafe`. None compiles C. A test holds `Cargo.lock` to that: it names no `cc`, `cmake`, `pkg-config`, `bindgen`, `vcpkg` or `nasm-rs`, and no `-sys` crate except `linux-raw-sys` and `windows-sys`, which declare system interfaces in Rust. `cargo deny check` refuses the same six build helpers.
- **Errors do not stop a run.** An archive that cannot be read or parsed is reported on standard error and the run goes on with the next. A panic while an archive is processed is caught and reported the same way, as an internal error, with exit status 2.
- **Nothing from an archive acts on the terminal.** Names, comments and paths are escaped before they are printed as text, so nothing from an archive starts a line of output or acts on a terminal. JSON keeps every byte, escaped by the serializer.
- **Sizes are not trusted.** The tests build archives of a few dozen bytes that claim a size of 2^62, and archives of a few hundred kilobytes that unpack to gigabytes, and the tool has to list them and write their lines, on Linux with its address space capped at 1 GiB.
- **Memory grows with the headers, not with the archive.** An archive is read by range: its headers, and the data a line needs. The tests analyse archives of several gigabytes under a memory cap of 1 GiB. `attack rar-13` holds its archive in memory, 1 GiB at most. `attack zip-crypto` reads by range too, and its proof and `-o` are one pass in a stream.
- **What was not read is said.** A RAR archive whose chain of headers breaks off, or with a header that fails its checksum, gets the finding `damaged`, and nothing is claimed of what was not read.

None of this proves that no file can break the tool. [SECURITY.md](SECURITY.md) says how to report one that does.

## Releases

There is no release yet. When a tag `vX.Y.Z` is pushed, `.github/workflows/release.yml` runs the tests, builds the files below and creates a draft release with them. No tag exists, so this list is what is planned:

| File | Built for |
| --- | --- |
| `archivewolf-linux-x86_64` | `x86_64-unknown-linux-musl` |
| `archivewolf-linux-arm64` | `aarch64-unknown-linux-musl` |
| `archivewolf-macos-arm64` | `aarch64-apple-darwin` |
| `archivewolf-macos-x86_64` | `x86_64-apple-darwin` |
| `archivewolf-macos-universal` | The two macOS binaries in one file |
| `archivewolf-windows-x86_64-msvc.exe` | `x86_64-pc-windows-msvc` |
| `archivewolf-windows-x86_64-gnu.exe` | `x86_64-pc-windows-gnu` |
| `archivewolf-windows-arm64-msvc.exe` | `aarch64-pc-windows-msvc` |
| `SHA256SUMS` | The SHA-256 of every file above |
| `SHA256SUMS.sigstore.json` | The cosign bundle for `SHA256SUMS`: the signature the workflow made, with its certificate |

Once there is a release, verify the signature of `SHA256SUMS` first, with the tag in the place of `vX.Y.Z`, and then the files against it:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/StrongWind1/ArchiveWolf/.github/workflows/release.yml@refs/tags/vX.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

## Development

| Target | Does |
| --- | --- |
| `make dev` | A debug build |
| `make fix` | rustfmt, and the fixes clippy can apply |
| `make check` | `cargo check` of every target |
| `make test` | The default test run, with cargo-nextest |
| `make check-all` | The gate: rustfmt, clippy, cargo-deny, `cargo check`, the tests, rustdoc, file hygiene and cargo-machete |
| `make check-all-full` | The gate, and the key searches of both attacks that are too slow for the default run |
| `make test-rar-13` | The RAR 1.3 key searches that are too slow for the default run |
| `make test-zip-crypto` | The `zip-crypto` searches that are: whole seed searches, long runs, every packer on every sample |
| `make test-extractors` | The lines against the extractors of the hashcat fork, whose path is given in `ARCHIVEWOLF_HASHCAT_REPO` |
| `make test-hashcat` | The recorded lines against a hashcat binary of the fork, whose path is given in `ARCHIVEWOLF_HASHCAT` |
| `make hooks` | Install the pre-commit hook of `.githooks` |

- **Tools.** `make check-all` needs cargo-nextest, cargo-deny, cargo-machete, editorconfig-checker (`ec`), yamllint, actionlint, taplo and markdownlint-cli2.
- **Lints.** Clippy runs with warnings denied. Its thresholds are in `clippy.toml`: clippy's defaults, except three that are held at what the code needs today.
- **Tests that run other programs.** Three tests outside the default run compare the tool with `7zz`, `unrar` and `zipinfo`, and fail when the program is missing (`cargo test -- --ignored --list` shows them with the slow ones). One test of `attack rar-13` also has `unrar` open the decrypted copy where it is installed. The tool itself starts no program.
- **Commits** follow the conventional form, with the scheme ID or the format as scope: `fix(rar-30): ...`, `feat(zip): ...`, `docs: ...`.

## Security

Please report a vulnerability privately, as [SECURITY.md](SECURITY.md) says, and not in a public issue. A crash or a hang on any file, text from an archive that acts on the terminal, and a file that is written where the tool does not say it writes are all in scope.

## Related tools

- [IKEWolf](https://github.com/StrongWind1/IKEWolf): IKE/IPsec security scanner with Aggressive Mode PSK hash extraction
- [NFSWolf](https://github.com/StrongWind1/NFSWolf): NFS security scanner, export escape, and credential escalation
- [CredWolf](https://github.com/StrongWind1/CredWolf): Active Directory credential validation over NTLM and Kerberos
- [KerbWolf](https://github.com/StrongWind1/KerbWolf): Kerberos roasting and hash extraction toolkit
- [NTDSWolf](https://github.com/StrongWind1/NTDSWolf): offline NTDS.dit parser and credential extractor
- [PassWolf](https://github.com/StrongWind1/PassWolf): AD password change, reset, and policy read over SAMR, Netlogon, LSA, Kerberos, and LDAP
- [AD-SecretGen](https://github.com/StrongWind1/AD-SecretGen): derive AD password hashes and Kerberos keys from a cleartext password

## Disclaimer

ArchiveWolf is a penetration-testing and security-research tool. Operating it against systems or data without explicit written authorization is illegal in most jurisdictions. You alone are responsible for how you use it.

## Licence

`Apache-2.0 AND UnRAR AND Zlib AND Info-ZIP`. All four licences apply to the crate.

| Part | Licence | Files that carry the notice |
| --- | --- | --- |
| ArchiveWolf | [Apache License 2.0](LICENSE) | Everything that is not named below |
| RAR code that follows the UnRAR source by Alexander Roshal | UnRAR licence, [LICENSE-UNRAR.txt](LICENSE-UNRAR.txt) | `src/attack/rar_13/crack.rs` and, under `src/formats/rar/`, `encryption.rs`, `headers.rs`, `rar1.rs`, `rar4.rs`, `rar5.rs` and `unpack15.rs` |
| The key search of `attack zip-crypto`, in `crates/zip-crypto/`: ports of parts of [bkcrack-rs](https://github.com/zachshallbetter/bkcrack-rs) by Zach Shallbetter, itself a port to Rust of [bkcrack](https://github.com/kimci86/bkcrack) by Joachim Hotonnier, and of bkcrack itself | zlib licence, [LICENSE-BKCRACK.txt](LICENSE-BKCRACK.txt) | `tables.rs`, `reduce.rs`, `kernel/port.rs` and `password.rs` |
| The packers of `attack zip-crypto`, in `src/attack/zip_crypto/pack/`: ports of the Deflate of [zlib](https://zlib.net) by Jean-loup Gailly and Mark Adler and of Info-ZIP `zip` 3.0 | zlib licence, in the files, and the Info-ZIP licence, [LICENSE-INFOZIP.txt](LICENSE-INFOZIP.txt) | `deflate.rs` and `trees.rs` |

The ports are altered versions and not the original software.

The UnRAR licence restricts use: the code may be used in any software to handle RAR archives, free of charge, but not to develop a RAR (WinRAR) compatible archiver and not to re-create the RAR compression algorithm, which is proprietary. Modified UnRAR source code may be distributed, by itself or as part of other software, on the condition that the full text of the paragraph below is included in the licence, or in the documentation if there is no licence, and in the source code comments of the resulting package.

The second paragraph of the UnRAR licence reads:

```text
UnRAR source code may be used in any software to handle
RAR archives without limitations free of charge, but cannot be
used to develop RAR (WinRAR) compatible archiver and to
re-create RAR compression algorithm, which is proprietary.
Distribution of modified UnRAR source code in separate form
or as a part of other software is permitted, provided that
full text of this paragraph, starting from "UnRAR source code"
words, is included in license, or in documentation if license
is not available, and in source code comments of resulting package.
```
