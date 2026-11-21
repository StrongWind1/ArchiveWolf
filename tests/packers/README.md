# Recorded streams of the packers

`src/attack/zip_crypto/pack/` packs a file the way zlib does and the way Info-ZIP `zip` does, byte for byte. The two JSON files here are what holds it to that: for each input and each setting they keep the length and the SHA-256 of the Deflate stream that the real program wrote, and a few streams whole. The tests of the module read them.

## What was recorded

| File | Program | Cases |
|---|---|---|
| `zlib.json` | zlib 1.3.2, as the CPython 3.15.2 of `uv` links it | 27 inputs, each at levels 1 to 9, memory levels 1 to 9 and the five strategies: 10,935 |
| `infozip.json` | Zip 3.0 (July 5th 2008) by Info-ZIP, `/usr/bin/zip` of the Debian 13 package `zip` 3.0-15+deb13u1 on amd64, which is built with its own Deflate and not with zlib | 27 inputs, each at `-1` to `-9`: 243 |

Recorded on 2026-11-20. zlib 1.3.1, as the Python 3.13.5 of Debian 13 links it, gives the same 10,935 streams: `record_zlib.py` was run with it and the two files differed in the line that names the program and nowhere else.

## How

```sh
uv run --no-project python -I tests/packers/record_zlib.py
uv run --no-project python -I tests/packers/record_infozip.py
```

Each script writes its JSON file beside itself. Neither takes an argument.

**zlib.** The stream of a case is `zlib.compressobj(level, zlib.DEFLATED, -15, mem_level, strategy)`, then `compress(input) + flush()`: a raw Deflate stream, the whole input in one call, and `Z_FINISH`. Level 0 is not recorded, since what zlib writes at level 0 depends on the sizes of the buffers of its caller.

**zip.** Each case runs `zip` twice in an empty directory, on the input as the file `data.bin`.

- `zip -X -q -LEVEL out.zip data.bin` says whether `zip` stores the input, as method 0. It does when the input packs into one block that is not smaller than the input, and it can do so only here, where the archive is a file and `zip` can go back to the header of the entry.
- `zip -X -q -LEVEL - data.bin`, with the archive going to a pipe, gives the Deflate stream: `zip` cannot go back there and writes the stream whatever comes of it. That stream is the recorded one.

Where both runs give a Deflate stream the script checks that it is the same stream, and fails if it is not. The empty input has no stream: `zip` stores a file of no bytes without starting its packer.

## The inputs

The inputs are not in the tree. Each is named by a line such as `text:400000:16`, and is either a file of the repository that never changes (`LICENSE`, `LICENSE-UNRAR.txt`) or the output of a small generator. The generators are written twice: in `inputs.py` for the recording, and in `src/attack/zip_crypto/pack/tests.rs` for the tests. The head of `inputs.py` lists the kinds. Both JSON files keep the length and the SHA-256 of every input, and the tests check them before they compare a stream, so the two copies of a generator cannot drift apart unseen.

The inputs are chosen for what the packers do differently on them: no bytes, one to three bytes, short and long text, random bytes that do not pack, runs, repeats, records of a binary table, data made of copies of itself (on which `zip` ends its blocks early), counts that make a Huffman tree too deep, and four inputs over 1 MiB, which slide the window 33 to 45 times.

## The layout of the files

Both files start with the program, the call and a line that explains a row.

- `zlib.json`: each input has its `streams`, one row for each distinct stream: the length, the SHA-256, and every setting that gives that stream. A setting is three digits, the level, the memory level and the strategy (0 default, 1 filtered, 2 Huffman only, 3 RLE, 4 fixed): `680` is level 6 at memory level 8 with the default strategy. Many settings give the same stream, which is why the rows are grouped: the file is a third of the size it has with one row for each setting.
- `infozip.json`: each input has its `cases`, one row for each level: the level, 1 where `zip` stores the input in an archive file, and the length and the SHA-256 of the stream it writes to a pipe.
- `whole` in both: a few streams of small inputs in hex, so that a difference can be read bit by bit.

## What the tests compare

The default run compares 4,164 of the cases of zlib and 179 of those of `zip`, in about 11 s of processor time on the machine of the recording: the crate is not optimised in the development profile. Two tests that are ignored compare all of them, in 12 s on 16 threads when optimised:

```sh
cargo nextest run --cargo-profile release-dev -p archivewolf -E 'test(/pack::tests/)' --run-ignored only
```

Every stream that is compared is also unpacked with `flate2` and has to give its input back.

## Recording again

A new input is a name in `NAMES` of `inputs.py`, and a new kind of input is a generator in `inputs.py` and the same one in `tests.rs`. Both scripts then record everything again, and the counts of cases in the tests change with it. A record made with another version of a program names that version in its first line, and a stream that differs from the one in the tree is a change in that program which the port does not have yet.
