# The files the table of types is held against

`src/formats/zip/known/types.json` says what a file of a type starts and ends with. The first rule of that table is that every row is backed by real files of its type from more than one writer, and that a row the files do not bear out is not in the table. This directory is that backing.

| File | Holds |
|---|---|
| `samples.json` | One object for each real file: its type, who wrote it, where it is from, its size, and its first and last bytes in hex. No whole file is kept |
| `gather.py` | The script that made `samples.json` |
| `pending.json` | Rows written from the documented formats that are not in the table, because files of two writers were not at hand |

The test `every_row_holds_for_real_files_of_its_type_and_for_no_other` in `src/formats/zip/known/types.rs` reads `samples.json`. For every row it asks two things: that the row holds for files of its type from two writers or more, and that no form of it that knows six bytes in a row holds for a file of another type that is not its kin.

## Where the files are from

`gather.py` takes a file from two kinds of places.

- Trees of public software on the machine it runs on: the packages of the system, the registry of cargo, and the repositories cloned for reference under `ref/`. The writer of such a file is named by the package or the repository it ships with. That is a stand-in: two packages may have used the same program.
- Programs that are run to write one, where the writer is the program: ImageMagick, FFmpeg, SoX, LibreOffice, SQLite, OpenSSL, gzip, bzip2, xz, zstd, tar, Info-ZIP, 7-Zip, RAR, and the standard library and ten libraries of Python.

The file was made on 2026-11-20 on Debian 13 with:

```text
uv run --no-project --with pillow --with ebooklib --with odfpy --with python-docx --with openpyxl --with python-pptx --with icalendar --with ics --with fpdf2 --with vobject python -I tests/types/gather.py --make
```

A run on another machine finds other files, and the rows have to hold for those as well: that is the point of running it again.

## Adding a type

Write the row in `types.json`, run `gather.py`, and run the test. A row for which `gather.py` finds no files of two writers stays in `pending.json` until it does.

The sixteen rows that wait there: `kdbx`, `avi`, `lnk`, `appledouble`, `ds_store`, `manifest`, `pcapng`, `reg`, `bplist`, `mdb`, `vcf`, `sql`, `url`, `desktop_ini`, `bat` and `torrent`.
