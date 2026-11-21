"""Gather the real files that the rows of the type table are held against.

For every type of `src/formats/zip/known/types.json` this looks for files of that type that
other programs wrote, and writes the first and the last bytes of each to `samples.json`, with
the size of the file and where it is from. No whole file is kept.

A file is taken from two kinds of places. The first is trees of software that is public and
installed on the machine: packages of the system, the registry of cargo, and repositories
cloned for reference under `ref/`. There the writer is named by the package or the repository
the file ships with. The second is programs that are run here to write one (`--make`), where
the writer is the program.

Run from the root of the repository, with the libraries of Python that write a format of
their own:

    uv run --no-project --with pillow --with ebooklib --with odfpy --with python-docx --with openpyxl --with python-pptx --with icalendar --with ics --with fpdf2 --with vobject python -I tests/types/gather.py --make

It never reads below a home directory other than the caches named in ROOTS, and it writes
nothing but `tests/types/samples.json` and a scratch directory that it removes.
"""

from __future__ import annotations

import argparse
import bz2
import fnmatch
import gzip
import importlib
import importlib.metadata
import json
import lzma
import os
import py_compile
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import wave
import zipfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
TABLE = REPO / "src/formats/zip/known/types.json"
OUT = REPO / "tests/types/samples.json"

# Public trees only. Each entry: the directory, and how many path parts below it name the writer.
ROOTS = [
    ("/usr/share", 1),
    ("/usr/lib", 1),
    ("/usr/local/lib", 1),
    ("/usr/local/share", 1),
    ("/opt", 1),
    ("/var/cache/apt/archives", 0),
    (str(Path.home() / ".cargo/registry/src"), 2),
    (str(Path.home() / ".rustup/toolchains"), 1),
    (str(Path.home() / ".cache/uv"), 3),
    (str(REPO / "ref/github"), 1),
    (str(REPO / "ref"), 1),
]

# Directories that are not walked: build output, and trees that another root already covers.
SKIP = {".git", "node_modules", "__pycache__", "target", "experiments"}
SKIP_PATHS = {str(REPO / "ref/github")}

# What is found: for each type, for each writer, its samples.
Found = dict[str, dict[str, list[dict[str, Any]]]]

HEAD = {"tar": 512, "iso": 4096, "exe": 192, "plist": 192, "text": 256}
HEAD_DEFAULT = 128
TAIL = 32
PER_TYPE = 10  # samples kept for one type
PER_WRITER = 2  # of one writer
MAX_SIZE = 64 << 20


def table() -> list[dict[str, Any]]:
    return json.loads(TABLE.read_text())


def kind_of(name: str, rows: list[dict[str, Any]], path: str = "") -> str | None:
    lower, whole = name.lower(), path.lower()
    for row in rows:
        for pattern in row["names"]:
            p = pattern.lower()
            if "/" in p:
                # a pattern with a directory in it is held against the end of the path
                if whole and fnmatch.fnmatchcase(whole, "*/" + p):
                    return row["type"]
                continue
            if fnmatch.fnmatchcase(lower, p):
                return row["type"]
    return None


def sample(path: Path, kind: str, writer: str, origin: str) -> dict[str, Any] | None:
    size = path.stat().st_size
    if size == 0 or size > MAX_SIZE:
        return None
    head_len = HEAD.get(kind, HEAD_DEFAULT)
    with path.open("rb") as handle:
        head = handle.read(head_len)
        tail = b""
        if size > len(head):
            handle.seek(max(len(head), size - TAIL))
            tail = handle.read(TAIL)
    return {"type": kind, "writer": writer, "origin": origin, "size": size, "head": head.hex(), "tail": tail.hex()}


def collect(rows: list[dict[str, Any]]) -> Found:
    found = {}
    for index, (root, depth) in enumerate(ROOTS):
        base = Path(root)
        if not base.is_dir():
            continue
        covered = SKIP_PATHS if index == len(ROOTS) - 1 else set()
        for directory, subdirs, files in os.walk(base, followlinks=False):
            subdirs[:] = sorted(d for d in subdirs if d not in SKIP and str(Path(directory) / d) not in covered)
            for name in sorted(files):
                kind = kind_of(name, rows, str(Path(directory) / name))
                if kind is None:
                    continue
                path = Path(directory) / name
                if path.is_symlink() or not path.is_file():
                    continue
                parts = path.relative_to(base).parts
                writer = "/".join(parts[:depth]) if depth and len(parts) > depth else base.name
                label = f"shipped with {writer} ({base.name})" if depth else f"shipped in {base.name}"
                bucket = found.setdefault(kind, {})
                per_writer = bucket.setdefault(label, [])
                if len(per_writer) >= PER_WRITER:
                    continue
                try:
                    entry = sample(path, kind, label, "a file found in a public tree of this machine")
                except OSError:
                    continue
                if entry is not None:
                    per_writer.append(entry)
    return found


def run(args: list[str], cwd: Path) -> bool:
    try:
        done = subprocess.run(args, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


def version(args: list[str]) -> str:
    try:
        out = subprocess.run(args, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "?"
    text = (out.stdout or out.stderr).decode("utf-8", "replace").strip().splitlines()
    return text[0][:60] if text else "?"


def make(rows: list[dict[str, Any]]) -> Found:
    """Files written here by real programs: (path, writer)."""
    made = []
    scratch = Path(tempfile.mkdtemp(prefix="archivewolf-types-"))
    text = scratch / "seed.txt"
    text.write_text("ArchiveWolf type table sample.\n" + "".join(f"line {n}: the quick brown fox jumps over the lazy dog\n" for n in range(400)))
    blob = scratch / "seed.bin"
    blob.write_bytes(bytes((n * 7919 + (n >> 3)) & 0xFF for n in range(200_000)))

    def add(name: str, writer: str, ok: bool) -> None:
        path = scratch / name
        if ok and path.is_file() and path.stat().st_size > 0:
            made.append((path, writer))

    if shutil.which("magick"):
        who = version(["magick", "-version"])
        for ext in ["png", "jpg", "gif", "bmp", "tif", "webp", "ico", "psd", "pdf", "ps"]:
            add(f"im.{ext}", who, run(["magick", "-size", "96x64", "gradient:blue-red", f"im.{ext}"], scratch))
    if shutil.which("ffmpeg"):
        who = version(["ffmpeg", "-version"])
        for ext in ["png", "jpg", "bmp", "gif", "webp", "tif"]:
            add(f"ff.{ext}", who, run(["ffmpeg", "-y", "-f", "lavfi", "-i", "testsrc=size=96x64:rate=1", "-frames:v", "1", f"ff.{ext}"], scratch))
        for ext in ["wav", "flac", "ogg", "opus", "mp3", "m4a", "mka"]:
            add(f"ff.{ext}", who, run(["ffmpeg", "-y", "-f", "lavfi", "-i", "sine=frequency=440:duration=1", f"ff.{ext}"], scratch))
        for ext in ["mp4", "mkv", "webm", "avi", "mov", "m4v", "3gp"]:
            add(f"ff.{ext}", who, run(["ffmpeg", "-y", "-f", "lavfi", "-i", "testsrc=size=96x64:rate=5", "-t", "1", f"ff.{ext}"], scratch))
    if shutil.which("sox"):
        who = version(["sox", "--version"])
        for ext in ["wav", "flac", "ogg"]:
            add(f"sox.{ext}", who, run(["sox", "-n", "-r", "8000", f"sox.{ext}", "synth", "1", "sine", "440"], scratch))
    if shutil.which("soffice"):
        who = version(["soffice", "--version"])
        profile = f"-env:UserInstallation=file://{scratch}/lo-profile"
        for ext in ["odt", "docx", "doc", "rtf", "pdf", "html", "epub"]:
            run(["soffice", profile, "--headless", "--convert-to", ext, "--outdir", str(scratch / "lo"), str(text)], scratch)
            add(f"lo/seed.{ext}", who, True)
        csv = scratch / "sheet.csv"
        csv.write_text("a,b,c\n1,2,3\n4,5,6\n")
        for ext in ["ods", "xlsx", "xls"]:
            run(["soffice", profile, "--headless", "--convert-to", ext, "--outdir", str(scratch / "lo"), str(csv)], scratch)
            add(f"lo/sheet.{ext}", who, True)
        for ext in ["odp", "pptx", "ppt"]:
            run(["soffice", profile, "--headless", "--convert-to", ext, "--outdir", str(scratch / "lo"), str(scratch / "lo/seed.odt")], scratch)
            add(f"lo/seed.{ext}", who, True)
    if shutil.which("sqlite3"):
        who = version(["sqlite3", "--version"])
        add("s.sqlite", f"sqlite3 {who}", run(["sqlite3", "s.sqlite", "create table t(a,b); insert into t values(1,'x');"], scratch))
        dump = scratch / "s.sql"
        try:
            dump.write_bytes(subprocess.run(["sqlite3", "s.sqlite", ".dump"], cwd=scratch, capture_output=True, timeout=30, check=False).stdout)
            add("s.sql", f"sqlite3 {who}", True)
        except OSError:
            pass
    for tool, name, args in [
        ("gzip", "t.txt.gz", ["sh", "-c", "gzip -c seed.txt > t.txt.gz"]),
        ("bzip2", "t.txt.bz2", ["sh", "-c", "bzip2 -c seed.txt > t.txt.bz2"]),
        ("xz", "t.txt.xz", ["sh", "-c", "xz -c seed.txt > t.txt.xz"]),
        ("xz", "t.txt.lzma", ["sh", "-c", "xz --format=lzma -c seed.txt > t.txt.lzma"]),
        ("zstd", "t.txt.zst", ["sh", "-c", "zstd -q -c seed.txt > t.txt.zst"]),
        ("tar", "t.tar", ["tar", "-cf", "t.tar", "seed.txt"]),
        ("zip", "t.zip", ["zip", "-q", "t.zip", "seed.txt"]),
        ("7zz", "z.7z", ["7zz", "a", "-bd", "z.7z", "seed.txt"]),
        ("7zz", "z.zip", ["7zz", "a", "-bd", "z.zip", "seed.txt"]),
        ("7zz", "z.tar", ["7zz", "a", "-bd", "z.tar", "seed.txt"]),
        ("7zz", "z.txt.xz", ["7zz", "a", "-bd", "z.txt.xz", "seed.txt"]),
        ("7zz", "z.txt.gz", ["7zz", "a", "-bd", "z.txt.gz", "seed.txt"]),
        ("7zz", "z.txt.bz2", ["7zz", "a", "-bd", "z.txt.bz2", "seed.txt"]),
        ("rar", "r5.rar", ["rar", "a", "-idq", "r5.rar", "seed.txt"]),
        ("rar", "r4.rar", ["rar", "a", "-idq", "-ma4", "r4.rar", "seed.txt"]),
    ]:
        if shutil.which(tool):
            names = {"7zz": "7-Zip (7zz)", "rar": "RAR (rar)", "zip": "Info-ZIP zip"}
            add(name, names.get(tool) or version([tool, "--version"]), run(args, scratch))
    if shutil.which("openssl"):
        who = version(["openssl", "version"])
        ok = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "o.key", "-out", "o.crt", "-days", "1", "-subj", "/CN=sample"], scratch)
        add("o.key", who, ok)
        add("o.crt", who, ok)
        add("o.der", who, ok and run(["openssl", "x509", "-in", "o.crt", "-outform", "der", "-out", "o.der"], scratch))
        add("o.p12", who, ok and run(["openssl", "pkcs12", "-export", "-inkey", "o.key", "-in", "o.crt", "-out", "o.p12", "-passout", "pass:sample"], scratch))
    # the standard library of Python is a writer of its own for the formats it implements
    who = f"Python {sys.version.split()[0]} standard library"

    with gzip.open(scratch / "py.txt.gz", "wb") as handle:
        handle.write(text.read_bytes())
    add("py.txt.gz", who, True)
    (scratch / "py.txt.bz2").write_bytes(bz2.compress(text.read_bytes()))
    add("py.txt.bz2", who, True)
    (scratch / "py.txt.xz").write_bytes(lzma.compress(text.read_bytes()))
    add("py.txt.xz", who, True)
    (scratch / "py.txt.lzma").write_bytes(lzma.compress(text.read_bytes(), format=lzma.FORMAT_ALONE))
    add("py.txt.lzma", who, True)
    with tarfile.open(scratch / "py.tar", "w") as handle:
        handle.add(text, arcname="seed.txt")
    add("py.tar", who, True)
    with zipfile.ZipFile(scratch / "py.zip", "w", zipfile.ZIP_DEFLATED) as handle:
        handle.write(text, "seed.txt")
    add("py.zip", who, True)
    with wave.open(str(scratch / "py.wav"), "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(8000)
        handle.writeframes(bytes(16000))
    add("py.wav", who, True)
    connection = sqlite3.connect(scratch / "py.db")
    connection.execute("create table t(a, b)")
    connection.commit()
    connection.close()
    add("py.db", f"{who}, SQLite {sqlite3.sqlite_version}", True)

    # libraries of Python that write a format themselves, each when it is installed
    def library(module: str) -> Any | None:
        try:
            return importlib.import_module(module)
        except ImportError:
            return None

    def release(name: str) -> str:
        try:
            return f"{name} {importlib.metadata.version(name)} (Python)"
        except importlib.metadata.PackageNotFoundError:
            return f"{name} (Python)"

    if (image := library("PIL.Image")) is not None:
        picture = image.new("RGB", (96, 64), (200, 30, 30))
        for ext in ["png", "jpg", "gif", "bmp", "tif", "webp", "ico", "pdf"]:
            try:
                picture.save(scratch / f"pil.{ext}")
            except (OSError, ValueError, KeyError):
                continue
            add(f"pil.{ext}", release("pillow"), True)
    if (epub := library("ebooklib.epub")) is not None:
        book = epub.EpubBook()
        book.set_identifier("sample")
        book.set_title("Sample")
        book.set_language("en")
        chapter = epub.EpubHtml(title="One", file_name="one.xhtml", lang="en")
        chapter.content = "<h1>One</h1><p>Sample.</p>"
        book.add_item(chapter)
        book.add_item(epub.EpubNcx())
        book.add_item(epub.EpubNav())
        book.spine = ["nav", chapter]
        epub.write_epub(str(scratch / "el.epub"), book)
        add("el.epub", release("ebooklib"), True)
    if (odf := library("odf.opendocument")) is not None:
        for ext, document in [("odt", odf.OpenDocumentText), ("ods", odf.OpenDocumentSpreadsheet), ("odp", odf.OpenDocumentPresentation), ("odg", odf.OpenDocumentDrawing)]:
            document().save(str(scratch / f"odfpy.{ext}"))
            add(f"odfpy.{ext}", release("odfpy"), True)
    if (docx := library("docx")) is not None:
        text_document = docx.Document()
        text_document.add_paragraph("Sample.")
        text_document.save(str(scratch / "pd.docx"))
        add("pd.docx", release("python-docx"), True)
    if (openpyxl := library("openpyxl")) is not None:
        workbook = openpyxl.Workbook()
        workbook.active["A1"] = 1
        workbook.save(str(scratch / "op.xlsx"))
        add("op.xlsx", release("openpyxl"), True)
    if (pptx := library("pptx")) is not None:
        pptx.Presentation().save(str(scratch / "pp.pptx"))
        add("pp.pptx", release("python-pptx"), True)
    if (icalendar := library("icalendar")) is not None:
        calendar = icalendar.Calendar()
        calendar.add("prodid", "-//sample//")
        calendar.add("version", "2.0")
        (scratch / "ic.ics").write_bytes(calendar.to_ical())
        add("ic.ics", release("icalendar"), True)
    if (ics := library("ics")) is not None:
        (scratch / "ics.ics").write_text(ics.Calendar().serialize(), newline="")
        add("ics.ics", release("ics"), True)
    if (vobject := library("vobject")) is not None:
        card = vobject.vCard()
        card.add("fn").value = "Sample Person"
        card.add("n").value = vobject.vcard.Name(family="Person", given="Sample")
        (scratch / "vo.vcf").write_text(card.serialize(), newline="")
        add("vo.vcf", release("vobject"), True)
    if (fpdf := library("fpdf")) is not None:
        page = fpdf.FPDF()
        page.add_page()
        page.set_font("helvetica", size=12)
        page.cell(text="Sample.")
        page.output(str(scratch / "fp.pdf"))
        add("fp.pdf", release("fpdf2"), True)
    py_compile.compile(str(Path(__file__)), cfile=str(scratch / "cp.pyc"))
    add("cp.pyc", f"CPython {sys.version.split()[0]}", True)

    out = {}
    for path, writer in made:
        kind = kind_of(path.name, rows)
        if kind is None:
            continue
        entry = sample(path, kind, writer, "written here by the program named")
        if entry is not None:
            out.setdefault(kind, {}).setdefault(writer, []).append(entry)
    shutil.rmtree(scratch, ignore_errors=True)
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--make", action="store_true", help="also run the programs that are installed to write files")
    args = parser.parse_args()
    rows = table()
    found = collect(rows)
    if args.make:
        for kind, writers in make(rows).items():
            bucket = found.setdefault(kind, {})
            for writer, entries in writers.items():
                bucket[writer] = entries + bucket.get(writer, [])
    # the same file under two names, as two forks of one repository ship it, is one file
    seen = set()
    for writers in found.values():
        for writer in sorted(writers, key=lambda w: (not any(e["origin"].startswith("written") for e in writers[w]), w)):
            fresh = []
            for entry in writers[writer]:
                key = (entry["type"], entry["size"], entry["head"], entry["tail"])
                if key not in seen:
                    seen.add(key)
                    fresh.append(entry)
            writers[writer] = fresh
    samples = []
    for row in rows:
        writers = found.get(row["type"], {})
        # made files first, then one of each writer, then seconds, as far as the count goes
        order = sorted((w for w in writers if writers[w]), key=lambda w: (not writers[w][0]["origin"].startswith("written"), w))
        taken = []
        for rank in range(PER_WRITER):
            for writer in order:
                if rank < len(writers[writer]) and len(taken) < PER_TYPE:
                    taken.append(writers[writer][rank])
        samples.extend(taken)
        print(f"{row['type']:14} {len(taken):3} samples from {len({s['writer'] for s in taken})} writers")
    OUT.write_text("[\n" + ",\n".join("  " + json.dumps(s, sort_keys=True) for s in samples) + "\n]\n")


if __name__ == "__main__":
    main()
