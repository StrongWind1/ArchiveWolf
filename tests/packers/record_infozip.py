"""Record the streams of Info-ZIP zip for every input and level.

Writes `infozip.json` beside this script. Run it from anywhere, with `zip` on the path:

    uv run --no-project python -I tests/packers/record_infozip.py

Each input is packed twice at each level. Once into an archive that is a file, which says
whether zip stores the input as it is, with method 0. Once into an archive that goes to a
pipe, where zip cannot go back to rewrite a header and so writes its Deflate stream whatever
comes of it: that stream is what is recorded. Where both are Deflate streams they must be the
same, and the script fails if they are not. `README.md` beside this script says what the file
is for.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import ModuleType

HERE = Path(__file__).resolve().parent

# The name of the input in the archive. zip does not pack files with some suffixes: this is none of them.
NAME = "data.bin"

DEFLATE = 8


def zip_program() -> str:
    """Return the path of `zip`."""
    program = shutil.which("zip")
    if program is None:
        message = "zip is not on the path"
        raise FileNotFoundError(message)
    return program


ZIP = zip_program()

# The cases whose whole stream is kept, as hex: (input, level).
WHOLE = [
    ("random:1:1", 6),
    ("text:3:3", 9),
    ("text:30:4", 1),
    ("text:300:5", 6),
    ("zeros:1000", 6),
    ("random:1000:6", 3),
    ("file:LICENSE-UNRAR.txt", 6),
    ("file:LICENSE-UNRAR.txt", 2),
]


def load_inputs() -> ModuleType:
    """Load `inputs.py` from beside this script: an isolated Python does not look there."""
    spec = importlib.util.spec_from_file_location("inputs", HERE / "inputs.py")
    if spec is None or spec.loader is None:
        message = "inputs.py is not beside this script"
        raise ImportError(message)
    module = importlib.util.module_from_spec(spec)
    # no cache of the compiled module is left in the tree
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    return module


def entry(archive: bytes) -> tuple[int, bytes]:
    """Return the method and the data of the one entry of an archive.

    The sizes are taken from the central directory: an archive that went to a pipe has none
    in its local header.
    """
    with zipfile.ZipFile(io.BytesIO(archive)) as reader:
        info = reader.infolist()[0]
    name_length, extra_length = struct.unpack_from(
        "<HH", archive, info.header_offset + 26
    )
    start = info.header_offset + 30 + name_length + extra_length
    return info.compress_type, archive[start : start + info.compress_size]


def pack(data: bytes, level: int) -> tuple[bool, bytes | None]:
    """Return whether zip stores the input in an archive file, and the Deflate stream it writes to a pipe.

    There is no stream for the empty input: zip does not start its packer for it.
    """
    with tempfile.TemporaryDirectory() as scratch:
        Path(scratch, NAME).write_bytes(data)
        subprocess.run(
            [ZIP, "-X", "-q", f"-{level}", "out.zip", NAME], cwd=scratch, check=True
        )
        in_file = entry(Path(scratch, "out.zip").read_bytes())
        piped = subprocess.run(
            [ZIP, "-X", "-q", f"-{level}", "-", NAME],
            cwd=scratch,
            check=True,
            stdout=subprocess.PIPE,
        )
        in_pipe = entry(piped.stdout)
    if in_file[0] == DEFLATE and in_file != in_pipe:
        message = f"zip -{level}: the stream in a file is not the stream in a pipe"
        raise RuntimeError(message)
    return in_file[0] != DEFLATE, in_pipe[1] if in_pipe[0] == DEFLATE else None


def version() -> str:
    """Return the line of `zip -v` that names the program."""
    listing = subprocess.run(
        [ZIP, "-v"], check=True, stdout=subprocess.PIPE, text=True
    ).stdout
    return next(
        line for line in listing.splitlines() if line.startswith("This is Zip")
    ).strip()


def main() -> None:
    """Pack every input at every level and write the record."""
    inputs = load_inputs()
    lines = [
        "{",
        f'  "program": {json.dumps(version())},',
        '  "call": "zip -X -q -LEVEL - data.bin, the archive to a pipe; and zip -X -q -LEVEL out.zip data.bin for whether the input is stored",',
        '  "case": "level, 1 where zip stores the input in an archive file, length of the Deflate stream in a pipe, its SHA-256 (null where zip writes none)",',
        '  "inputs": [',
    ]
    blocks = []
    for name in inputs.NAMES:
        data = inputs.make(name)
        rows = []
        for level in range(1, 10):
            stored, stream = pack(data, level)
            row = (
                [level, int(stored), None, None]
                if stream is None
                else [
                    level,
                    int(stored),
                    len(stream),
                    hashlib.sha256(stream).hexdigest(),
                ]
            )
            rows.append(f"        {json.dumps(row)}")
        head = [
            "    {",
            f'      "input": {json.dumps(name)},',
            f'      "length": {len(data)},',
            f'      "sha256": "{hashlib.sha256(data).hexdigest()}",',
            '      "cases": [',
        ]
        blocks.append("\n".join([*head, ",\n".join(rows), "      ]", "    }"]))
        sys.stderr.write(f"{name}: {len(data)} bytes, {len(rows)} cases\n")
    lines.append(",\n".join(blocks))
    lines.append("  ],")
    lines.append('  "whole": [')
    whole = []
    for name, level in WHOLE:
        stored, stream = pack(inputs.make(name), level)
        if stream is None:
            message = f"{name}: zip writes no stream"
            raise RuntimeError(message)
        whole.append(
            f"    {json.dumps({'input': name, 'level': level, 'stored': stored, 'stream': stream.hex()})}"
        )
    lines.append(",\n".join(whole))
    lines.append("  ]")
    lines.append("}")
    (HERE / "infozip.json").write_text("\n".join(lines) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
