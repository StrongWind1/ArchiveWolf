"""Record the streams of zlib for every input, level, memory level and strategy.

Writes `zlib.json` beside this script. Run it from anywhere:

    uv run --no-project python -I tests/packers/record_zlib.py

The zlib that is recorded is the one the Python of that command links, and its version goes
into the file. `README.md` beside this script says what the file is for.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import platform
import sys
import zlib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import ModuleType

HERE = Path(__file__).resolve().parent

# The cases whose whole stream is kept, as hex: (input, level, memory level, strategy).
WHOLE = [
    ("empty", 6, 8, 0),
    ("random:1:1", 6, 8, 0),
    ("text:3:3", 9, 9, 4),
    ("text:30:4", 1, 8, 0),
    ("text:300:5", 6, 8, 0),
    ("text:300:5", 9, 1, 1),
    ("zeros:1000", 6, 8, 3),
    ("random:1000:6", 6, 8, 2),
    ("random:1000:6", 1, 9, 0),
    ("file:LICENSE-UNRAR.txt", 6, 8, 0),
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


def pack(data: bytes, level: int, mem_level: int, strategy: int) -> bytes:
    """Return the raw Deflate stream of the whole input."""
    packer = zlib.compressobj(level, zlib.DEFLATED, -15, mem_level, strategy)
    return packer.compress(data) + packer.flush()


def setting(level: int, mem_level: int, strategy: int) -> int:
    """Return a setting as the three digits the record keeps it in."""
    return level * 100 + mem_level * 10 + strategy


def record_input(name: str, data: bytes) -> str:
    """Return the part of the record that is about one input."""
    # the streams of the input in the order they first come up, each with its settings
    streams: dict[tuple[int, str], list[int]] = {}
    for strategy in range(5):
        for mem_level in range(1, 10):
            for level in range(1, 10):
                stream = pack(data, level, mem_level, strategy)
                streams.setdefault(
                    (len(stream), hashlib.sha256(stream).hexdigest()), []
                ).append(setting(level, mem_level, strategy))
    rows = [
        f"        {json.dumps([length, digest, settings])}"
        for (length, digest), settings in streams.items()
    ]
    head = [
        "    {",
        f'      "input": {json.dumps(name)},',
        f'      "length": {len(data)},',
        f'      "sha256": "{hashlib.sha256(data).hexdigest()}",',
        '      "streams": [',
    ]
    sys.stderr.write(f"{name}: {len(data)} bytes, {len(rows)} streams\n")
    return "\n".join([*head, ",\n".join(rows), "      ]", "    }"])


def main() -> None:
    """Pack every input at every setting and write the record."""
    inputs = load_inputs()
    whole = []
    for name, level, mem_level, strategy in WHOLE:
        stream = pack(inputs.make(name), level, mem_level, strategy)
        whole.append(
            f"    {json.dumps({'input': name, 'setting': setting(level, mem_level, strategy), 'stream': stream.hex()})}"
        )
    lines = [
        "{",
        f'  "program": {json.dumps(f"zlib {zlib.ZLIB_RUNTIME_VERSION}, as CPython {platform.python_version()} links it")},',
        '  "call": "zlib.compressobj(level, zlib.DEFLATED, -15, mem_level, strategy), then compress(input) + flush()",',
        '  "setting": "three digits: the level, the memory level, the strategy (0 default, 1 filtered, 2 Huffman only, 3 RLE, 4 fixed)",',
        '  "stream": "the length of a stream, its SHA-256, and every setting that gives it",',
        '  "inputs": [',
        ",\n".join(record_input(name, inputs.make(name)) for name in inputs.NAMES),
        "  ],",
        '  "whole": [',
        ",\n".join(whole),
        "  ]",
        "}",
    ]
    (HERE / "zlib.json").write_text("\n".join(lines) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
