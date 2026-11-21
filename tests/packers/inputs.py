"""The inputs of the recorded packer streams, made from their names.

Every input is a file of the repository that never changes, or bytes from a generator that is
written twice: here, and in the test module of `src/attack/zip_crypto/pack/`. The recorded
files keep the SHA-256 of every input, so a generator that drifts on either side is found
before any stream is compared.

A name is a kind and its numbers, with colons between them:

    empty                      no bytes
    file:NAME                  a file at the root of the repository
    zeros:LENGTH               zero bytes
    random:LENGTH:SEED         bytes of the generator
    text:LENGTH:SEED           words of a fixed list
    repeat:LENGTH:SEED:PERIOD  PERIOD random bytes, over and over
    runs:LENGTH:SEED           runs of one of four letters, 1 to 700 long
    binary:LENGTH:SEED         records of 16 bytes: a counter, small numbers, a constant
    copies:LENGTH:SEED         a few random bytes, then a copy of an earlier stretch, over and over
    mix:LENGTH:SEED            stretches of the kinds above, up to 60,000 bytes each
    fib:SEED                   21 byte values whose counts are the Fibonacci numbers, shuffled, six times
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).resolve().parent.parent.parent

WORDS = [
    "the",
    "of",
    "and",
    "to",
    "in",
    "is",
    "that",
    "for",
    "it",
    "as",
    "was",
    "with",
    "be",
    "by",
    "on",
    "not",
    "he",
    "this",
    "are",
    "or",
    "his",
    "from",
    "at",
    "which",
    "but",
    "have",
    "an",
    "had",
    "they",
    "you",
    "were",
    "their",
    "one",
    "all",
    "we",
    "can",
    "her",
    "has",
    "there",
    "been",
    "if",
    "more",
    "when",
    "will",
    "would",
    "who",
    "so",
    "no",
    "archive",
    "password",
    "entry",
    "stream",
    "window",
    "block",
    "packer",
    "level",
    "header",
    "length",
    "distance",
    "literal",
    "Huffman",
    "Deflate",
    "known",
    "plaintext",
]

# The names of all inputs, the small ones first.
NAMES = [
    "empty",
    "random:1:1",
    "text:2:2",
    "text:3:3",
    "text:30:4",
    "text:300:5",
    "zeros:1000",
    "random:1000:6",
    "runs:4000:7",
    "text:5000:8",
    "binary:6000:9",
    "copies:9000:10",
    "file:LICENSE-UNRAR.txt",
    "file:LICENSE",
    "text:70000:11",
    "random:100000:12",
    "repeat:120000:13:700",
    "mix:150000:14",
    "fib:15",
    "zeros:300000",
    "text:400000:16",
    "binary:500000:17",
    "copies:700000:18",
    "runs:1100000:19",
    "text:1200000:20",
    "mix:1300000:21",
    "random:1500000:22",
]

MASK = 0xFFFFFFFF


class Xorshift:
    """The 32-bit xorshift generator of Marsaglia, with the shifts 13, 17 and 5."""

    def __init__(self, seed: int) -> None:
        """Start from a seed, which must not be zero."""
        self.state = seed & MASK

    def next(self) -> int:
        """Return the next 32 bits."""
        x = self.state
        x ^= (x << 13) & MASK
        x ^= x >> 17
        x ^= (x << 5) & MASK
        self.state = x
        return x

    def below(self, limit: int) -> int:
        """Return a number below the limit."""
        return self.next() % limit


def random_bytes(rng: Xorshift, length: int) -> bytearray:
    """Return bytes of the generator: each output gives four, the lowest first."""
    out = bytearray()
    while len(out) < length:
        out += rng.next().to_bytes(4, "little")
    del out[length:]
    return out


def text(rng: Xorshift, length: int) -> bytearray:
    """Return words of the list: one in sixteen ends a sentence, one in sixteen has a comma after it."""
    out = bytearray()
    while len(out) < length:
        out += WORDS[rng.below(len(WORDS))].encode()
        mark = rng.below(16)
        out += b".\n" if mark == 0 else b", " if mark == 1 else b" "
    del out[length:]
    return out


def repeat(rng: Xorshift, length: int, period: int) -> bytearray:
    """Return random bytes of the length of the period, over and over."""
    unit = random_bytes(rng, period)
    out = unit * (length // period + 1)
    del out[length:]
    return out


def runs(rng: Xorshift, length: int) -> bytearray:
    """Return runs of one of four letters."""
    out = bytearray()
    while len(out) < length:
        letter = 0x61 + rng.below(4)
        out += bytes([letter]) * (1 + rng.below(700))
    del out[length:]
    return out


def binary(rng: Xorshift, length: int) -> bytearray:
    """Return records of 16 bytes, as a table in a binary file has them."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += counter.to_bytes(4, "little")
        out += (rng.next() & 0x3FF).to_bytes(2, "little")
        out += b"\x00\x00"
        out += (rng.next() & 0x0F0F0F0F).to_bytes(4, "little")
        out += b"\x01\x00\x00\x80"
        counter += 1
    del out[length:]
    return out


def copies(rng: Xorshift, length: int, out: bytearray | None = None) -> bytearray:
    """Append at least the given length to the output, and return it: one to five random bytes, then 10 to 199 bytes that the output already has."""
    out = bytearray() if out is None else out
    target = len(out) + length
    while len(out) < target:
        for _ in range(1 + rng.below(5)):
            out.append(rng.next() & 0xFF)
        back = rng.below(len(out))
        out += bytes(out[back : back + 10 + rng.below(190)])
    return out


def mix(rng: Xorshift, length: int) -> bytearray:
    """Return stretches of the other kinds."""
    out = bytearray()
    while len(out) < length:
        kind = rng.below(5)
        stretch = 1 + rng.below(60000)
        match kind:
            case 0:
                out += random_bytes(rng, stretch)
            case 1:
                out += text(rng, stretch)
            case 2:
                out += bytes([rng.next() & 0xFF]) * stretch
            case 3:
                out += repeat(rng, stretch, 1 + rng.below(300))
            case _:
                copies(rng, stretch, out)
    del out[length:]
    return out


def fib(rng: Xorshift) -> bytearray:
    """Return 21 byte values whose counts are the Fibonacci numbers, shuffled, six times.

    A Huffman tree of such counts is deeper than the 15 bits a code may have, which the
    packers handle by a rule of their own.
    """
    block = bytearray()
    count, following = 1, 1
    for value in range(21):
        block += bytes([value * 7 + 3]) * count
        count, following = following, count + following
    for i in range(len(block) - 1, 0, -1):
        j = rng.below(i + 1)
        block[i], block[j] = block[j], block[i]
    return block * 6


# The generators that take a length and a seed, by the kind they make.
SEEDED: dict[str, Callable[[Xorshift, int], bytearray]] = {
    "random": random_bytes,
    "text": text,
    "runs": runs,
    "binary": binary,
    "copies": copies,
    "mix": mix,
}


def make(name: str) -> bytes:
    """Return the input of a name."""
    kind, _, rest = name.partition(":")
    numbers = (
        [int(part) for part in rest.split(":")] if kind not in {"empty", "file"} else []
    )
    match kind:
        case "empty":
            out = bytearray()
        case "file":
            out = bytearray((ROOT / rest).read_bytes())
        case "zeros":
            out = bytearray(numbers[0])
        case "fib":
            out = fib(Xorshift(numbers[0]))
        case "repeat":
            out = repeat(Xorshift(numbers[1]), numbers[0], numbers[2])
        case _ if kind in SEEDED:
            out = SEEDED[kind](Xorshift(numbers[1]), numbers[0])[: numbers[0]]
        case _:
            message = f"unknown input: {name}"
            raise ValueError(message)
    return bytes(out)
