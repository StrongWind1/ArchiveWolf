# archivewolf-zip-crypto

The cipher of ZIP traditional encryption (`zip-crypto`) and the key search of the known-plaintext attack of Biham and Kocher on it: the three keys and their update in both directions, the reduction of the candidates for the third key, and four kernels that search one candidate and answer alike. With them, the way from three keys back to every password of six bytes or fewer that gives them, which is worked out and not searched.

It is the part of `archivewolf attack zip-crypto` that has to be fast, and it knows nothing of archives. It is a crate of its own because a vector kernel is entered through a call the compiler cannot check, which ArchiveWolf itself forbids, and so that it is built with optimisation in every profile.

| Kernel | What it is |
|---|---|
| `reference` | The search of bkcrack as it is written there, one list at a time. The others are tested against it |
| `scalar` | The same search as flat loops over arrays, with one table that gives the byte that fits. Runs on every processor |
| `avx2` | The flat loops eight lists at a time, for a processor with AVX2 |
| `avx512` | The flat loops sixteen lists at a time, for a processor with AVX-512 (F, BW, DQ, VL) and BMI2 |

Which of the two vector kernels is the faster depends on the processor, so a caller that has the time measures both: `Kernel::vector()` lists the ones the processor runs. On the machine they were written on, with all sixteen threads busy, the scalar kernel searches about 5,000 candidates a second, `avx2` about 13,000 and `avx512` about 19,000 (`cargo run --release --example speed`).

The reduction and the reference kernel are a port of bkcrack-rs by Zach Shallbetter, itself a port of bkcrack by Joachim Hotonnier, and the way from keys back to a password is a port of bkcrack. Both are under the zlib licence (`LICENSE-BKCRACK.txt`). The rest is under Apache-2.0 (`LICENSE`).
