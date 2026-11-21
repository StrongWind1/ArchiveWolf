# Test Fixtures

The fixtures are archives, sorted into directories by what they hold. Most were written by the original tools. The ones called synthetic, and the `gen_own_*` and `gen_ses_*` files, were built for cases no archiver writes.

Passwords are in `passwords.json`, under the path of the fixture below `tests/fixtures/`. ArchiveWolf takes no password and tests none: a password is recorded so that an archive tool can open the fixture, and so that `make test-hashcat` can crack its line. Where this file names a password, it is the one in `passwords.json`.

The columns `info` and `hash` say what the binary printed for a fixture on 2026-11-19, in its own words. For any fixture:

```sh
archivewolf info --entries tests/fixtures/zip-crypto/zipcrypto.zip
archivewolf hash tests/fixtures/zip-crypto/zipcrypto.zip
archivewolf hash --all tests/fixtures/zip-crypto/zipcrypto.zip
```

In the tables, `exact`, `structural` and `weak` are what `info` says a line proves, and a word in brackets such as `[no-mode]` is the reason `hash` gives on standard error for a line that is missing.

This file names the fixtures whose origin or purpose is recorded. The directories hold more, and `passwords.json` has the passwords of those as well.

## Directories

| Directory | Holds | `info` | `hash` |
|---|---|---|---|
| `zip-crypto/` | ZIP traditional encryption (ZipCrypto) | scheme `zip-crypto`, finding `zip-crypto falls without the password to 12 bytes of known plaintext` | `$zip$1$`, mode 46100 |
| `zip-winzip/` | ZIP with WinZip AES | scheme `zip-winzip`, with the key size and `ae1` or `ae2` in the variant | `$zip$2$`, mode 46200 |
| `zip-pkware/` | ZIP with PKWARE strong encryption, AES and a password | scheme `zip-pkware`, variants `zip-pkware:data:aes128:password` to `aes256` | `$zip$3$`, mode 46300, 46310 or 46320 by key size |
| `pseudo/` | ZIP entries that are marked encrypted and are not | `pseudo-encrypted`, `hash none: nothing is encrypted` | no line, `archivewolf: no hash lines` |
| `rar-13/` | RAR 1.3 and 1.4 with a password | scheme `rar-13`, `hash none` | no line, `[no-mode]`. `attack rar-13` recovers the key |
| `rar-15/` | RAR 1.5 | scheme `rar-15` | `$rar$15$`, mode 46500 |
| `rar-20/` | RAR 2.0 | scheme `rar-20` | `$rar$20$`, mode 46600 |
| `rar-30/` | RAR 3.x to 4.x | scheme `rar-30`, variants `rar-30:data` and `rar-30:headers` | `$rar$30$`, mode 46700 |
| `rar-50/` | RAR 5 and 7 | scheme `rar-50`, variants of `rar-50:data` and `rar-50:headers` | `$rar$50$`, mode 46800 |
| `7z-aes/` | 7-Zip | scheme `7z-aes` | `$7z$*`, mode 46900. Four fixtures have no line |
| `unencrypted/` | ZIP, RAR and 7-Zip archives with nothing encrypted | `coverage none`, `hash none: nothing is encrypted` | no line |
| `unknown-pw/` | Encrypted archives without a recorded password, and edge cases | by fixture, see below | by fixture |
| `unparseable/` | Damaged archives, later volumes, and two ZIP files that parse | by fixture, see below | by fixture |
| `regress/f3-tools/` | RAR 5 and 7-Zip archives built for regression tests: two entries of one name, names that differ in a backslash, entries under passwords of their own | `rar-50` and `7z-aes` | `$rar$50$` and `$7z$*`; with `--all`, a line for each encrypted entry or folder |

## ZIP

### `zip-crypto/`, made by hand

| Fixture | Password | Created with | `info` | `hash` |
|---|---|---|---|---|
| `zipcrypto.zip` | `testpass` | `zip -e` | `1 of 1 entry encrypted; coverage all` | `$zip$1$`, exact, with the note that a stored entry alone is confirmed by 40 bits |
| `zipcrypto_deflate.zip` | `deflpass` | `zip -e` | `2 of 2 entries encrypted` | `$zip$1$`, exact |
| `zipcrypto_stored.zip` | `bktest` | `zip -e -0` | `3 of 3 entries encrypted` | `$zip$1$`, exact, from `plain.txt` |
| `zipcrypto_sfx.zip` | `bktest` | `zip -e -0` and a program in front | `ZIP, 3 entries, at offset 512` | `$zip$1$`, exact |
| `zipcrypto_datadesc.zip` | not known (`a$` passes only the check byte) | `zip -e` (bit 3 set) | `1 of 1 entry encrypted` | `$zip$1$`, exact. The check byte comes from the file time |
| `multi_stored.zip` | `multipass` | `zip -e -0` | `3 of 3 entries encrypted` | `$zip$1$`, exact, from `multi3.txt`, with the checks of all three headers |
| `nested.zip` | `nested` | `zip -e -0` | `1 of 1 entry encrypted`: `inner.zip` is one entry | `$zip$1$`, exact |
| `commented.zip` | `comment` | `zip -z -e -0` | a `comment` row: `This is a test comment` | `$zip$1$`, exact |
| `mixed.zip` | `mixpass` | `zip` | `1 of 2 entries encrypted; coverage some`, and the finding that the others are not | `$zip$1$`, exact, from `tiny.txt` |

### ZIP passwords corrected on 2026-11-14

`passwords.json` held 22 passwords for `zip-crypto/` fixtures that passed the one-byte header check and nothing else: 7-Zip rejects every one of them. They had come out of a cracking run whose hash line tested only that byte, where one wrong password in 256 passes. With a line that tests the data, 15 archives gave up their real password to `rockyou.txt` and short masks (hashcat mode 46100), and each was confirmed by unpacking: `7z.zip` `password`, `archivec.zip` `orange`, `bruteforce-6char.zip` `zzzzzz`, `bruteforce-7char.zip` `zzzzzzz`, `bruteforce-8char.zip` `zzzzzzzz`, `bruteforce_max_length.zip` `abcdefghijklmnop`, `bruteforce_mixed_methods.zip` `mix`, `bruteforce_one_char.zip` `a`, `bruteforce_special_chars.zip` `!?`, `noradi.zip` `noradi`, `stored.zip` `pass`, `test.zip` `yamaha`, `test05.zip` `123123`, `test_zyx.zip` `zyx`, `zip64.zip` `noradi`. Seven have no known password and no entry in `passwords.json`: `C.zip`, `mask_options.zip`, `pay.zip`, `perfdata_ctext.zip`, `test03.zip`, `test04.zip`, `zipcrypto_datadesc.zip`.

### ZIP fixtures generated for the hash formats (`gen_*.zip`)

Passwords are in `passwords.json`. `infozip_*` were written by Info-ZIP `zip 3.0`, `7z_*` by `7zz a -tzip`, and `own_*` and `ses_*` by the generator of the hashcat test modules (`tools/test_modules/lib/zip_traditional.py`, `zip_strong.py`), for the cases neither tool produces. Every `ses_*` archive was read back with `7zz t`.

| Directory | Fixtures | What they cover | `hash` |
|---|---|---|---|
| `zip-crypto/` | `gen_infozip_{store,deflate,bzip2,stream,zip64,tiny,store_multi}.zip` | Info-ZIP: stored, deflate, bzip2, data descriptor from a pipe, forced ZIP64, a two-byte file, two stored entries | `$zip$1$`: exact, but structural for `bzip2` and weak (24 bits) for `tiny` |
| `zip-crypto/` | `gen_7z_zipcrypto_{copy,deflate,deflate64,bzip2,lzma,ppmd,xz}.zip` | 7-Zip: every compression method it writes with traditional encryption | `$zip$1$`: exact for `copy` and `deflate`, structural for `bzip2` and `xz`, weak (8 bits) for `deflate64`, `lzma` and `ppmd`, for which hashcat has no decoder |
| `zip-crypto/` | `gen_7z_zipcrypto_pw_{long70,space,special}.zip` | 70-character password, a space, `:*$` | `$zip$1$`, exact |
| `zip-crypto/` | `gen_own_zc_{stored,deflate,bzip2,lzma,zstd,xz}.zip` | One method each, including zstd (93) and xz (95) | `$zip$1$`: exact for `stored` and `deflate`, structural for `bzip2` and `xz`, weak (8 bits) for `lzma` and `zstd` |
| `zip-crypto/` | `gen_own_zc_datadesc.zip`, `gen_own_zc_datadesc_stored.zip` | Check byte from the file time | `$zip$1$`, exact |
| `zip-crypto/` | `gen_own_zc_pkzip1_twobyte.zip` | Made-by version 1.0 and 1.1: the only case with two check bytes. `info` says `check bytes 16 bits` | `$zip$1$`, exact |
| `zip-crypto/` | `gen_own_zc_eight_stored.zip` | Ten stored entries: the line carries eight headers | one `$zip$1$*8*` line; ten lines with `--all` |
| `zip-crypto/` | `gen_own_zc_two_passwords.zip`, `gen_own_zc_two_passwords_deflate.zip` | `first.txt` is `own-first`, `second.txt` is `own-second` | one `$zip$1$` line; a line for each entry with `--all` |
| `zip-crypto/` | `gen_own_zc_deflate_tiny.zip`, `gen_own_zc_stored_1byte.zip`, `gen_own_zc_long_password.zip` | One-byte files, a 200-character password | `$zip$1$`: exact, but weak (16 bits) for `stored_1byte` |
| `zip-crypto/` | `gen_infozip_did_not_pack.zip` | Info-ZIP on data that does not pack: `noise.bin`, 40,000 bytes of a fixed xorshift generator (seed 2026, the one `tests/zip_crypto_attack_test.rs` runs), written as Deflate in two stored blocks. The two sizes show it: the stream is ten bytes longer than the file. Made with `zip -X -e -P own-noise` | `$zip$1$`, exact |
| `pseudo/` | `gen_infozip_empty.zip`, `gen_own_zc_empty_only.zip` | Empty files behind an encryption header: a header and no data. `info` reports the entries as `encrypted`: an empty entry proves nothing either way | `$zip$1$`, weak: the line tests the check byte of the header |
| `zip-winzip/` | `gen_7z_aes128_{copy,deflate}.zip`, `gen_7z_aes192_deflate.zip`, `gen_7z_aes256_{deflate,deflate64,bzip2,lzma,ppmd,xz,empty,tiny}.zip` | 7-Zip: three key sizes, every method, an empty and a two-byte file | `$zip$2$`, exact |
| `zip-winzip/` | `gen_7z_aes256_pw_{long70,special}.zip`, `gen_own_aes256_long_password.zip` | Long and special passwords (200 characters is past one HMAC block) | `$zip$2$`, exact |
| `zip-winzip/` | `gen_own_aes128_ae1.zip`, `gen_own_aes192_ae2_stored.zip`, `gen_own_aes256_{empty,zstd,two_passwords}.zip` | AE-1 with CRC, AE-2 stored, zstd, two passwords | `$zip$2$`, exact; two lines for `two_passwords` with `--all` |
| `zip-winzip/` | `gen_own_mixed_zc_aes.zip` | One traditional and one AES entry. `info` says `schemes   mixed` | two lines: `$zip$1$` and `$zip$2$` |
| `zip-pkware/` | `gen_ses_aes{128,192,256}_{iv,noiv}_{deflate,stored}.zip` | Strong encryption, three key sizes, with a stored vector and with the CRC-32 and size standing in for it | `$zip$3$`, exact, mode 46300, 46310 or 46320 |

### ZIP fixtures for the header paths of `attack zip-crypto`

The archives of `zip-crypto/` in the table below: all but one have encryption headers that were not filled from a generator nobody can predict, and `gen_sharpziplib_net9.zip` is the control. Each was written by the real program or library, on 2026-11-20 or 2026-11-21, and was opened with its password by Python's `zipfile`. The tests of `src/attack/zip_crypto/seed/` hold the twelve header bytes of every entry of each, with the seed and the keys below. For every one of them `info` says `zip-crypto:check8` with all entries encrypted, and `hash` gives one `$zip$1$` line, exact.

| Fixture | Password | Created with | What its headers give |
|---|---|---|---|
| `gen_infozip_six.zip` | `six-headers` | `zip -e -P six-headers` of Info-ZIP 3.0 on Linux with glibc 2.41, on six text files of 6 to 80 bytes: two stored, four deflated | The seed of `rand()`, 1,795,889,087: the time the archive was written at, 1,795,212,702, exclusive-or the process number 774,689. The keys after the password are `b4fd7fc8 9cc4f2bc 92c95100` |
| `gen_infozip_four.zip` | `four-headers` | The same in the same second, on four text files of 6 to 80 bytes: two stored, two deflated | The seed 1,795,889,082: the same time, exclusive-or the process number 774,692. Keys `9309413d 76dafb18 09f0cd24` |
| `gen_infozip_musl.zip` | `musl-headers` | `zip -e -P musl-headers` of Info-ZIP 3.0, built from `zip30.tar.gz` with `musl-gcc` against musl 1.2.5, on six text files of 6 to 80 bytes: one stored, five deflated. The build sets the flags by hand (`-DUNIX -DUIDGID_NOT_16BIT -DLARGE_FILE_SUPPORT -DUNICODE_SUPPORT -DHAVE_DIRENT_H -DHAVE_TERMIOS_H -std=gnu89`), because the probes of `unix/configure` fail under GCC 14 | The seed of the `rand()` of musl, 1,797,846,278: the time the archive was written at, exclusive-or the number of its process. Keys `c7de90d8 78871436 53aceb37` |
| `gen_infozip_win.zip` | `win-headers` | `zip.exe -e -P win-headers` of Info-ZIP 3.0 on the same six files, run on Windows Server 2022 (21H2) with its own C runtime, `msvcrt.dll` 7.0.20348. The program was built from `zip30.tar.gz` with `x86_64-w64-mingw32-gcc` and `win32/makefile.gcc` without the assembler parts. Two changes to the source that have no part in encryption: the macro `CR` of `zip.h` has another name, since the Windows headers of the compiler use that name, and `__p___mb_cur_max` is a stub that says one byte for a character | The seed of the `rand()` of the Windows runtime, 1,795,223,696: the time, exclusive-or the number of its process. Keys `dbfe37b1 3846a40b a01bd1c3`. The same program under Wine 10.0 gave an archive that falls the same way |
| `gen_minizip_glibc.zip` | `minizip-headers` | `minizip -o -p minizip-headers` of zlib 1.2.11 (`contrib/minizip`, built with GCC against glibc 2.41 and the zlib of the system) on the same six files, all deflated. It leaves no mark of its writer: made by version 0, no data descriptor, two check bytes | The seed of the `rand()` of glibc, 3,493,857,940: the time, exclusive-or the constant 3141592654 that minizip takes where `zip` takes a process number. Keys `256aa44f bff40c8d 2c7d19a0` |
| `gen_sharpziplib_net5.zip` | `Tr0ub4dor&3xyz` | SharpZipLib 1.3.0 (`ZipOutputStream`) on the .NET 5.0.17 runtime: six deflated entries. A copy of `sharp-net5.zip` of the experiment behind section 8.5 of the design | The seed of the generator of the thread, 513,587,410, with the first entry at position 0, and with it the first eleven bytes of every header before it was encrypted. Keys `9f15e5d8 956912eb fbf58431` |
| `gen_dotnetzip_net5.zip` | `Tr0ub4dor&3xyz` | DotNetZip 1.16.0 (`ZipFile.AddEntry`) on the same runtime: six deflated entries. A copy of `dnz-net5.zip` | The thread seed 2,017,255,694, position 0. The same keys |
| `gen_sharpziplib_net9.zip` | `Tr0ub4dor&3xyz` | The program of `gen_sharpziplib_net5.zip` on the .NET 9.0.22 runtime. A copy of `sharp-net9.zip` | Nothing: on that runtime a generator that is given no seed takes one from the system, and no thread seed fits. The same keys |
| `gen_sharpziplib_netfx.zip` | `sharp-on-the-framework` | SharpZipLib 1.3.0 (`ZipOutputStream`, the build of the package for .NET 4.5) on the .NET Framework 4.8 of Windows Server 2022: twenty deflated entries of one line of text repeated to 1, 2 or 3 MB, so that each entry takes the writer past a step of the clock and the archive stays small. The program was compiled there with the compiler of the Framework, and printed the tick count in front of each entry | The clock: the first entry at a count of 1,586,105,1xx milliseconds since the machine started, 18 days 8 hours. 17 groups of entries with one header each. Keys `39a18f95 31f4b9ff 5ee38f6b` |
| `gen_dotnetzip_netfx.zip` | `dotnetzip-on-the-framework` | DotNetZip 1.16.0 (`Ionic.Zip.ZipFile`, the build of the package for .NET 4.0) on the same machine by the same program: 24 entries of the same kind | The same clock, some hundred milliseconds on. 17 groups. Keys `a907bbe9 8d79aaa6 f1112924` |
| `gen_doublecmd_first.zip`, `gen_doublecmd_second.zip` | `doublecmd-headers` | The zip plugin of Double Commander 1.1.22 as Debian builds it (`zip.wcx` of the package `doublecmd-plugins` 1.1.22-1, Abbrevia on Free Pascal 3.2.2), called as Double Commander calls it: `PackFilesW` with `PK_PACK_ENCRYPT`, by a small program that loads the plugin and gives the password where the plugin asks for it. Two archives of six text files each, written one after the other in one load of the plugin | The plugin never seeds the generator of Free Pascal, so its headers are one sequence, the same on every machine: the first archive has the first six headers of it and the second the next six. Keys `f7419951 8d4ec2f6 8c6d298e` |
| `gen_ziparchive_glibc.zip` | `ziparchive-on-glibc` | The `ZipArchive` library of Artpol 4.6.2 (`CZipArchive::AddNewFile` at level 6, after `SetPassword`), built with `g++` 14.2 against glibc 2.41, its own zlib built as C: fourteen text files of numbered lines, 14 to 31 KB, one added every 1.1 seconds by a small program that printed `time(NULL)` in front of each. The source is the copy of the library in the repository `in7egral/taig_kycompress`, with the four signatures of the archive format set back to the standard ones, which stand as comments beside what that project put in their place | The clock: the library seeds `rand()` with the time for every entry, and the first entry was written at second 1,795,236,980. 14 groups of one entry each, with one second in which none was started. Keys `33a016bd 922954b8 d84dd431` |
| `gen_ziparchive_win.zip` | `ziparchive-on-windows` | The same library and program, built with `x86_64-w64-mingw32-g++` 14 and run on Windows Server 2022 (21H2) with its own C runtime, on the same fourteen files | The first entry at second 1,795,232,739, five hours after the time its entries carry, which is that of a clock five hours behind UTC. 14 groups: twelve start with one byte and two with the next, since the first value of that generator moves by one in twenty seconds. Its directory carries the marks of `yeka/zip` (made by 2.0 on FAT, a data descriptor, no extra field), and its headers take them back. Keys `a58fee66 7537c576 97a0f4e6` |
| `gen_ziputils_win.zip` | `ziputils-on-windows` | zip utils of Lucian Wischik (`CreateZip` with a password, `ZipAdd`), the `zip.cpp` that 45 repositories carry unchanged, here from `netease-kit/NIM_PC_Demo`, built with `x86_64-w64-mingw32-g++` 14 and run on Windows Server 2022 by a remote command, in the session of a service: sixteen entries of one line of text repeated to 0.6 to 3 MB, so that the entries fall into several steps of the clock and the archive stays small. The program printed `GetTickCount()` and `GetDesktopWindow()` in front of each entry | Seven groups of one to three entries with one header each, at seven interrupts of the timer in a row: counts of 1,595,078,078 to 1,595,078,171 milliseconds, 18 days 11 hours. The handle of the desktop window in that session was `03C20044`, not the `00010010` of the desktop a user works at: the command finds no clock for it and says so, and the tests of the generator give it the handle. Keys `97536406 5a1e52dd cbbfb588` |
| `gen_ziputils_session.zip` | `ziputils-in-a-session` | The program and the sixteen files of `gen_ziputils_win.zip`, on 2026-11-21 on the same machine, started in the session of the user who was logged on at its console, by a task of the scheduler that ran once and was removed. It printed `GetTickCount()` and `GetDesktopWindow()` in front of each entry | Ten groups of one to three entries. The handle of the desktop window was `00010010`, the one the command searches with, and so it was on a second machine with Windows Server 2022: the command finds the clock, a count of 1,599,332,093 milliseconds at the first entry, 18 days 12 hours. Keys `3f4c1976 0ec2f912 500ad85e` |
| `gen_infozip_official.zip` | `zip-official32-headers` | `zip.exe -X -e -P` of Zip 3.0 as Info-ZIP gave it out for Windows in 32 bits (`zip300xn.zip`, SHA-256 `f8bbc1821d50400245107ce8cfa4a6c7b524387b58bbd6cbe9c20094e82c3bb5`, built with Visual C++ 6.0 with the runtime inside the program), on Windows Server 2022, on the six files of `gen_infozip_six.zip` | The seed of the `rand()` of the Windows runtime, 1,795,283,964: the time 1,795,282,864, exclusive-or the process number 3148, both as the program that started it wrote them down. Keys `3320b31b 4885c587 2cd08312`. The build in 64 bits, those of GnuWin32 and of MinGW gave archives that fall the same way |
| `gen_infozip_cygwin.zip` | `zip-cygwin-headers` | The same with the `zip.exe` of Cygwin (`zip-3.0-13`, with `cygwin1.dll` 3.6.12 beside it and nothing else of Cygwin on the machine) | The seed 1,795,281,026 of the generator of glibc, which the `rand()` of Cygwin is: the time 1,795,282,905, exclusive-or 1883, the process number as Cygwin counts it. Keys `6f85a779 fba3ad95 2f09892c`. The `zip.exe` of MSYS2 gave an archive that falls the same way |
| `gen_winrar_723.zip` | `winrar-headers` | `WinRAR.exe a -afzip -ibck -inul -mezl -p` of WinRAR 7.23 (64 bits) on Windows Server 2022, on the same six files: `-mezl` is its switch for ZIP legacy encryption. It names version 3.1 as its own and writes a data descriptor behind each entry | The header of Info-ZIP, whose code WinRAR carries. The seed of the `rand()` of the Windows runtime, 1,795,280,570: the time 1,795,283,874, exclusive-or the process number 5400. Keys `1869cbd8 c344cb2a d916d172`. Versions 4.20, 5.01, 5.21, 5.71, 6.02 and 7.01 gave archives that fall the same way; 5.50 and 5.61 wrote AES under the same command |
| `gen_winrar_290.zip` | `winrar-headers` | The same command without `-mezl`, which it does not know, by the `WinRAR.exe` of version 2.90, unpacked from its installer and run from a folder. It names version 2.0 | The seed 1,795,277,858 of the `rand()` of the Borland runtime, which that version was built with: the time 1,795,284,070, exclusive-or the process number 6212. Version 3.00 gave an archive that falls the same way. The same keys |
| `gen_winrar_320.zip` | `winrar-headers` | The same by version 3.20 | The same generator from the seed 1,795,279,794, the time 1,795,284,070 exclusive-or the process number 6100, with each byte put through the table of the CRC-32 before it is encrypted, as that version does. The same keys. Versions 3.51 to 4.01 take their header bytes from a hash of the tick count and the time, encrypt them once, and are not reached |
| `gen_aspose_net5.zip` | `aspose-headers` | Aspose.ZIP 24.6.0 (`Archive` with `TraditionalEncryptionSettings`, the build of the package for .NET Standard 2.0) on the .NET 5.0.17 runtime on Windows Server 2022, on sixteen text files of 14 to 33 KB. The library ran without a licence: it wrote ten of them and put a comment into the archive that says so | The seed of the generator of the thread, 1,278,361,627, with one generator made before the first entry: the library makes a `new Random()` for every entry, as DotNetZip does, and ends the header with the high byte of the time. Keys `63f0b5bd 73c967af b7fe3ec1`. It leaves no mark of its own in the directory |
| `gen_c1zip_net8.zip` | `c1-headers` | The zip library of ComponentOne, `C1.Zip` 8.0.20241.6 (`C1ZipFile.Entries.Add` after `Password` was set), on the .NET 8.0.34 runtime on Windows Server 2022, on the same sixteen files | The library makes a `new Random(DateTime.Now.Millisecond)` for every entry: every header is one of a thousand. Sixteen groups of one entry each, the first at millisecond 997. Keys `1e96a16e 339c589e 41f3f92a`. Archives of the same program on .NET 10 on Linux and on the .NET Framework 4.8 fall the same way |
| `gen_yeka_a.zip`, `gen_yeka_b.zip` | `Tr0ub4dor&3xyz` | `github.com/yeka/zip` at `03d6312`: five deflated entries, with the times 12:00:00, 12:01:02 and so on. Copies of `yeka-a.zip` and `yeka-b.zip` | The constant header of the library: the first ten bytes of every header of both archives are `f85160718ebf1818a9d8`. The same keys |
| `gen_yeka_c.zip` | `other-password` | The same. A copy of `yeka-c.zip` | The first ten bytes of every header are `f8f521076505689d75a5`. Keys `efd79102 bc1dce1f f4741427` |

### Other ZIP fixtures

| Fixture | Password | Created with | `info` | `hash` |
|---|---|---|---|---|
| `zip-winzip/winzip_aes256.zip` | `aespass` | `7zz -mem=AES256` | `zip-winzip:256:ae2  AE-2, AES-256` | `$zip$2$`, exact |
| `zip-winzip/winzip_aes128.zip` | `aes128pw` | `7zz -mem=AES128` | `zip-winzip:128:ae2  AE-2, AES-128` | `$zip$2$`, exact |
| `pseudo/pseudo.zip` | none | `zip` and an edit of the flag | `none of 1 entry encrypted, 1 pseudo-encrypted; coverage none` | no line |
| `unencrypted/empty.zip` | none | `zip` | `none of 1 entry encrypted; coverage none` | no line |
| `unparseable/crc_tiny.zip` | `crctest` | `zip -e -0` | `3 of 3 entries encrypted`: files of 2, 3 and 5 bytes | `$zip$1$`, exact, from `four.txt`. With `--all`, three lines, the two from the smaller files weak |
| `unparseable/multidisk_stub.zip` | none recorded | synthetic | `ZIP, later volume of a set, 1 entry`, `1 of 1 entry encrypted` | `$zip$1$`, exact |
| `unknown-pw/edge_zip-forensic_securezip-strong-signed.zip` | none: certificates | from the zip-forensic collection | `zip-pkware:data:aes256:certificate`, finding `encrypted to certificates: no password opens it` | no line, `[no-password]` |
| `unknown-pw/zip-forensic_securezip-strong-aes256-pw.zip` | not known | PKWARE SecureZIP, from the zip-forensic collection | `zip-pkware:data:aes256:password  AES-256` | `$zip$3$`, exact, mode 46320 |

## RAR

### RAR 1.4 comments (`unencrypted/`)

| Fixture | What it is | `info` |
|---|---|---|
| `rar14_with_comment.rar` | Synthetic. The comment bytes are plain text, as the format stores them without `MHD_PACK_COMMENT` | `none of 1 entry encrypted`, and the row `comment   ArchiveWolf RAR 1.4 test comment` |
| `rar14_packed_comment.rar` | From the `rars` test corpus. The comment is packed (`MHD_PACK_COMMENT`, fixed key `{0, 7, 77}` and Unpack15) | `none of 1 entry encrypted`, and the row `comment   This is the archive comment.` |

### `rar-13/` (password `password`)

`info` reports the scheme `rar-13`, the finding ``rar-13 falls without the password: `attack rar-13` searches its 2^23 keys``, `hash none` and the reason `no-mode`. `hash` writes no line. `attack rar-13 FIXTURE -o FILE` prints `KEY RECOVERED: RAR 1.3 key = 73 1f 3d` for each of them and writes the decrypted copy to `FILE`.

| Fixture | Entries | Time of `attack rar-13` on 16 cores | Tested in |
|---|---|---|---|
| `rar14-password-stored.rar` | One stored entry of 87 bytes | under a second | the default test run |
| `edge_rars_STOREPWD.RAR` | One stored entry of 27 bytes | under a second | the default test run |
| `rar14-password-compressed.rar` | One compressed entry, 83 bytes packed | under a second | the default test run |
| `README_password=password.rar` | One compressed entry, 1 KB packed | about half a minute | `make test-rar-13` |
| `rar14-solid-password.rar` | Three entries in a solid archive, the first 12 KB packed. One key for all three | about five minutes | `make test-rar-13` |

### `rar-15/` and `rar-20/` (password `password`)

| Fixture | From | `hash` |
|---|---|---|
| `rar-15/rar15-password-stored.rar`, `rar-15/rar15-password-compressed.rar` | junrar test suite | `$rar$15$`, exact |
| `rar-20/rar20-password-stored.rar`, `rar-20/rar20-password-compressed.rar` | junrar test suite | `$rar$20$`, exact |
| `rar-15/rars_service_block_stored.rar` | Written by the `rars` tool, which puts a service block (`RARS`, `LONG_BLOCK`) before the file header; the walker has to skip its data | `$rar$15$`, exact, method field `30` |
| `rar-15/rars_service_block_m3.rar` | The same, 40 KB of text | `$rar$15$`, exact, method field `33` |
| `rar-20/rars_service_block_stored.rar` | The same for RAR 2.0 | `$rar$20$`, exact, method field `30` |
| `rar-20/rars_service_block_m5.rar` | The same, 40 KB of text | `$rar$20$`, exact, method field `35` |

`rar-15/rars_rar3_encrypted.rar` (password `pass`) and `rar-15/readme_154_password.rar` also give a `$rar$15$` line.

### `rar-30/` and `rar-50/`, generated with RAR

The files named `vNNN_*` were written by the RAR binaries of versions 3.00, 4.20, 5.00, 5.21, 7.00 and 7.30 beta 2, with the password `gutenberg`. The name gives the version and the switches: `p` for `-p` (entries encrypted), `hp` for `-hp` (headers encrypted), `m0` to `m5` for the compression, `ma4` for the RAR 4 format written by RAR 5.00, and `sfx`, `solid`, `blake2sp` (`-htb`) and `qo` (`-qo+`).

| Fixtures | `info` | `hash` |
|---|---|---|
| `rar-30/v*_p_*` | `rar-30:data  AES-128, SHA-1 2^18, CRC-32` | `$rar$30$*1*`, exact |
| `rar-30/v*_hp_*` | `headers   encrypted: names and sizes hidden`, `rar-30:headers  AES-128, SHA-1 2^18, structure` | `$rar$30$*0*`, structural, from the headers |
| `rar-50/v*_p_*` | `rar-50:data:check:keyed  AES-256, PBKDF2-HMAC-SHA256 2^15, check value 64 bits`, with `keyed CRC-32` or `keyed BLAKE2sp` | `$rar$50$*0*`, exact |
| `rar-50/v*_hp_*` | `headers   encrypted: names and sizes hidden`, `rar-50:headers:check  AES-256, PBKDF2-HMAC-SHA256 2^15, check value 64 bits` | `$rar$50$*0*`, exact, from the headers |
| `rar-30/v420_*_sfx.sfx`, `rar-50/v730_*_sfx.sfx` | the same as without the program, and `at offset 244864` | the same line type |

### `rar-50/` without a check value (password `gutenberg`)

Made by `rar`, then the check value (and for `crc` and `b2` the flag of the keyed checksum) removed from the header; `unrar t` accepts each.

| Fixtures | What they are | `hash` |
|---|---|---|
| `nocheck_st_{crc,crcmac,b2,b2mac}.rar` | A stored entry | `$rar$50$*1*`, exact, with check type 0, 1, 2 and 3 |
| `nocheck_m3_{crc,crcmac,b2,b2mac}.rar`, `nocheck_m5_exe_crcmac.rar` | A compressed entry; the m5 one is an executable with E8 filters | `$rar$50$*1*`, exact, with check type 0, 1, 2 and 3 |
| `nocheck_hp_m0.rar`, `nocheck_hp_m3.rar` | Encrypted headers without a check value. `info` says `rar-50:headers:nocheck  AES-256, PBKDF2-HMAC-SHA256 2^15, structure` | `$rar$50$*1*`, structural, from the headers, with check type 4 |
| `synth_type1_blake2sp.rar`, `synth_type1_hashmac.rar` | Synthetic, no password recorded | `$rar$50$*1*`, exact |

### Other encrypted RAR fixtures

| Fixture | Password | What it is | `hash` |
|---|---|---|---|
| `rar-30/rar3-nonascii-password.rar` | `пароль密码ü` | Encrypted headers (`-hp`) | `$rar$30$*0*`, structural, from the headers |
| `rar-30/bad-crc-enc-headers.rar` | not known | Encrypted headers (`-hp`) | `$rar$30$*0*`, structural, from the headers |
| `rar-30/rars_rar4_mixed_visible_names_password.rar` | `known-pass` | `2 of 3 entries encrypted; coverage some` | `$rar$30$*1*`, exact |
| `rar-50/rar5-nonascii-password.rar` | `пароль密码ü` | Encrypted headers (`-hp`) | `$rar$50$*0*`, exact, from the headers |
| `unknown-pw/edge_rars_comment_psw.rar` | not known | RAR 2.0, two entries | `$rar$20$`, exact |
| `unknown-pw/edge_rarpar_test_read_format_rar5_only_crypt_exfld.rar` | not known | RAR 5 with 2^6 rounds and no check value, and packed data that is not whole cipher blocks | no line, `[damaged]`: mode 46800 refuses such data |
| `unknown-pw/edge_rars_ESPLIT.RAR`, `unknown-pw/edge_rarpar_test_read_format_rar_ppmd_use_after_free.rar` | not known | `info` reports the scheme `rar-13` | no line, `[no-mode]` |
| `unknown-pw/edge_rars_split-encrypted.rar`, `unknown-pw/edge_arca_encrypted_multivol_rar300.rar`, `unknown-pw/edge_rars_encrypted_newnaming_rar300.part01.rar` | not known | The encrypted entry continues in another volume | no line, `[split]` |

### Two passwords in one archive

| Fixture | Format | Members | `hash` |
|---|---|---|---|
| `rar-30/ttzip-core_test_read_format_rar4_encrypted.rar` | RAR 4.x | `b.txt` password `password`, `d.txt` password `password2`, `a.txt` and `c.txt` not encrypted | one `$rar$30$*1*` line, from `b.txt`. Two with `--all`, one for each password. `info` counts `2 key groups` |
| `rar-50/ttzip-core_test_read_format_rar5_encrypted.rar` | RAR 5.x | Same layout and passwords | one `$rar$50$*0*` line, from `b.txt`. Two with `--all` |

`passwords.json` holds one password for each archive, so it lists `password`. The second one was not documented by the source of these files (libarchive's test suite); it was recovered with hashcat mode 46700 and a wordlist, and `unrar t -ppassword2` confirms it for `d.txt` in both archives.

### Not encrypted and not readable

`unencrypted/` holds RAR 1.4, 3.x, 4.x, 5.x and 7.0 archives from the junrar test suite and other collections, with various compression methods, solid archives, volumes, Unicode names, audio filters, PPM, delta and BCJ. For each, `info` reports `coverage none` and `hash none: nothing is encrypted`.

`unparseable/` holds damaged RAR files, later volumes of RAR sets, and the two ZIP files of the table under "Other ZIP fixtures". In a walk of the directory, `info` reports every later volume as `later volume of a set` with nothing encrypted, the damaged RAR files it can read as archives with nothing encrypted or as `incomplete`, and three files as parse errors (`corrupt-header.rar`, `loop.rar`, `loop2.rar`), so the walk exits with status 2. None of them makes the tool panic.

## 7-Zip (`7z-aes/`)

### Made with `7zz`, known passwords

`method` is the column of `info --entries`. A hexadecimal number in it is the identifier of a filter.

| Fixture | `method` | Password | Created with | `hash` |
|---|---|---|---|---|
| `7z_stored.7z` | `stored` | `7zpass` | `7zz -m0=Copy` | `$7z$*`, exact |
| `lzma1.7z` | `LZMA` | `lzma1pw` | `7zz -m0=LZMA` | `$7z$*`, exact |
| `7z_lzma2.7z` | `LZMA2` | `7zlzma` | `7zz -m0=LZMA2` | `$7z$*`, exact |
| `ppmd_enc.7z` | `PPMd` | `ppmdpw` | `7zz -m0=PPMD` | `$7z$*`, exact |
| `7z_bzip2_enc.7z` | `BZip2` | `bz2pass` | `7zz -m0=BZip2` | `$7z$*`, exact |
| `7z_deflate.7z` | `Deflate` | `deflpw` | `7zz -m0=Deflate` | `$7z$*`, exact |
| `7z_deflate64_enc.7z` | `Deflate64` | `defl64` | `7zz -m0=Deflate64` | `$7z$*`, exact |
| `bcj_lzma2.7z` | `LZMA2+03030103` | `bcjpass` | `7zz -mf=BCJ` | `$7z$*`, exact |
| `bcj2_enc.7z` | `LZMA+LZMA+LZMA2+0303011b` | `bcj2pw` | `7zz -mf=BCJ2` | `$7z$*`, exact, with four streams |
| `arm_enc.7z` | `LZMA2+03030501` | `armpw` | `7zz -mf=ARM` | `$7z$*`, exact |
| `7z_delta_enc.7z` | `LZMA2+03` | `deltapw` | `7zz -mf=Delta` | `$7z$*`, exact |
| `solid.7z` | `LZMA2`, one folder of three files | `solidpw` | `7zz -ms=on` | `$7z$*`, exact |
| `7z_nonsolid_enc.7z` | `LZMA2`, three folders | `multifolder` | `7zz -ms=off` | one `$7z$*` line, exact; three with `--all` |
| `7z_unicode_pw.7z` | `stored` | `пароль` | `7zz` | `$7z$*`, exact |
| `long_pw.7z` | `stored` | not recorded | `7zz` | `$7z$*`, exact |
| `lowpower.7z` | `stored` | `lowpow` | `7zz -m0=Copy` | `$7z$*`, exact |
| `multi.7z` | `LZMA2`, one folder of three files | `7zmulti` | `7zz` | `$7z$*`, exact |
| `3.test.txt.7z` | `LZMA2` | `abc` | zip-password-finder | `$7z$*`, exact |
| `3.test.multi.7z` | `LZMA2`, two folders | `abc` | zip-password-finder | `$7z$*`, exact |

`long_pw.7z` has no entry in `passwords.json`. An earlier version of this file gave its password as 128 times `a`, which `7zz t` rejects.

### Encrypted headers (`-mhe=on`)

`info` reports `headers   encrypted: names and sizes hidden` and no entries. The line is `$7z$*`, exact, from the headers.

| Fixture | Password | Created with |
|---|---|---|
| `headers.7z` | `7zhdr` | `7zz -mhe=on` |
| `7z_hdr_lzma2.7z` | `hdrpw` | `7zz -mhe=on -m0=LZMA2` |
| `7z_hdr_bzip2.7z` | `hdrbz2` | `7zz -mhe=on -m0=BZip2` |
| `3.test.hdr.7z` | `abc` | zip-password-finder |

### Made with an empty password

`7z_empty_pw.7z` was made with `7zz -p""`. The archive holds one empty file, and a 7zAES coder in front of nothing. `info` reports `1 of 1 folder encrypted`, `hash none` and the reason `no-data: it is empty, so every password would match`. It has no line and no entry in `passwords.json`, where it used to stand with an empty password that an earlier line format "confirmed".

### 7z fixtures generated for the hash format (`gen_*.7z`)

Passwords are in `passwords.json`. `gen_7z_*` were written by 7-Zip 26.02 (`7zz a`), `gen_py7zr_*` by py7zr, which shares no code with 7-Zip. Every one was tested with `7zz t` under its password and under a wrong one, except the two Zstandard archives, which this 7-Zip does not unpack: their passwords were confirmed at the time by the password check ArchiveWolf then had and by hashcat mode 46900.

Each gives one `$7z$*` line. It is exact for all of them but the five `gen_py7zr_*_hdr.7z`, where it is structural.

| Fixtures | What they cover |
|---|---|
| `gen_7z_{copy,lzma,lzma2,ppmd,bzip2,deflate,deflate64}.7z` | One packer each, 40 KB of text |
| `gen_7z_hdr_lzma2.7z`, `gen_7z_hdr_solid.7z` | Encrypted header: stored, and packed with LZMA |
| `gen_7z_exe_{bcj,arm,armt,arm64,ppc,sparc,ia64,riscv,delta4,swap2,swap4}.7z` | Every filter 7-Zip has, in front of LZMA2, on a real x86-64 program |
| `gen_7z_exe_{bcj2,bcj2_lzma}.7z` | BCJ2: four packed streams, each encrypted with a vector of its own, two of them empty or packed with LZMA |
| `gen_7z_exe_{delta_bcj,bcj_copy,bcj_deflate,bcj_ppmd}.7z` | Two filters in one folder, and a filter behind no packer, Deflate and PPMd |
| `gen_7z_exe_solid_{bcj,bcj2,arm64,ia64,riscv}.7z` | A filter in a folder of three files: the CRC-32 covers the first, and a branch converter needs the bytes behind it |
| `gen_7z_solid_{lzma2,bzip2,deflate,ppmd,copy}.7z` | Two files in one folder: the line is tested on the first, 28 bytes |
| `gen_7z_solid_rand_{lzma,lzma2,deflate}.7z` | The first file does not compress and the second does, so the line is cut at the worst-case bound |
| `gen_7z_nonsolid.7z` | Three folders: three lines with `--all`, the smallest first |
| `gen_7z_two_passwords.7z` | Two folders with different passwords: `7z-first` for `tiny.txt`, `7z-second` for `text40k.txt`. One line, from `tiny.txt`; two with `--all` |
| `gen_7z_mixed_plain_first.7z` | A folder that is not encrypted, then one that is: `1 of 2 folders encrypted; coverage some`, and the line from folder 1 |
| `gen_7z_empty_first.7z` | An empty file in front: it has no stream, and the line is that of the file behind it |
| `gen_7z_sfx.7z` | A program in front of the archive: `at offset 43432` |
| `gen_7z_pw_{unicode,long70,special,space}.7z` | Non-ASCII, 70 characters, `p:w*d$`, a space |
| `gen_py7zr_{lzma2,ppmd,zstd,bcj_lzma2,copy}.7z` | py7zr: a header packed with LZMA2, PPMd properties of 7 bytes, Zstandard |
| `gen_py7zr_{lzma2,ppmd,zstd,bcj_lzma2,copy}_hdr.7z` | py7zr with an encrypted header, for which it stores no CRC-32: the line says `header` in the place of the CRC-32 |

### Synthetic, without a line

| Fixture | What it is | `info` and `hash` |
|---|---|---|
| `rawkey.7z` | The key is the password itself | `no-mode: its key is the password itself, with no key derivation, which 7-Zip reads and never writes and hashcat does not test` |
| `unknown_coder.7z`, `tier5_padded.7z` | Encrypted before it is packed, by a coder nothing knows | `not-expressible: one of its streams is not encrypted, or is encrypted before it is packed` |

`bcj2_noextra.7z` is a copy of `bcj2_enc.7z` with three streams zeroed, which no password opens. The tool tests no password and does not see that: it writes a `$7z$*` line for it, exact, like the one of `bcj2_enc.7z`.

### Passwords not known, or from other collections

| Fixture | Source | Password |
|---|---|---|
| `flag.7z` | bkwhack | not known (a CTF challenge) |
| `aes_small_test.7z` | sevenz-rust2 | `iBlm8NTigvru0Jr0` |
| `encrypted.7z` | sevenz-rust2 | `sevenz-rust` |

Each gives one `$7z$*` line, exact.

### Not encrypted (`unencrypted/`)

For each, `info` reports `coverage none` and `hash none: nothing is encrypted`.

| Fixture | Compressor | Notes |
|---|---|---|
| `plain.7z` | LZMA2 | Basic unencrypted |
| `7za433_7zip_lzma2_bcj2.7z` | LZMA2 + BCJ2 | 4-stream coder |
| `copy.7z` | Copy (stored) | No compression |
| `solid.7z` | LZMA2 | Solid archive |
| `non_solid.7z` | LZMA2 | Non-solid |
| `bzip2_file.7z` | BZip2 | |
| `ppmd.7z` | PPMd | |
| `delta.7z` | Delta | |
| `delta_bcj2.7z` | Delta + BCJ2 | |
| `decompress_example_lzma2_bcj_x86.7z` | LZMA2 + BCJ | |
| `decompress_example_bcj_arm64.7z` | ARM64 | |
| `single_file_with_content_lzma.7z` | LZMA1 | |
| `two_files_with_content_lzma.7z` | LZMA1 | |
| `single_empty_file.7z` | -- | Empty file entry: `7z, 0 folders` |
| `two_empty_file.7z` | -- | Two empty entries: `7z, 0 folders` |
| `interleaved_empty_entry.7z` | -- | Mixed empty/content |
| `zstdmt-brotli.7z` | Zstd+Brotli | Unsupported by 7zz |
| `zstdmt-lz4.7z` | Zstd+LZ4 | Unsupported by 7zz |

## Regression fixtures of 2026-11-19 (`regress/zip/`, `regress/rar/`, `regress/7z/`)

| Fixture | Password | What it is | `hash` |
|---|---|---|---|
| `regress/zip/zip64_offset_only.zip` | `pw` | A ZIP64 extra field that holds the offset alone | `$zip$1$`, exact |
| `regress/zip/aes_directory_entry.zip` | `7z-aes256_deflate` | A directory entry flagged with WinZip AES in front of an entry with data | `$zip$2$`, exact, from the entry with data |
| `regress/7z/weak_first.7z` | `weakpw` | Two folders: a file of one byte, then one of 86 bytes | `$7z$*`, exact, from the second folder. With `--all` the first gives a weak line |
| `regress/rar/rar3_hp_vol.part1.rar`, `.part2.rar` | `secret` | RAR 3.00 volumes with encrypted headers | `$rar$30$*0*` from each, with the note that only the last volume of a set confirms a password. The line of the second volume cracks; the line of the first does not |
| `regress/rar/rar4_hp_vol.part1.rar`, `.part2.rar` | `secret` | RAR 4.20 volumes with encrypted headers: a 20-byte end block | `$rar$30$*0*` in the 32-byte form, from each |
| `regress/rar/rar5_hp_vol.part1.rar` to `.part3.rar` | `secret` | RAR 5 volumes with encrypted headers | `$rar$50$*0*`, exact, from each |
| `regress/rar/rar5_p_vol.part1.rar`, `.part2.rar` | `secret` | RAR 5 volumes with one encrypted entry split across them | `$rar$50$*0*`, exact, from the check value of the entry in each volume |
| `regress/rar/rar3_no_salt.rar` | `secret` | A RAR 3 entry without a salt | no line, `[not-expressible]` |
| `regress/rar/service_zero_check_value.rar` | `password` (`d.txt`: `password2`) | A RAR 5 service record with a zeroed check value in front of the files, the checksum of its header set right | `$rar$50$*0*` from `b.txt`. With `--all`, a line for `d.txt` and a type 1 line for the service record |
| `regress/rar/rounds_2e25.rar` | none | RAR 5 with a round count of 2^25, the checksums of the two changed headers set right | no line, `[unsupported-parameters]` |
| `regress/rar/rar5_comment.rar` | none | A RAR 5 archive with a comment, nothing encrypted | no line |

Every line of this table that is not marked otherwise was cracked with its password by a build of the hashcat fork on 2026-11-19.

## Totals

This file keeps no counts. `archivewolf info tests/fixtures` prints a block for every archive it finds, and `archivewolf hash tests/fixtures` ends with a count of its lines by mode.
