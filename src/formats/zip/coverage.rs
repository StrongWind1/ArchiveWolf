//! What the analysis reports for every variant ZIP defines, row by row of its registry, and
//! for every reason and finding ZIP can give.
//!
//! A row has a fixture where an archiver writes it. The others are built here: no free tool
//! writes strong encryption with a cipher other than AES, an encrypted central directory or a
//! header that contradicts itself.

use std::path::Path;

use super::analyse::analyse;
use super::craft::DecryptionHeader;
use super::craft::Member;
use super::craft::Zip;
use super::craft::aes_extra;
use super::craft::deflated;
use super::craft::member;
use super::craft::noise;
use super::craft::pkware_extra;
use crate::analysis::Analysed;
use crate::analysis::Analysis;
use crate::analysis::Check;
use crate::analysis::CheckKind;
use crate::analysis::Cipher;
use crate::analysis::Counts;
use crate::analysis::Coverage;
use crate::analysis::Entries;
use crate::analysis::EntryKind;
use crate::analysis::EntryLine;
use crate::analysis::Finding;
use crate::analysis::Found;
use crate::analysis::Generation;
use crate::analysis::Headers;
use crate::analysis::Kdf;
use crate::analysis::KdfName;
use crate::analysis::Missing;
use crate::analysis::NoLine;
use crate::analysis::Protection;
use crate::analysis::Reason;
use crate::analysis::Salt;
use crate::analysis::Scheme;
use crate::analysis::Split;
use crate::analysis::State;
use crate::analysis::Volume;
use crate::formats::source::Source;
use crate::line::Lines;
use crate::line::Note;
use crate::line::Proves;
use crate::line::Tag;

fn fixture(rel: &str, wanted: Lines) -> Analysed {
    let source = Source::open(Path::new(&format!("tests/fixtures/{rel}")), 0).unwrap();
    analyse(&source, wanted).unwrap()
}

fn built(members: &[Member<'_>], wanted: Lines) -> Analysed {
    analyse(&Source::from_bytes(Zip::of(members).build()), wanted).unwrap()
}

fn bytes(archive: Vec<u8>, wanted: Lines) -> Analysed {
    analyse(&Source::from_bytes(archive), wanted).unwrap()
}

fn codes(analysis: &Analysis) -> Vec<&'static str> {
    analysis.findings.iter().map(Finding::code).collect()
}

fn protection(analysis: &Analysis, index: usize) -> &Protection {
    analysis.entry_list[index].protection.as_ref().unwrap()
}

fn states(analysis: &Analysis) -> Vec<State> {
    analysis.entry_list.iter().map(|entry| entry.state).collect()
}

/// The data of a ZipCrypto entry: 12 bytes of encryption header and `stream` bytes behind it.
fn zip_crypto_data(stream: usize) -> Vec<u8> {
    noise(12 + stream)
}

/// The data of a WinZip AES entry: salt, verifier, `ciphertext` bytes and the code.
fn aes_data(strength: u8, ciphertext: usize) -> Vec<u8> {
    noise(usize::from(4 * strength + 4) + 2 + ciphertext + 10)
}

/// An entry under strong encryption: its central extra field, and its data behind `header`.
fn pkware_member<'a>(name: &'a str, extra: &'a [u8], data: &'a [u8]) -> Member<'a> {
    Member { version: 51, central_extra: extra, size: Some(400), ..member(name, 0x0041, data) }
}

fn pkware_data(header: &DecryptionHeader) -> Vec<u8> {
    [header.bytes(), noise(64)].concat()
}

// ---------------------------------------------------------------------------
// zip-crypto
// ---------------------------------------------------------------------------

#[test]
fn zip_crypto_with_one_check_byte() {
    for rel in ["zip-crypto/gen_7z_zipcrypto_deflate.zip", "zip-crypto/gen_infozip_deflate.zip"] {
        let Analysed { analysis, lines } = fixture(rel, Lines::Best);
        let protection = protection(&analysis, lines[0].entry.unwrap());
        assert_eq!((protection.scheme, protection.parameters.cipher, protection.parameters.key_bits, &protection.salt), (Scheme::ZipCrypto, Some(Cipher::ZipCrypto), Some(96), &Salt::None), "{rel}");
        assert_eq!(protection.parameters.check, [Check::new(CheckKind::CheckByte, 8), Check::new(CheckKind::Crc32, 32)], "{rel}");
        assert_eq!((lines.len(), lines[0].tag, lines[0].mode, lines[0].proves), (1, Tag::Zip1, 46100, Proves::Exact), "{rel}");
        // one byte: two hex digits behind the slash of the check
        let check = lines[0].text.split('*').nth(2).unwrap();
        assert_eq!(check.split('/').nth(1).map(str::len), Some(2), "{rel}: {check}");
    }
}

/// PKZIP before 2.0 wrote two check bytes. The writer is named by "version made by": APPNOTE
/// 6.1.6 ties the width to the version of PKZIP that wrote the entry, and writers at 2.0 and
/// later put "version needed" 1.0 on a stored entry and fill one byte (Info-ZIP fills both,
/// libzip one).
#[test]
fn zip_crypto_with_two_check_bytes() {
    let Analysed { analysis, lines } = fixture("zip-crypto/gen_own_zc_pkzip1_twobyte.zip", Lines::Best);
    assert!(analysis.entry_list.iter().all(|entry| entry.protection.as_ref().unwrap().parameters.check.first() == Some(&Check::new(CheckKind::CheckByte, 16))));
    assert_eq!(analysis.schemes.len(), 1);
    let check = lines[0].text.split('*').nth(2).unwrap();
    assert_eq!(check.split('/').nth(1).map(str::len), Some(4), "{check}");

    // the same entry from a writer at 1.1 and from one at 2.0 that says it needs 1.0
    let data = zip_crypto_data(40);
    let Analysed { analysis, lines } = built(&[Member { made_by: 11, version: 10, ..member("old.bin", 1, &data) }], Lines::Best);
    assert_eq!(protection(&analysis, 0).parameters.check[0], Check::new(CheckKind::CheckByte, 16));
    assert_eq!(lines[0].text.split('*').nth(2).unwrap().len(), 24 + 1 + 4);
    let Analysed { analysis, lines } = built(&[Member { made_by: 20, version: 10, ..member("new.bin", 1, &data) }], Lines::Best);
    assert_eq!(protection(&analysis, 0).parameters.check[0], Check::new(CheckKind::CheckByte, 8));
    assert_eq!(lines[0].text.split('*').nth(2).unwrap().len(), 24 + 1 + 2);

    // an archive with both widths has two rows of one scheme and one key group
    let analysis = built(&[Member { made_by: 11, ..member("old.bin", 1, &data) }, member("new.bin", 1, &data)], Lines::Best).analysis;
    assert_eq!(analysis.schemes.iter().map(|row| (row.scheme, row.entries)).collect::<Vec<_>>(), [(Scheme::ZipCrypto, Some(1)), (Scheme::ZipCrypto, Some(1))]);
    assert!(!analysis.mixed && analysis.entry_list.iter().all(|entry| entry.key_group == Some(1)));
}

/// A method hashcat has no decoder for: the line tests the check bytes of the headers and
/// nothing else, and says so.
#[test]
fn zip_crypto_over_a_method_hashcat_cannot_unpack() {
    for (rel, method) in [("zip-crypto/gen_7z_zipcrypto_deflate64.zip", 9), ("zip-crypto/gen_7z_zipcrypto_lzma.zip", 14), ("zip-crypto/gen_7z_zipcrypto_ppmd.zip", 98)] {
        let Analysed { analysis, lines } = fixture(rel, Lines::Best);
        assert_eq!((lines.len(), lines[0].proves, lines[0].note), (1, Proves::Weak { bits: 8 }, Some(Note::NoDecoder { method, checks: 1 })), "{rel}");
        assert!(lines[0].text.ends_with("*$/zip$"), "{rel}: no data in the line");
        assert_eq!(codes(&analysis), ["weak-scheme", "weak-check", "proof-not-run"], "{rel}");
        assert_eq!(analysis.entry_list[0].state, State::Encrypted, "{rel}");
    }

    // the legacy methods, Zstandard and a method without a name
    for method in [1_u16, 6, 93, 97] {
        let data = zip_crypto_data(300);
        let Analysed { analysis, lines } = built(&[Member { method, ..member("a.bin", 1, &data) }], Lines::Best);
        assert_eq!((lines[0].proves, lines[0].note), (Proves::Weak { bits: 8 }, Some(Note::NoDecoder { method, checks: 1 })), "method {method}");
        assert_eq!(analysis.entry_list[0].method.as_ref().unwrap().number, Some(u64::from(method)));
    }
    // bzip2 and xz are tested by their signature
    for rel in ["zip-crypto/gen_7z_zipcrypto_bzip2.zip", "zip-crypto/gen_infozip_bzip2.zip"] {
        let lines = fixture(rel, Lines::Best).lines;
        assert_eq!((lines[0].proves, lines[0].note), (Proves::Structural, None), "{rel}");
    }
}

// ---------------------------------------------------------------------------
// zip-winzip
// ---------------------------------------------------------------------------

#[test]
fn zip_winzip_in_both_versions_and_three_strengths() {
    for ae_version in [1_u16, 2] {
        for (strength, bits) in [(1_u8, 128), (2, 192), (3, 256)] {
            let extra = aes_extra(ae_version, strength, 8);
            let data = aes_data(strength, 50);
            let Analysed { analysis, lines } = built(&[Member { method: 99, extra: &extra, ..member("a.bin", 1, &data) }], Lines::Best);

            let protection = protection(&analysis, 0);
            assert_eq!((protection.scheme, protection.parameters.ae, protection.parameters.cipher, protection.parameters.key_bits), (Scheme::ZipWinzip, Some(ae_version), Some(Cipher::Aes), Some(bits)));
            assert_eq!(protection.parameters.kdf, Some(Kdf { name: KdfName::Pbkdf2HmacSha1, rounds: Some(1000) }));
            // AE-1 keeps the CRC-32 of the data, AE-2 stores none
            let mut check = vec![Check::new(CheckKind::Verifier, 16), Check::new(CheckKind::Hmac, 80)];
            check.extend((ae_version == 1).then_some(Check::new(CheckKind::Crc32, 32)));
            assert_eq!(protection.parameters.check, check);
            assert_eq!(protection.salt, Salt::Known(data[..usize::from(4 * strength + 4)].to_vec()));

            assert_eq!((lines.len(), lines[0].tag, lines[0].mode, lines[0].proves), (1, Tag::Zip2, 46200, Proves::Exact));
            assert!(lines[0].text.starts_with(&format!("$zip$2$*{strength}*{}*", hex::encode(&data[..usize::from(4 * strength + 4)]))), "{}", lines[0].text);
            assert_eq!(analysis.entry_list[0].method.as_ref().unwrap().name.as_deref(), Some("deflate"), "the method the entry really uses");
        }
    }
    // and from the archivers that write it
    for (rel, ae, bits) in [("zip-winzip/gen_own_aes128_ae1.zip", 1, 128), ("zip-winzip/gen_own_aes192_ae2_stored.zip", 2, 192), ("zip-winzip/gen_7z_aes256_deflate.zip", 2, 256), ("zip-winzip/rawzip_aes256-ae1.zip", 1, 256)] {
        let Analysed { analysis, lines } = fixture(rel, Lines::Best);
        let protection = protection(&analysis, lines[0].entry.unwrap());
        assert_eq!((protection.parameters.ae, protection.parameters.key_bits), (Some(ae), Some(bits)), "{rel}");
    }
}

/// Entries under WinZip AES are grouped by their salt, and entries under ZipCrypto are one
/// group whatever they hold.
#[test]
fn key_groups_follow_the_salt() {
    let extra = aes_extra(2, 3, 0);
    let (first, second) = (aes_data(3, 40), [vec![0x77; 16], noise(52)].concat());
    let zip_crypto = zip_crypto_data(30);
    let analysis = built(
        &[Member { method: 99, extra: &extra, ..member("a", 1, &first) }, Member { method: 99, extra: &extra, ..member("b", 1, &second) }, Member { method: 99, extra: &extra, ..member("a again", 1, &first) }, member("c", 1, &zip_crypto), Member { method: 8, ..member("d", 1, &zip_crypto) }],
        Lines::Best,
    )
    .analysis;
    assert_eq!(analysis.entry_list.iter().map(|entry| entry.key_group).collect::<Vec<_>>(), [Some(1), Some(2), Some(1), Some(3), Some(3)]);
    let rows: Vec<(Scheme, Option<usize>, Option<usize>)> = analysis.schemes.iter().map(|row| (row.scheme, row.entries, row.key_groups)).collect();
    assert_eq!(rows, [(Scheme::ZipWinzip, Some(3), Some(2)), (Scheme::ZipCrypto, Some(2), Some(1))]);
    assert!(analysis.mixed && codes(&analysis).contains(&"mixed-schemes"));
}

/// A version or a strength the format does not have is shown as it is stored, and no line is
/// written for it: nothing says such an entry is laid out like the ones the mode knows.
#[test]
fn zip_winzip_with_a_version_or_a_strength_that_is_not_known() {
    let data = aes_data(3, 40);
    let extra = aes_extra(2, 7, 8);
    let Analysed { analysis, lines } = built(&[Member { method: 99, extra: &extra, ..member("a.bin", 1, &data) }], Lines::Best);
    let protection = protection(&analysis, 0);
    assert_eq!((protection.scheme, protection.parameters.key_bits, protection.parameters.identifier, &protection.salt), (Scheme::ZipWinzip, None, Some(7), &Salt::Unknown));
    assert!(lines.is_empty());
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipWinzip, 0, NoLine::UnknownScheme)]);
    assert_eq!(analysis.no_line[0].reason(), Reason::UnknownScheme);

    let extra = aes_extra(3, 3, 8);
    let Analysed { analysis, lines } = built(&[Member { method: 99, extra: &extra, ..member("a.bin", 1, &data) }], Lines::Best);
    assert_eq!((protection_of(&analysis).parameters.ae, analysis.entry_list[0].state), (Some(3), State::Encrypted));
    assert!(lines.is_empty() && analysis.no_line[0].why == NoLine::UnknownScheme);
}

fn protection_of(analysis: &Analysis) -> &Protection {
    protection(analysis, 0)
}

// ---------------------------------------------------------------------------
// zip-pkware
// ---------------------------------------------------------------------------

#[test]
fn zip_pkware_with_aes_and_a_password() {
    for (rel, alg, bits, mode, stored_iv) in [
        ("zip-pkware/gen_ses_aes128_iv_deflate.zip", "660e", 128, 46300, true),
        ("zip-pkware/gen_ses_aes192_iv_stored.zip", "660f", 192, 46310, true),
        ("zip-pkware/gen_ses_aes256_iv_deflate.zip", "6610", 256, 46320, true),
        ("zip-pkware/gen_ses_aes128_noiv_stored.zip", "660e", 128, 46300, false),
        ("zip-pkware/gen_ses_aes192_noiv_deflate.zip", "660f", 192, 46310, false),
        ("zip-pkware/gen_ses_aes256_noiv_stored.zip", "6610", 256, 46320, false),
    ] {
        let Analysed { analysis, lines } = fixture(rel, Lines::Best);
        assert_eq!((lines.len(), lines[0].tag, lines[0].mode, lines[0].proves), (1, Tag::Zip3, mode, Proves::Exact), "{rel}");
        assert!(lines[0].text.starts_with(&format!("$zip$3$*{alg}*{bits}*1*")), "{rel}: {}", lines[0].text);

        // the parameters are those of the decryption header
        let protection = protection(&analysis, lines[0].entry.unwrap());
        assert_eq!((protection.scheme, protection.parameters.cipher, protection.parameters.key_bits, protection.parameters.identifier), (Scheme::ZipPkware, Some(Cipher::Aes), Some(bits), None), "{rel}");
        assert_eq!(protection.parameters.kdf, Some(Kdf { name: KdfName::Sha1, rounds: None }), "{rel}");
        assert_eq!(protection.parameters.check, [Check::structure(), Check::new(CheckKind::Crc32, 32)], "{rel}");
        // the vector the header stores, or the CRC-32 and the size that stand in for it
        let Salt::Known(vector) = &protection.salt else { panic!("{rel}: no vector") };
        assert_eq!(vector.len(), if stored_iv { 16 } else { 12 }, "{rel}");
        assert_eq!(lines[0].text.split('*').nth(4), Some(hex::encode(vector).as_str()), "{rel}: the vector the analysis shows is the one of the line");
    }
}

/// Every entry under strong encryption has a vector of its own, which goes into the key of
/// its data beside the password: each is a key group.
#[test]
fn pkware_entries_are_grouped_by_their_vector() {
    let extra = pkware_extra(0x6610, 256, 1);
    let first = pkware_data(&DecryptionHeader::password(0x6610, 256));
    let second = pkware_data(&DecryptionHeader { iv: vec![0xB2; 16], ..DecryptionHeader::password(0x6610, 256) });
    let analysis = built(&[pkware_member("a", &extra, &first), pkware_member("b", &extra, &second), pkware_member("c", &extra, &first)], Lines::All).analysis;
    assert_eq!(analysis.entry_list.iter().map(|entry| entry.key_group).collect::<Vec<_>>(), [Some(1), Some(2), Some(1)]);
    assert_eq!((analysis.schemes[0].entries, analysis.schemes[0].key_groups), (Some(3), Some(2)));
}

/// The ciphers of strong encryption other than AES: named, and no mode tests them. 7-Zip, John
/// the Ripper and hashcat stop at AES, and how PKWARE derives their keys is not published.
#[test]
fn zip_pkware_with_every_other_cipher_has_no_mode() {
    for (alg_id, bits, cipher) in [
        (0x6601_u16, 56_u16, Some(Cipher::Des)),
        (0x6602, 40, Some(Cipher::Rc2Old)),
        (0x6603, 168, Some(Cipher::TripleDes)),
        (0x6609, 112, Some(Cipher::TripleDes2Key)),
        (0x6702, 128, Some(Cipher::Rc2)),
        (0x6720, 448, Some(Cipher::Blowfish)),
        (0x6721, 256, Some(Cipher::Twofish)),
        (0x6801, 128, Some(Cipher::Rc4)),
        // "unknown algorithm" is an identifier of the format, and one it does not have
        (0xFFFF, 128, None),
        (0x6699, 128, None),
    ] {
        let extra = pkware_extra(alg_id, bits, 1);
        let data = pkware_data(&DecryptionHeader { iv: vec![0x1F; 8], erd: noise(64), ..DecryptionHeader::password(alg_id, bits) });
        let Analysed { analysis, lines } = built(&[pkware_member("secret.bin", &extra, &data)], Lines::Best);
        assert!(lines.is_empty(), "0x{alg_id:04x}");

        let protection = protection(&analysis, 0);
        let identifier = cipher.is_none().then_some(u64::from(alg_id));
        assert_eq!((protection.scheme, protection.parameters.cipher, protection.parameters.key_bits, protection.parameters.identifier), (Scheme::ZipPkware, cipher, Some(u32::from(bits)), identifier), "0x{alg_id:04x}");
        assert_eq!(analysis.entry_list[0].state, State::Encrypted, "0x{alg_id:04x}");
        assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipPkware, 0, NoLine::PkwareCipher { cipher, identifier: alg_id })], "0x{alg_id:04x}");
        assert_eq!(analysis.no_line[0].reason(), Reason::NoMode, "0x{alg_id:04x}");
        assert_eq!(analysis.entry_list[0].line, Some(EntryLine(Err(Reason::NoMode))), "0x{alg_id:04x}");
    }
}

#[test]
fn zip_pkware_to_certificates_only_has_no_password() {
    let Analysed { analysis, lines } = fixture("unknown-pw/edge_zip-forensic_securezip-strong-signed.zip", Lines::All);
    assert!(lines.is_empty());
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipPkware, 0, NoLine::Certificate)]);
    assert_eq!(analysis.no_line[0].reason(), Reason::NoPassword);
    let protection = protection(&analysis, 0);
    assert_eq!((protection.parameters.cipher, protection.parameters.key_bits, protection.parameters.kdf), (Some(Cipher::Aes), Some(256), None));
    assert!(protection.parameters.check.is_empty(), "nothing a password could be tested against");
    assert_eq!(codes(&analysis), ["certificate"]);
    assert_eq!(analysis.findings[0].entries, [0]);

    // flags 2 without a recipient list, and with a cipher no mode tests: no password either way
    for alg_id in [0x6610_u16, 0x6720] {
        let extra = pkware_extra(alg_id, 256, 2);
        let data = pkware_data(&DecryptionHeader { flags: 2, ..DecryptionHeader::password(alg_id, 256) });
        let analysis = built(&[pkware_member("sealed.bin", &extra, &data)], Lines::Best).analysis;
        assert_eq!(analysis.no_line[0].why, NoLine::Certificate, "0x{alg_id:04x}");
    }
}

/// What is said of an entry does not hang on the entries around it: an entry that only
/// certificates open has its reason and its finding beside an entry that gives the line,
/// whichever of the two is the smaller and so ranks first.
#[test]
fn what_is_said_of_an_entry_does_not_hang_on_the_order_of_the_entries() {
    let (open_extra, sealed_extra) = (pkware_extra(0x6610, 256, 1), pkware_extra(0x6610, 256, 2));
    let header = |flags: u16, padding: usize| {
        let mut data = pkware_data(&DecryptionHeader { flags, ..DecryptionHeader::password(0x6610, 256) });
        data.extend(noise(padding));
        data
    };
    for (open_size, sealed_size) in [(16, 4000), (4000, 16)] {
        let (open, sealed) = (header(1, open_size), header(2, sealed_size));
        for wanted in [Lines::Best, Lines::All] {
            let Analysed { analysis, lines } = built(&[pkware_member("open.bin", &open_extra, &open), pkware_member("sealed.bin", &sealed_extra, &sealed)], wanted);
            assert_eq!((lines.len(), lines[0].entry), (1, Some(0)), "{open_size} and {sealed_size} bytes");
            assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipPkware, 1, NoLine::Certificate)], "{open_size} and {sealed_size} bytes");
            assert_eq!(analysis.findings, [Finding::new(Found::Certificate, vec![1])], "{open_size} and {sealed_size} bytes");
            assert_eq!(analysis.entry_list[1].line, Some(EntryLine(Err(Reason::NoPassword))));
        }
    }
}

/// Flags 3: a password or a certificate opens the entry. Its decryption header lists the
/// recipients between the random data and the validation data (APPNOTE 7.2.4.7, 7.2.4.8 and
/// 7.4.4), and the random data is encrypted under the password as in an entry for a password
/// alone, so the line is the same line.
#[test]
fn zip_pkware_for_a_password_or_a_certificate() {
    let recipient = [vec![0x91; 20], noise(268)].concat();
    let header = DecryptionHeader { flags: 3, recipients: vec![recipient.clone(), recipient], vdata: noise(32), ..DecryptionHeader::password(0x660F, 192) };
    let extra = pkware_extra(0x660F, 192, 3);
    let data = pkware_data(&header);
    let Analysed { analysis, lines } = built(&[pkware_member("either.bin", &extra, &data)], Lines::Best);

    assert_eq!((lines.len(), lines[0].tag, lines[0].mode, lines[0].proves), (1, Tag::Zip3, 46310, Proves::Exact));
    assert_eq!(lines[0].text, format!("$zip$3$*660f*192*3*{}*{}*{}$/zip$", hex::encode([0xA1; 16]), hex::encode(&header.erd), hex::encode(&header.vdata)));
    assert!(analysis.no_line.is_empty() && codes(&analysis).is_empty());
    assert_eq!(protection(&analysis, 0).parameters.kdf, Some(Kdf { name: KdfName::Sha1, rounds: None }));

    // without a list, which a writer may leave out
    let header = DecryptionHeader { flags: 3, ..DecryptionHeader::password(0x660E, 128) };
    let extra = pkware_extra(0x660E, 128, 3);
    let lines = built(&[pkware_member("either.bin", &extra, &pkware_data(&header))], Lines::Best).lines;
    assert!(lines[0].text.starts_with("$zip$3$*660e*128*3*"));
}

/// The mode refuses random data that is wrapped with 3DES (flag 0x4000), so no line is written
/// for it.
#[test]
fn zip_pkware_with_wrapped_random_data_has_no_mode() {
    let header = DecryptionHeader { flags: 0x4001, ..DecryptionHeader::password(0x6610, 256) };
    let extra = pkware_extra(0x6610, 256, 0x4001);
    let Analysed { analysis, lines } = built(&[pkware_member("wrapped.bin", &extra, &pkware_data(&header))], Lines::Best);
    assert!(lines.is_empty());
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipPkware, 0, NoLine::RandomDataWrapped)]);
    assert_eq!(analysis.no_line[0].reason(), Reason::NoMode);
}

/// What modes 46300 to 46320 load is read off `zip_strong.c`: a vector of 16 bytes, 4096 bytes
/// of random data, 1024 of validation data, and an algorithm with its own key length.
#[test]
fn a_zip_pkware_line_stays_within_what_its_mode_loads() {
    let within = DecryptionHeader { erd: noise(4096), vdata: noise(1024), ..DecryptionHeader::password(0x6610, 256) };
    let over_iv = DecryptionHeader { iv: vec![9; 17], ..DecryptionHeader::password(0x6610, 256) };
    let over_erd = DecryptionHeader { erd: noise(4112), ..DecryptionHeader::password(0x6610, 256) };
    let over_vdata = DecryptionHeader { vdata: noise(1040), ..DecryptionHeader::password(0x6610, 256) };
    let extra = pkware_extra(0x6610, 256, 1);

    let line_of = |header: &DecryptionHeader| built(&[pkware_member("a.bin", &extra, &pkware_data(header))], Lines::Best);
    let Analysed { lines, .. } = line_of(&within);
    assert_eq!(lines[0].text.len(), "$zip$3$*6610*256*1*".len() + 32 + 1 + 8192 + 1 + 2048 + "$/zip$".len());

    for (header, why) in [(&over_iv, NoLine::LineField { field: "initialisation vector", size: 17, limit: 16 }), (&over_erd, NoLine::LineField { field: "random data", size: 4112, limit: 4096 }), (&over_vdata, NoLine::LineField { field: "validation data", size: 1040, limit: 1024 })] {
        let Analysed { analysis, lines } = line_of(header);
        assert!(lines.is_empty(), "{why}");
        assert_eq!((analysis.no_line[0].reason(), &analysis.no_line[0].why), (Reason::OverLimit, &why));
    }
    // a vector no line carries leaves the entry without a key group
    assert_eq!(protection(&line_of(&over_iv).analysis, 0).salt, Salt::Unknown);
}

#[test]
fn a_decryption_header_that_no_line_can_be_built_from() {
    let extra = pkware_extra(0x6610, 256, 1);
    let reason_of = |header: &DecryptionHeader| {
        let Analysed { analysis, lines } = built(&[pkware_member("a.bin", &extra, &pkware_data(header))], Lines::Best);
        assert!(lines.is_empty());
        analysis.no_line[0].why.clone()
    };
    // a format APPNOTE does not define: no decryption header, and so damage
    assert_eq!(reason_of(&DecryptionHeader { format: 4, ..DecryptionHeader::password(0x6610, 256) }), NoLine::HeaderFormat { format: 4 });
    assert_eq!(NoLine::HeaderFormat { format: 4 }.reason(), Reason::Damaged);
    // a key length that is not the one of the algorithm
    assert_eq!(reason_of(&DecryptionHeader::password(0x6610, 128)), NoLine::Unreadable);
    // random data that is not whole cipher blocks, or none
    assert_eq!(reason_of(&DecryptionHeader { erd: noise(100), ..DecryptionHeader::password(0x6610, 256) }), NoLine::Unreadable);
    assert_eq!(reason_of(&DecryptionHeader { erd: Vec::new(), ..DecryptionHeader::password(0x6610, 256) }), NoLine::Unreadable);
    // validation data too short for its CRC-32
    assert_eq!(reason_of(&DecryptionHeader { vdata: vec![1, 2, 3], ..DecryptionHeader::password(0x6610, 256) }), NoLine::Unreadable);

    // an entry too short for a decryption header: the central header still names its cipher
    let Analysed { analysis, lines } = built(&[pkware_member("short.bin", &extra, &[0x10, 0])], Lines::Best);
    assert!(lines.is_empty());
    let protection = protection(&analysis, 0);
    assert_eq!((protection.parameters.cipher, protection.parameters.key_bits, &protection.salt), (Some(Cipher::Aes), Some(256), &Salt::Unknown));
    assert_eq!((analysis.no_line[0].reason(), analysis.entry_list[0].key_group), (Reason::Damaged, None));
}

/// A central header only has extra field 0x0017. Without it the decryption header says the
/// same, and the line is built from that.
#[test]
fn zip_pkware_without_its_extra_field_is_read_from_the_decryption_header() {
    let data = pkware_data(&DecryptionHeader::password(0x660E, 128));
    let Analysed { analysis, lines } = built(&[Member { version: 51, size: Some(400), ..member("a.bin", 0x0041, &data) }], Lines::Best);
    assert_eq!((lines.len(), lines[0].mode), (1, 46300));
    assert_eq!((protection(&analysis, 0).scheme, protection(&analysis, 0).parameters.key_bits), (Scheme::ZipPkware, Some(128)));
}

// ---------------------------------------------------------------------------
// Central directory encryption
// ---------------------------------------------------------------------------

/// An encrypted central directory: the ZIP64 end record says with what, the entries are
/// hidden, and no mode tests it.
#[test]
fn an_encrypted_central_directory_hides_the_entries() {
    let data = pkware_data(&DecryptionHeader::password(0x6610, 256));
    let members = [Member { version: 62, ..member("1", 0x2041, &data) }, Member { version: 62, ..member("2", 0x2041, &data) }];
    let Analysed { analysis, lines } = bytes(Zip::of(&members).directory_protection(8, 0x6610, 256, 1).build(), Lines::All);

    assert!(lines.is_empty());
    assert_eq!((analysis.headers, analysis.entries, analysis.coverage, analysis.generation), (Headers::Encrypted, Entries::Hidden, Coverage::Unknown, Generation::Zip64));
    assert!(analysis.entry_list.is_empty() && analysis.is_encrypted());
    let row = &analysis.schemes[0];
    assert_eq!((row.scheme, row.parameters.cipher, row.parameters.key_bits, row.entries, row.key_groups), (Scheme::ZipPkware, Some(Cipher::Aes), Some(256), None, None));
    assert_eq!(row.parameters.kdf, Some(Kdf { name: KdfName::Sha1, rounds: None }));
    assert_eq!(analysis.no_line, [Missing::for_scheme(Scheme::ZipPkware, NoLine::CentralDirectoryEncrypted)]);
    assert_eq!(analysis.no_line[0].reason(), Reason::NoMode);

    // another cipher, and one the format has no name for
    for (alg_id, cipher, identifier) in [(0x6609_u16, Some(Cipher::TripleDes2Key), None), (0x6777, None, Some(0x6777))] {
        let analysis = bytes(Zip::of(&members).directory_protection(0, alg_id, 112, 1).build(), Lines::Best).analysis;
        let parameters = &analysis.schemes[0].parameters;
        assert_eq!((analysis.headers, parameters.cipher, parameters.identifier, parameters.key_bits), (Headers::Encrypted, cipher, identifier, Some(112)));
    }

    // encrypted to certificates only: no password opens it
    let analysis = bytes(Zip::of(&members).directory_protection(8, 0x6610, 256, 2).build(), Lines::Best).analysis;
    assert_eq!(analysis.no_line, [Missing::for_scheme(Scheme::ZipPkware, NoLine::Certificate)]);
    assert_eq!((analysis.no_line[0].reason(), codes(&analysis)), (Reason::NoPassword, vec!["certificate"]));
    assert!(analysis.schemes[0].parameters.kdf.is_none());

    // compressed and not encrypted: not a directory this tool unpacks, and said so
    let error = analyse(&Source::from_bytes(Zip::of(&members).directory_protection(8, 0, 0, 0).build()), Lines::Best).unwrap_err();
    assert!(error.to_string().contains("compressed with method 8"), "{error:#}");
}

/// Flag bit 13 on an entry says that its local header is masked. In a directory that can be
/// read it is no encryption of its own: the entry is what its other marks say.
#[test]
fn bit_13_in_a_readable_directory_is_not_an_encrypted_directory() {
    let extra = pkware_extra(0x660E, 128, 1);
    let data = pkware_data(&DecryptionHeader::password(0x660E, 128));
    let zip_crypto = zip_crypto_data(40);
    let Analysed { analysis, lines } = built(&[Member { flags: 0x2041, ..pkware_member("masked", &extra, &data) }, member("also masked", 0x2001, &zip_crypto), member("open", 0x2000, b"plain")], Lines::Best);
    assert_eq!(analysis.headers, Headers::Readable);
    assert_eq!(states(&analysis), [State::Encrypted, State::Encrypted, State::Plain]);
    assert_eq!(lines.iter().map(|line| line.tag).collect::<Vec<_>>(), [Tag::Zip1, Tag::Zip3]);
}

// ---------------------------------------------------------------------------
// A mark that contradicts the rest
// ---------------------------------------------------------------------------

/// A mark without the extra field that says what it means is never read as no mark: the entry
/// is named by its mark, not determined, and gives no line.
#[test]
fn a_mark_that_contradicts_its_extra_fields_is_named_and_never_plain() {
    let data = aes_data(3, 40);
    for (name, flags, method, scheme) in [("method 99, flagged, no AES field", 1_u16, 99_u16, Scheme::ZipWinzip), ("method 99, not flagged, no AES field", 0, 99, Scheme::ZipWinzip), ("bit 6 without bit 0", 0x40, 8, Scheme::ZipPkware)] {
        let Analysed { analysis, lines } = built(&[Member { method, ..member("odd.bin", flags, &data) }, member("open.txt", 0, b"plain")], Lines::Best);
        assert!(lines.is_empty(), "{name}");
        assert_eq!(states(&analysis), [State::Undetermined, State::Plain], "{name}");
        assert_eq!((protection(&analysis, 0).scheme, analysis.entry_list[0].key_group), (scheme, None), "{name}");
        assert_eq!(analysis.entries, Entries::Counts(Counts { total: 2, encrypted: 0, plain: 1, pseudo: 0, undetermined: 1 }), "{name}");
        assert_eq!(analysis.coverage, Coverage::Some, "{name}: what is not determined is not counted as open");
        assert_eq!(analysis.no_line, [Missing::for_entry(scheme, 0, NoLine::Unreadable)], "{name}");
        assert!(analysis.is_encrypted(), "{name}");
    }

    // method 99 with its field and a clear flag is WinZip AES all the same
    let extra = aes_extra(2, 3, 0);
    let Analysed { analysis, lines } = built(&[Member { method: 99, extra: &extra, ..member("a.bin", 0, &data) }], Lines::Best);
    assert_eq!((states(&analysis), lines.len(), lines[0].tag), (vec![State::Encrypted], 1, Tag::Zip2));
}

/// A stored entry under ZipCrypto is 12 bytes longer than what it holds. One whose sizes say
/// otherwise is neither encrypted data nor plain data with a flag on it, and the mode refuses a
/// stored line whose sizes disagree.
#[test]
fn a_stored_entry_whose_sizes_contradict_each_other_is_not_determined() {
    let data = zip_crypto_data(40);
    let good = zip_crypto_data(60);
    let Analysed { analysis, lines } = built(&[Member { size: Some(10), ..member("odd.bin", 1, &data) }, member("good.bin", 1, &good)], Lines::All);
    assert_eq!(states(&analysis), [State::Undetermined, State::Encrypted]);
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipCrypto, 0, NoLine::SizesDisagree)]);
    assert_eq!(analysis.no_line[0].reason(), Reason::Damaged);
    assert_eq!(lines.len(), 1);

    // the line of the other entry does not carry its header
    let lines = built(&[Member { size: Some(10), ..member("odd.bin", 1, &data) }, member("good.bin", 1, &good)], Lines::Best).lines;
    assert!(lines[0].text.starts_with("$zip$1$*1*") && lines[0].entry == Some(1), "{}", lines[0].text);
}

// ---------------------------------------------------------------------------
// Pseudo-encryption
// ---------------------------------------------------------------------------

#[test]
fn entries_that_are_marked_and_open() {
    for rel in ["pseudo/pseudo.zip", "pseudo/pseudo_encrypted_zc.zip", "pseudo/edge_zip2_ignore_encryption_flag.zip"] {
        let Analysed { analysis, lines } = fixture(rel, Lines::All);
        assert!(lines.is_empty() && analysis.no_line.is_empty(), "{rel}");
        assert!(states(&analysis).contains(&State::PseudoEncrypted) && !states(&analysis).contains(&State::Encrypted), "{rel}");
        assert_eq!((analysis.coverage, analysis.schemes.len()), (Coverage::None, 0), "{rel}");
        assert!(codes(&analysis).contains(&"pseudo-encryption"), "{rel}");
        assert!(!analysis.is_encrypted(), "{rel}");
    }
}

/// The proof has the limits of `limits.rs` and no other: an entry of 11 MB is proven like one
/// of 11 bytes, and an entry with a real encryption header is not taken for an open one.
#[test]
fn the_proof_is_run_on_large_entries_too() {
    let big = vec![0x42_u8; 11_000_000];
    let stream = deflated(&big);
    let crc = Some(crc32fast::hash(&big));
    let locked = zip_crypto_data(500);
    let Analysed { analysis, lines } = built(&[Member { method: 8, crc, size: Some(11_000_000), ..member("big.bin", 1, &stream) }, Member { crc, size: Some(11_000_000), ..member("stored.bin", 1, &big) }, member("locked.bin", 1, &locked)], Lines::Best);
    assert_eq!(states(&analysis), [State::PseudoEncrypted, State::PseudoEncrypted, State::Encrypted]);
    assert_eq!(codes(&analysis), ["pseudo-encryption", "partial", "weak-scheme"]);
    assert_eq!((lines.len(), lines[0].entry), (1, Some(2)), "the line is that of the entry that is encrypted");
}

/// An entry that holds nothing proves nothing. With its flag and an encryption header it is
/// encrypted, and its line tests the check byte of that header.
#[test]
fn an_empty_entry_with_an_encryption_header_is_encrypted() {
    for rel in ["pseudo/gen_infozip_empty.zip", "pseudo/edge_libzip_empty-pkware.zip"] {
        let Analysed { analysis, lines } = fixture(rel, Lines::Best);
        assert_eq!(states(&analysis), [State::Encrypted], "{rel}");
        assert_eq!((analysis.entry_list[0].size, analysis.entry_list[0].packed), (Some(0), Some(12)), "{rel}");
        assert_eq!((lines.len(), lines[0].proves, lines[0].note), (1, Proves::Weak { bits: 8 }, Some(Note::EmptyEntry { checks: 1 })), "{rel}");
        assert!(!codes(&analysis).contains(&"pseudo-encryption") && codes(&analysis).contains(&"weak-check"), "{rel}");
    }
}

/// An entry the proof does not unpack stays encrypted, the analysis says the proof was not
/// run, and the entry still gets its line.
#[test]
fn an_entry_the_proof_was_not_run_on_is_encrypted_and_keeps_its_line() {
    let data = zip_crypto_data(300);
    let Analysed { analysis, lines } = built(&[Member { method: 12, ..member("a.bz2", 1, &data) }, member("stored.bin", 1, &data), member("open.txt", 0, b"plain")], Lines::All);
    assert_eq!(states(&analysis), [State::Encrypted, State::Encrypted, State::Plain]);
    let not_run = analysis.findings.iter().find(|finding| finding.code() == "proof-not-run").unwrap();
    assert_eq!((&not_run.found, not_run.entries.as_slice()), (&Found::ProofNotRun, &[0][..]), "the stored entry was put to the proof");
    assert_eq!(lines.len(), 2);

    // over the limit for one entry: a Deflate stream that starts like one and is said to
    // unpack to more than a gigabyte
    let stream = deflated(&vec![0x42_u8; 200_000]);
    let Analysed { analysis, lines } = built(&[Member { method: 8, size: Some((1 << 30) + 5), ..member("huge.bin", 1, &stream) }], Lines::Best);
    assert_eq!((states(&analysis), codes(&analysis).contains(&"proof-not-run"), lines.len()), (vec![State::Encrypted], true, 1));
}

/// An entry that is not marked is plain and nothing of it is read: not its local header, not
/// its data, whatever they are.
#[test]
fn an_entry_that_is_not_marked_is_not_looked_at() {
    // a checksum that is not that of the data, a local header that is none, data past the end
    let wrong = Member { crc: Some(1), ..member("wrong-crc.txt", 0, b"content") };
    let mut archive = Zip::of(&[wrong, member("no-header.txt", 0, b"more"), Member { declared: Some(0x00FF_FFFF), ..member("past-the-end.bin", 0, b"x") }]).build();
    let second = 30 + 13 + 7;
    archive[second..second + 4].copy_from_slice(b"JUNK");
    let Analysed { analysis, lines } = bytes(archive, Lines::All);
    assert_eq!(states(&analysis), [State::Plain; 3]);
    assert!(lines.is_empty() && analysis.no_line.is_empty());
    assert_eq!((analysis.coverage, analysis.volume), (Coverage::Unknown, Some(Volume::Incomplete)), "the directory names more than the file holds, and what is not listed may be encrypted");
    assert_eq!(codes(&analysis), ["incomplete"]);
}

// ---------------------------------------------------------------------------
// Which entry gives the line
// ---------------------------------------------------------------------------

/// An entry that cannot carry data never ranks before one that can: an empty directory that
/// is marked as WinZip AES used to rank first, give no line, and leave the archive without one.
#[test]
fn an_entry_without_data_never_ranks_before_one_with_data() {
    let extra = aes_extra(2, 3, 8);
    let data = aes_data(3, 9000);
    let empty = aes_data(3, 0);
    let Analysed { analysis, lines } = built(&[Member { method: 99, extra: &extra, ..member("docs/", 1, b"") }, Member { method: 99, extra: &extra, ..member("empty.txt", 1, &empty) }, Member { method: 99, extra: &extra, ..member("docs/a.bin", 1, &data) }], Lines::Best);
    assert_eq!((lines.len(), lines[0].entry, lines[0].proves), (1, Some(2), Proves::Exact));
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipWinzip, 0, NoLine::Empty)], "the directory has nothing to test and says so, whichever entry gave the line");
    assert_eq!((analysis.entry_list[0].kind, analysis.entry_list[0].state), (EntryKind::Directory, State::Encrypted));
    assert_eq!(analysis.coverage, Coverage::All);

    // every entry is asked with --all: the empty file has a line, the directory has nothing to test
    let Analysed { analysis, lines } = built(&[Member { method: 99, extra: &extra, ..member("docs/", 1, b"") }, Member { method: 99, extra: &extra, ..member("empty.txt", 1, &empty) }, Member { method: 99, extra: &extra, ..member("docs/a.bin", 1, &data) }], Lines::All);
    assert_eq!(lines.iter().map(|line| line.entry).collect::<Vec<_>>(), [Some(2), Some(1)]);
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipWinzip, 0, NoLine::Empty)]);
    assert_eq!(analysis.no_line[0].reason(), Reason::NoData);

    // ZipCrypto: an empty entry behind one whose line also tests its header alone
    let (lzma, header_only) = (zip_crypto_data(700), zip_crypto_data(0));
    let lines = built(&[member("empty.txt", 1, &header_only), Member { method: 14, ..member("a.lzma", 1, &lzma) }], Lines::Best).lines;
    assert_eq!((lines[0].entry, lines[0].note), (Some(1), Some(Note::NoDecoder { method: 14, checks: 2 })));
}

/// When the entry that ranks first gives no line, the next is asked, and the archive is left
/// without a line only when no entry gives one.
#[test]
fn the_next_entry_is_asked_when_the_best_gives_no_line() {
    // the smallest stored entry ranks first, and its data lies past the end of the file
    let (small, large) = (zip_crypto_data(20), zip_crypto_data(900));
    let members = [member("large.bin", 1, &large), member("small.bin", 1, &small)];
    let mut archive = Zip::of(&members).build();
    let directory = archive.windows(4).position(|window| window == b"PK\x01\x02").unwrap();
    let second = archive[directory + 4..].windows(4).position(|window| window == b"PK\x01\x02").unwrap() + directory + 4;
    // its central header says the entry starts 4 MiB in
    archive[second + 42..second + 46].copy_from_slice(&0x0040_0000_u32.to_le_bytes());
    let Analysed { analysis, lines } = bytes(archive, Lines::Best);
    assert_eq!((lines.len(), lines[0].entry), (1, Some(0)));
    assert_eq!(states(&analysis), [State::Encrypted, State::Undetermined]);
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipCrypto, 1, NoLine::Unreadable)], "an entry whose headers say it gives none says so, and does not stand in the way of the next");

    // an entry that only fails when it is asked: a method number the mode has no room for
    let Analysed { analysis, lines } = built(&[Member { method: 1000, ..member("odd.bin", 1, &small) }, Member { method: 14, ..member("a.lzma", 1, &large) }], Lines::Best);
    assert_eq!((lines.len(), lines[0].entry), (1, Some(1)));
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipCrypto, 0, NoLine::MethodNumber { method: 1000 })], "the one that ranks first says why it gives none");
    assert_eq!(analysis.entry_list[0].line, Some(EntryLine(Err(Reason::OverLimit))));

    // strong encryption: a cipher without a mode in front of AES, by size
    let (small_extra, extra) = (pkware_extra(0x6720, 128, 1), pkware_extra(0x6610, 256, 1));
    let blowfish = pkware_data(&DecryptionHeader { erd: noise(16), ..DecryptionHeader::password(0x6720, 128) });
    let aes = pkware_data(&DecryptionHeader::password(0x6610, 256));
    let Analysed { analysis, lines } = built(&[pkware_member("blowfish.bin", &small_extra, &blowfish), pkware_member("aes.bin", &extra, &aes)], Lines::Best);
    assert_eq!((lines.len(), lines[0].entry), (1, Some(1)), "AES ranks first");
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipPkware, 0, NoLine::PkwareCipher { cipher: Some(Cipher::Blowfish), identifier: 0x6720 })], "and the cipher without a mode says so beside it");

    // no entry gives a line: each says why
    let Analysed { analysis, lines } = built(&[Member { method: 1000, ..member("a", 1, &small) }, Member { method: 65535, ..member("b", 1, &large) }], Lines::Best);
    assert!(lines.is_empty());
    assert_eq!(analysis.no_line.iter().map(Missing::reason).collect::<Vec<_>>(), [Reason::OverLimit; 2]);
}

/// What mode 46100 loads is read off `zip_traditional.c`: eight checks, 4 MiB of data, a
/// method of three digits.
#[test]
fn a_zip_crypto_line_stays_within_what_its_mode_loads() {
    let data = zip_crypto_data(30);
    let members: Vec<Member<'_>> = (0..12).map(|_| member("same.bin", 1, &data)).collect();
    let Analysed { analysis, lines } = built(&members, Lines::Best);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].text.starts_with("$zip$1$*8*"), "eight checks and no more: {}", lines[0].text);
    assert_eq!(analysis.entry_list.len(), 12);

    // a stored entry past 4 MiB goes without its data, and one at 4 MiB with it
    let at_limit = zip_crypto_data(4 << 20);
    let lines = built(&[member("at-limit.bin", 1, &at_limit)], Lines::Best).lines;
    assert_eq!((lines[0].proves, lines[0].text.len() > 8 << 20), (Proves::Exact, true));
    let over = zip_crypto_data((4 << 20) + 1);
    let lines = built(&[member("over.bin", 1, &over)], Lines::Best).lines;
    assert_eq!((lines[0].proves, lines[0].note), (Proves::Weak { bits: 8 }, Some(Note::StoredTooLarge { stored: (4 << 20) + 1, limit: 4 << 20, checks: 1 })));
    assert!(lines[0].text.ends_with("*400001*$/zip$"), "the size is in the line and the data is not");

    // WinZip AES: the same limit on the data, and the same room for the method
    let extra = aes_extra(2, 1, 1000);
    let aes = aes_data(1, 40);
    let Analysed { analysis, lines } = built(&[Member { method: 99, extra: &extra, ..member("a.bin", 1, &aes) }], Lines::Best);
    assert!(lines.is_empty());
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipWinzip, 0, NoLine::MethodNumber { method: 1000 })]);
    let extra = aes_extra(2, 1, 0);
    let big = aes_data(1, (4 << 20) + 1);
    let lines = built(&[Member { method: 99, extra: &extra, ..member("a.bin", 1, &big) }], Lines::Best).lines;
    assert_eq!((lines[0].proves, lines[0].note), (Proves::Weak { bits: 16 }, Some(Note::VerifierOnly { packed: (4 << 20) + 1, limit: 4 << 20, method: 0 })));
}

/// An entry that is marked and too short for what its scheme puts in front of the data.
#[test]
fn an_entry_too_short_for_its_scheme_has_nothing_to_test() {
    let Analysed { analysis, lines } = built(&[member("nothing.bin", 1, b""), Member { method: 8, size: Some(40), ..member("short.bin", 1, &[0x5A; 7]) }], Lines::All);
    assert!(lines.is_empty());
    assert_eq!(states(&analysis), [State::Encrypted, State::Encrypted]);
    assert_eq!(analysis.no_line.iter().map(|missing| (missing.entry, missing.reason())).collect::<Vec<_>>(), [(Some(0), Reason::NoData), (Some(1), Reason::Damaged)]);

    let extra = aes_extra(2, 3, 0);
    let analysis = built(&[Member { method: 99, extra: &extra, ..member("short.bin", 1, &[0x5A; 27]) }], Lines::Best).analysis;
    assert_eq!(analysis.no_line[0].reason(), Reason::Damaged);
}

/// The most entries an archive without ZIP64 records can name, all of them marked and all at
/// the same place: each is looked at once, and the work is that of their number. A lookup
/// that compares every entry with every other one would take billions of steps here.
#[test]
fn sixty_five_thousand_marked_entries_at_one_place_are_no_long_work() {
    let data = zip_crypto_data(300);
    let single = Zip::of(&[member("same.bin", 1, &data)]).build();
    let directory = single.windows(4).position(|window| window == b"PK\x01\x02").unwrap();
    let header = &single[directory..single.len() - 22];
    let count = u16::MAX;

    let mut archive = single[..directory].to_vec();
    archive.extend(header.iter().copied().cycle().take(header.len() * usize::from(count)));
    archive.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    archive.extend_from_slice(&[count.to_le_bytes(), count.to_le_bytes()].concat());
    archive.extend_from_slice(&u32::try_from(header.len() * usize::from(count)).unwrap().to_le_bytes());
    archive.extend_from_slice(&u32::try_from(directory).unwrap().to_le_bytes());
    archive.extend_from_slice(&[0, 0]);

    let started = std::time::Instant::now();
    let Analysed { analysis, lines } = bytes(archive.clone(), Lines::Best);
    assert_eq!((analysis.entry_list.len(), analysis.coverage, analysis.schemes[0].key_groups), (usize::from(count), Coverage::All, Some(1)));
    assert!(lines.len() == 1 && lines[0].text.starts_with("$zip$1$*8*"), "{}", lines[0].text);
    // asked for every entry: the same line 65,535 times is one line
    assert_eq!(bytes(archive, Lines::All).lines.len(), 1);
    assert!(started.elapsed() < std::time::Duration::from_secs(20), "{:?}", started.elapsed());
}

// ---------------------------------------------------------------------------
// Volumes
// ---------------------------------------------------------------------------

/// The last volume of a spanned archive holds the central directory of all of it. An entry
/// that starts on another disk is not in this file and gets no line from it.
#[test]
fn the_last_volume_of_a_spanned_archive_gives_lines_for_its_own_entries() {
    let (first, last) = (zip_crypto_data(300), zip_crypto_data(40));
    let mut archive = Zip::of(&[Member { disk: 0, ..member("first.bin", 1, &first) }, Member { disk: 1, method: 99, ..member("middle.bin", 1, &first) }, Member { disk: 2, ..member("last.txt", 1, &last) }]).disk(2).build();
    // the two entries of other disks are not at their offsets in this file
    archive[0] = 0;
    let middle = 30 + 9 + 312;
    archive[middle + 30] ^= 0xFF;

    let Analysed { analysis, lines } = bytes(archive, Lines::All);
    assert_eq!(analysis.volume, Some(Volume::Later));
    assert_eq!(analysis.entry_list.iter().map(|entry| entry.split).collect::<Vec<_>>(), [Some(Split::Before), Some(Split::Before), Some(Split::No)]);
    assert_eq!(states(&analysis), [State::Undetermined, State::Undetermined, State::Encrypted], "ZipCrypto without its data, and a contradiction");
    assert_eq!((lines.len(), lines[0].entry), (1, Some(2)));
    assert_eq!(analysis.no_line[0], Missing::for_entry(Scheme::ZipCrypto, 0, NoLine::Split));
    assert_eq!(analysis.no_line[0].reason(), Reason::Split);
    assert!(codes(&analysis).contains(&"split-entry"));
    assert_eq!(analysis.findings.iter().find(|finding| finding.code() == "split-entry").unwrap().entries, [0, 1]);
}

/// The fixture is the last disk of two by its end record, and holds its one entry all the
/// same: a line is built from what is in the file.
#[test]
fn a_volume_that_holds_the_entry_its_directory_puts_elsewhere() {
    let Analysed { analysis, lines } = fixture("unparseable/multidisk_stub.zip", Lines::Best);
    assert_eq!((analysis.volume, analysis.entry_list[0].split, analysis.entry_list[0].state), (Some(Volume::Later), Some(Split::No), State::Encrypted));
    assert_eq!(lines.len(), 1);
}

/// The first volume of a split archive has the split marker and no central directory. Its
/// entries are read from their local headers, and the one that runs into the next volume has
/// no line.
#[test]
fn the_first_volume_of_a_split_archive_is_read_from_its_local_headers() {
    let (whole, cut) = (zip_crypto_data(40), zip_crypto_data(5000));
    let extra = aes_extra(2, 3, 0);
    let aes = aes_data(3, 100);
    let zip = Zip::of(&[member("whole.txt", 1, &whole), Member { method: 99, extra: &extra, ..member("aes.bin", 1, &aes) }, member("open.txt", 0, b"plain"), member("cut.bin", 1, &cut)]).build();
    let directory = zip.windows(4).position(|window| window == b"PK\x01\x02").unwrap();
    let mut volume = b"PK\x07\x08".to_vec();
    volume.extend_from_slice(&zip[..directory - 1000]);

    let Analysed { analysis, lines } = bytes(volume, Lines::All);
    assert_eq!((analysis.volume, analysis.offset, analysis.headers), (Some(Volume::First), 0, Headers::Readable));
    assert_eq!(states(&analysis), [State::Encrypted, State::Encrypted, State::Plain, State::Undetermined]);
    assert_eq!(analysis.entry_list.iter().map(|entry| entry.split).collect::<Vec<_>>(), [Some(Split::No), Some(Split::No), Some(Split::No), Some(Split::After)]);
    assert_eq!(lines.iter().map(|line| (line.tag, line.entry)).collect::<Vec<_>>(), [(Tag::Zip1, Some(0)), (Tag::Zip2, Some(1))]);
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipCrypto, 3, NoLine::Split)]);
    assert_eq!(codes(&analysis), ["mixed-schemes", "partial", "weak-scheme", "split-entry"]);
    // a local header does not say what wrote it: the check is taken as one byte
    assert_eq!(protection(&analysis, 0).parameters.check[0], Check::new(CheckKind::CheckByte, 8));
}

/// A file that holds less than its directory names is incomplete: the end of an archive that
/// was cut into pieces, or an entry whose data lies past the end of the file.
#[test]
fn a_file_that_holds_less_than_its_directory_names_is_incomplete() {
    let (a, b, c) = (zip_crypto_data(300), zip_crypto_data(300), zip_crypto_data(40));
    let zip = Zip::of(&[member("a.bin", 1, &a), member("b.bin", 1, &b), member("c.txt", 1, &c)]).build();
    let Analysed { analysis, lines } = bytes(zip[400..].to_vec(), Lines::All);
    assert_eq!(analysis.volume, Some(Volume::Incomplete));
    assert_eq!(states(&analysis), [State::Undetermined, State::Undetermined, State::Encrypted]);
    assert_eq!(analysis.entry_list.iter().map(|entry| entry.split).collect::<Vec<_>>(), [Some(Split::Before), Some(Split::Before), Some(Split::No)]);
    assert_eq!((lines.len(), lines[0].entry), (1, Some(2)));
    assert_eq!(analysis.no_line.iter().map(Missing::reason).collect::<Vec<_>>(), [Reason::Split, Reason::Split]);
    assert_eq!(codes(&analysis), ["weak-scheme", "split-entry", "incomplete"]);

    // an entry whose data lies past the end: its headers are there and its data is not
    let data = zip_crypto_data(40);
    let Analysed { analysis, lines } = built(&[Member { declared: Some(0x00FF_FFFF), ..member("cut.bin", 1, &data) }], Lines::Best);
    assert!(lines.is_empty());
    assert_eq!((analysis.volume, states(&analysis)), (Some(Volume::Incomplete), vec![State::Undetermined]));
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipCrypto, 0, NoLine::Unreadable)]);
    assert_eq!((analysis.no_line[0].reason(), analysis.entry_list[0].line), (Reason::Damaged, Some(EntryLine(Err(Reason::Damaged)))));
    assert!(codes(&analysis).contains(&"incomplete"));
}

// ---------------------------------------------------------------------------
// The archive as a whole
// ---------------------------------------------------------------------------

#[test]
fn the_variant_the_offset_and_the_comment() {
    let data = zip_crypto_data(40);
    let analysis = bytes(Zip::of(&[member("a.bin", 1, &data)]).comment(b"made by hand").build(), Lines::Best).analysis;
    assert_eq!((analysis.generation, analysis.offset, analysis.volume, analysis.comment.as_deref()), (Generation::Zip, 0, Some(Volume::Single), Some("made by hand")));

    // ZIP64 records, and a ZIP64 value in an extra field without them
    let analysis = bytes(Zip::of(&[member("a.bin", 1, &data)]).zip64().build(), Lines::Best).analysis;
    assert_eq!((analysis.generation, analysis.comment), (Generation::Zip64, None));
    assert_eq!(fixture("zip-crypto/zip64.zip", Lines::Best).analysis.generation, Generation::Zip64);

    // a comment that is not UTF-8 is still a comment
    let analysis = bytes(Zip::of(&[member("a.bin", 1, &data)]).comment(&[b'c', 0xE9, b'!']).build(), Lines::Best).analysis;
    assert_eq!(analysis.comment.as_deref(), Some("c\u{FFFD}!"));

    // behind a program, with and without ZIP64 records
    for zip64 in [false, true] {
        let members = [member("a.bin", 1, &data)];
        let zip = Zip::of(&members);
        let mut behind = b"MZ".to_vec();
        behind.resize(5000, 0x90);
        behind.extend_from_slice(&if zip64 { zip.zip64().build() } else { zip.build() });
        let Analysed { analysis, lines } = bytes(behind, Lines::Best);
        assert_eq!((analysis.offset, analysis.volume, lines.len()), (5000, Some(Volume::Single), 1), "ZIP64 {zip64}");
    }
}

#[test]
fn a_directory_does_not_count_for_coverage_however_it_is_told() {
    let data = zip_crypto_data(40);
    let analysis = built(&[member("by-name/", 0, b""), Member { made_by: 0x0A14, external: 0x10, ..member("by-attribute", 0, b"") }, member("locked.bin", 1, &data)], Lines::Best).analysis;
    assert_eq!(analysis.entry_list.iter().map(|entry| entry.kind).collect::<Vec<_>>(), [EntryKind::Directory, EntryKind::Directory, EntryKind::File]);
    assert_eq!((analysis.coverage, codes(&analysis)), (Coverage::All, vec!["weak-scheme"]));
}

/// Every reason for no line that a ZIP archive can lead to, and every finding, is produced
/// by a test of this file. This one holds the list.
#[test]
fn the_reasons_and_findings_zip_can_give() {
    let data = zip_crypto_data(40);
    let analysis = built(&[Member { method: 1000, ..member("a", 1, &data) }], Lines::Best).analysis;
    assert_eq!(analysis.no_line[0].reason(), Reason::OverLimit);
    // no-mode, no-password, unknown-scheme, over-limit, split, no-data and damaged are the
    // seven ZIP gives. Not-expressible and unsupported-parameters belong to RAR and 7-Zip: a
    // ZIP line says everything its mode tests, and no ZIP scheme has a parameter its own
    // software refuses.
    let given = [Reason::NoMode, Reason::NoPassword, Reason::UnknownScheme, Reason::OverLimit, Reason::Split, Reason::NoData, Reason::Damaged];
    assert_eq!(Reason::ALL.iter().filter(|reason| !given.contains(reason)).collect::<Vec<_>>(), [&Reason::UnsupportedParameters, &Reason::NotExpressible]);
}

/// A split archive as Info-ZIP writes it, read volume by volume: the first starts with the
/// split marker and has no central directory, the last has the directory of all of them and
/// starts in the middle of an entry.
#[test]
#[ignore = "runs zip"]
fn the_volumes_of_a_split_archive_written_by_zip() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a-first.txt"), b"the first entry is whole in the first volume\n").unwrap();
    std::fs::write(dir.path().join("b-large.bin"), noise(150_000)).unwrap();
    std::fs::write(dir.path().join("c-last.txt"), b"the last entry is whole in the last volume\n").unwrap();
    let status = std::process::Command::new("zip").current_dir(dir.path()).args(["-q", "-0", "-s", "64k", "-P", "volumes", "set.zip", "a-first.txt", "b-large.bin", "c-last.txt"]).status().unwrap_or_else(|error| panic!("zip could not be started: {error}: the test needs Info-ZIP's zip"));
    assert!(status.success(), "zip failed: {status}");
    let volume = |name: &str, wanted: Lines| analyse(&Source::open(&dir.path().join(name), 0).unwrap(), wanted).unwrap();
    let listed = |analysis: &Analysis| analysis.entry_list.iter().map(|entry| (entry.name.clone().unwrap(), entry.state, entry.split.unwrap())).collect::<Vec<_>>();

    let Analysed { analysis, lines } = volume("set.z01", Lines::All);
    assert_eq!((analysis.volume, analysis.headers), (Some(Volume::First), Headers::Readable));
    assert_eq!(listed(&analysis), [("a-first.txt".to_owned(), State::Encrypted, Split::No), ("b-large.bin".to_owned(), State::Undetermined, Split::After)]);
    assert_eq!((lines.len(), lines[0].entry, lines[0].proves), (1, Some(0), Proves::Exact));
    assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::ZipCrypto, 1, NoLine::Split)]);
    assert!(codes(&analysis).contains(&"split-entry"));

    let Analysed { analysis, lines } = volume("set.zip", Lines::All);
    assert_eq!(analysis.volume, Some(Volume::Later));
    assert_eq!(listed(&analysis), [("a-first.txt".to_owned(), State::Undetermined, Split::Before), ("b-large.bin".to_owned(), State::Undetermined, Split::Before), ("c-last.txt".to_owned(), State::Encrypted, Split::No)]);
    assert_eq!((lines.len(), lines[0].entry, lines[0].proves), (1, Some(2), Proves::Exact));
    assert_eq!(analysis.no_line.iter().map(Missing::reason).collect::<Vec<_>>(), [Reason::Split, Reason::Split]);

    // asked for the best line, the entries of other volumes are not asked at all
    assert!(volume("set.zip", Lines::Best).analysis.no_line.is_empty());
    // a volume between the two is the middle of an entry and no archive
    assert!(analyse(&Source::open(&dir.path().join("set.z02"), 0).unwrap(), Lines::Best).is_err());
}
