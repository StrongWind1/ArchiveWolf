//! Which entry of a RAR archive gets the line, and which entries can get none.
//!
//! Every encrypted entry is held against what its hashcat mode loads and can confirm a
//! password with ([`assess`]). An entry that passes is a [`Candidate`]: what its line is built
//! from, what the line proves, and its [`Rank`]. An entry that does not pass has the case that
//! stands in its way, and that is its reason when it is asked for a line.
//!
//! The rank puts first the entry whose line proves most, and among those the one that costs a
//! cracker least. A RAR 5 entry with a check value needs no data at all. Every other line
//! carries the encrypted data of its entry, whole: the checksum it is tested against covers
//! every byte, so a stream that is cut short could never confirm a password.
//!
//! The limits are those of the modes, read from their source in the hashcat fork
//! (`src/modules/rar_legacy.c` for modes 46500 and 46600, `module_46700.c`, `module_46800.c`).

use super::encryption::Rar50Record;
use super::encryption::RarEncryption;
use super::encryption::Unused;
use super::headers::RarEntry;
use crate::analysis::EntryKind;
use crate::analysis::NoLine;
use crate::analysis::Scheme;
use crate::line::Note;
use crate::line::Proves;

/// The most encrypted data a line carries: `RARL_DATA_MAX`, `RAR30_DATA_MAX` and
/// `RAR50_DATA_MAX` of the modes, which refuse a line with more. Two hex digits a byte keep
/// such a line well inside the line buffer of hashcat.
pub(crate) const MAX_INLINE_DATA: usize = 4 * 1024 * 1024;

/// What a `$rar$15$` or `$rar$20$` line prefers to carry: a stored entry of this size or
/// less is tested on the device by modes 46500 and 46600 (`RARL_KERNEL_DATA`), anything else
/// on host threads.
const PREFERRED_LEGACY_DATA: u64 = 256 * 1024;

/// What a `$rar$30$` or `$rar$50$` line prefers to carry: what the older modes for RAR 3
/// stop at.
const PREFERRED_DATA: u64 = 320 * 1024;

/// The largest unpacked size modes 46500 to 46700 take: their lines give it eight hex digits.
const MAX_UNPACKED_LEGACY: u64 = 0xFFFF_FFFF;

/// The fewest bytes a checksum has to cover to prove more than the bytes themselves.
const CHECKSUM_BYTES: u64 = 4;

/// The kind of line that carries the data of an entry, with what it takes from the encryption
/// of the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataLine {
    /// `$rar$15$`.
    Rar15,
    /// `$rar$20$`.
    Rar20,
    /// `$rar$30$` type 1, with the salt of the entry.
    Rar30 {
        /// The salt.
        salt: [u8; 8],
    },
    /// `$rar$50$` type 1, with the encryption record of the entry.
    Rar50(Rar50Record),
}

impl DataLine {
    /// The scheme the line is for.
    const fn scheme(&self) -> Scheme {
        match self {
            Self::Rar15 => Scheme::Rar15,
            Self::Rar20 => Scheme::Rar20,
            Self::Rar30 { .. } => Scheme::Rar30,
            Self::Rar50(_) => Scheme::Rar50,
        }
    }
}

/// What the line of an entry is built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plan {
    /// The check value in the encryption record of a RAR 5 entry: `$rar$50$` type 0.
    CheckValue {
        /// The encryption record.
        crypt: Rar50Record,
        /// Its check value.
        value: [u8; 8],
    },
    /// The encrypted data of the entry and the checksum of what it unpacks to.
    Data {
        /// The kind of line.
        line: DataLine,
        /// Size of what the entry unpacks to.
        unpacked: u64,
    },
}

/// The rank of an entry among the entries that can give a line. Lower is better, and the
/// fields compare in their order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Rank {
    /// How much less than a full check the line proves: 0 for a line that is exact.
    weakness: u8,
    /// The entry cannot carry data: a directory or an empty file. Such an entry never comes
    /// before one that can.
    no_data: bool,
    /// The line carries the data of the entry, which a line on a check value does not need.
    carries_data: bool,
    /// The data is more than its line prefers to carry.
    oversize: bool,
    /// The data has to be unpacked before its checksum can be tested.
    compressed: bool,
    /// The exponent of the round count of RAR 5.
    lg2count: u8,
    /// Size of the encrypted data the line carries.
    data_size: u64,
}

/// An entry that can give a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Candidate {
    /// What the line is built from.
    pub plan: Plan,
    /// What the line lets a cracker confirm a password by.
    pub proves: Proves,
    /// Why that is less than a checksum over the whole entry, when it is.
    pub note: Option<Note>,
    /// Where the entry stands among the candidates.
    pub rank: Rank,
}

/// Whether an entry can carry data: it is no directory and not empty.
fn can_carry_data(entry: &RarEntry) -> bool {
    entry.kind != EntryKind::Directory && entry.packed > 0 && entry.unpacked != Some(0)
}

/// Whether the encrypted data is a whole number of the 16-byte blocks its cipher works on.
const fn whole_blocks(packed: u64) -> bool {
    packed.is_multiple_of(16)
}

/// The case that keeps a compression method out of a line, when its mode does not unpack it.
/// `scheme` is the scheme of the entry.
fn packing(scheme: Scheme, entry: &RarEntry) -> Option<NoLine> {
    if scheme == Scheme::Rar50 {
        // modes take methods 0 to 5, and unpack the algorithms of RAR 5 and RAR 7
        if entry.method > 5 {
            return Some(NoLine::Packing { name: format!("method {}", entry.method) });
        }
        return (!entry.stored && entry.algorithm > 1).then(|| NoLine::Packing { name: format!("version {} of the compression algorithm", entry.algorithm) });
    }
    (!(0x30..=0x35).contains(&entry.method)).then(|| NoLine::Packing { name: format!("method 0x{:02x}", entry.method) })
}

/// Hold the data of an entry against what the mode of `scheme` loads. `len` is the size of
/// the archive.
fn data_fits(scheme: Scheme, entry: &RarEntry, len: u64) -> Result<u64, NoLine> {
    if entry.is_split() {
        return Err(NoLine::Split);
    }
    if entry.packed == 0 || entry.unpacked == Some(0) {
        return Err(NoLine::Empty);
    }
    if scheme == Scheme::Rar50 && !entry.has_crc32 && entry.blake2sp.is_none() {
        return Err(NoLine::NoChecksum);
    }
    if entry.solid && !entry.stored {
        return Err(NoLine::SolidMember);
    }
    let unpacked = entry.unpacked.ok_or(NoLine::SizeUnknown)?;
    if let Some(case) = packing(scheme, entry) {
        return Err(case);
    }
    if scheme != Scheme::Rar50 && unpacked > MAX_UNPACKED_LEGACY {
        return Err(NoLine::UnpacksTooLarge { size: unpacked, limit: MAX_UNPACKED_LEGACY });
    }
    let limit = u64::try_from(MAX_INLINE_DATA).unwrap_or(u64::MAX);
    if entry.packed > limit {
        return Err(NoLine::TooLarge { packed: entry.packed, limit });
    }
    if scheme != Scheme::Rar15 && !whole_blocks(entry.packed) {
        return Err(NoLine::NotWholeBlocks);
    }
    // a stored entry is as long as its data, or as its data filled up to whole blocks
    let stored_fits = match scheme {
        Scheme::Rar15 => entry.packed == unpacked,
        Scheme::Rar20 => unpacked.checked_next_multiple_of(16) == Some(entry.packed),
        _ => unpacked <= entry.packed,
    };
    if entry.stored && !stored_fits {
        return Err(NoLine::SizesDisagree);
    }
    if !entry.data_is_inside(len) {
        return Err(NoLine::DataOutsideFile);
    }
    Ok(unpacked)
}

/// A line that carries the data of the entry.
fn data_candidate(line: DataLine, entry: &RarEntry, len: u64) -> Result<Candidate, NoLine> {
    let scheme = line.scheme();
    let unpacked = data_fits(scheme, entry, len)?;
    // a checksum over one, two or three bytes says no more than those bytes do
    let short = u8::try_from(unpacked).ok().filter(|&size| u64::from(size) < CHECKSUM_BYTES);
    let (proves, note) = match short {
        Some(size) => (Proves::Weak { bits: 8 * u32::from(size) }, Some(Note::ShortEntry { size: u64::from(size) })),
        None => (Proves::Exact, None),
    };
    let preferred = if matches!(scheme, Scheme::Rar15 | Scheme::Rar20) { PREFERRED_LEGACY_DATA } else { PREFERRED_DATA };
    let rank = Rank {
        weakness: short.map_or(0, |size| 4_u8.saturating_sub(size)),
        no_data: entry.kind == EntryKind::Directory,
        carries_data: true,
        oversize: entry.packed > preferred,
        compressed: !entry.stored,
        lg2count: if let DataLine::Rar50(crypt) = line { crypt.lg2count } else { 0 },
        data_size: entry.packed,
    };
    Ok(Candidate { plan: Plan::Data { line, unpacked }, proves, note, rank })
}

/// Hold an encrypted entry against what the mode of its scheme loads and can confirm a
/// password with. `len` is the size of the archive.
///
/// `None` for an entry that is not encrypted. `Err` is the case that keeps the entry from a
/// line.
pub(crate) fn assess(entry: &RarEntry, len: u64) -> Option<Result<Candidate, NoLine>> {
    Some(match entry.encryption {
        RarEncryption::None => return None,
        RarEncryption::Rar13 => Err(NoLine::NoMode(Scheme::Rar13)),
        RarEncryption::Unknown { .. } => Err(NoLine::UnknownScheme),
        RarEncryption::Unreadable(_) => Err(NoLine::Unreadable),
        RarEncryption::Rar15 => data_candidate(DataLine::Rar15, entry, len),
        RarEncryption::Rar20 => data_candidate(DataLine::Rar20, entry, len),
        // the key of such an entry is derived without a salt, and a line always has one
        RarEncryption::Rar30 { salt: None } => Err(NoLine::NoSalt),
        RarEncryption::Rar30 { salt: Some(salt) } => data_candidate(DataLine::Rar30 { salt }, entry, len),
        RarEncryption::Rar50(crypt) => match (rounds_fit(&crypt), crypt.check_value) {
            (Err(case), _) => Err(case),
            // a check value needs nothing of the entry: not its data, and not the rest of it
            (Ok(()), Some(value)) => {
                let rank = Rank { weakness: 0, no_data: !can_carry_data(entry), carries_data: false, oversize: false, compressed: false, lg2count: crypt.lg2count, data_size: 0 };
                Ok(Candidate { plan: Plan::CheckValue { crypt, value }, proves: Proves::Exact, note: None, rank })
            },
            // without one, or with one that does not count, the entry is tested by its data.
            // When it has none to test, the check value that could not be used is why no
            // password can be confirmed.
            (Ok(()), None) => data_candidate(DataLine::Rar50(crypt), entry, len).map_err(|why| match (crypt.unused, &why) {
                (Some(Unused::Zero), NoLine::Empty | NoLine::NoChecksum) => NoLine::ZeroCheckValue,
                (Some(Unused::Damaged), NoLine::Empty | NoLine::NoChecksum) => NoLine::CheckValueDamaged,
                _ => why,
            }),
        },
    })
}

/// Hold the round count of a RAR 5 encryption record against what UnRAR accepts and what
/// mode 46800 loads: UnRAR refuses more than 2^24 rounds, and the mode a count of 2^0.
pub(crate) const fn rounds_fit(crypt: &Rar50Record) -> Result<(), NoLine> {
    if !crypt.rounds_accepted() {
        Err(NoLine::RoundsRefused { power: crypt.lg2count })
    } else if crypt.lg2count == 0 {
        Err(NoLine::RoundsBelowMode { power: crypt.lg2count })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plenty large archive: no entry of a test lies outside it unless the test says so.
    const LEN: u64 = 1 << 40;

    fn rar_50(lg2count: u8, check_value: bool) -> RarEncryption {
        RarEncryption::Rar50(Rar50Record { lg2count, salt: [1; 16], iv: [2; 16], check_value: check_value.then_some([3; 8]), unused: None, hashmac: false })
    }

    const RAR_30: RarEncryption = RarEncryption::Rar30 { salt: Some([7; 8]) };

    /// A stored entry of `packed` bytes under `encryption`, with the method its generation
    /// stores for stored data.
    fn stored(encryption: RarEncryption, packed: u64) -> RarEntry {
        let mut entry = RarEntry::new(EntryKind::File, 100);
        entry.encryption = encryption;
        entry.packed = packed;
        entry.unpacked = Some(packed);
        entry.method = if matches!(encryption, RarEncryption::Rar50(_)) { 0 } else { 0x30 };
        entry
    }

    /// The same, packed with the usual method to `packed` bytes from ten times as many.
    fn packed(encryption: RarEncryption, packed: u64) -> RarEntry {
        let mut entry = stored(encryption, packed);
        entry.unpacked = Some(packed * 10);
        entry.method += 3;
        entry.stored = false;
        entry
    }

    fn candidate(entry: &RarEntry) -> Candidate {
        assess(entry, LEN).unwrap().unwrap()
    }

    fn refused(entry: &RarEntry) -> NoLine {
        assess(entry, LEN).unwrap().unwrap_err()
    }

    fn rank(entry: &RarEntry) -> Rank {
        candidate(entry).rank
    }

    #[test]
    fn an_entry_that_is_not_encrypted_is_not_assessed() {
        assert_eq!(assess(&stored(RarEncryption::None, 64), LEN), None);
    }

    #[test]
    fn a_check_value_comes_before_any_data() {
        let checked = stored(rar_50(15, true), 1000);
        let unchecked = stored(rar_50(15, false), 1008);
        assert!(matches!(candidate(&checked).plan, Plan::CheckValue { crypt, value: [3, 3, 3, 3, 3, 3, 3, 3] } if crypt.lg2count == 15));
        assert!(matches!(candidate(&unchecked).plan, Plan::Data { line: DataLine::Rar50(crypt), unpacked: 1008 } if crypt.check_value.is_none()));
        assert!(rank(&checked) < rank(&unchecked));
        assert_eq!(candidate(&checked).proves, Proves::Exact);

        // of two check values, the one whose key costs less
        assert!(rank(&stored(rar_50(10, true), 0)) < rank(&stored(rar_50(20, true), 0)));
    }

    #[test]
    fn a_check_value_needs_nothing_of_its_entry() {
        // split, empty, a directory, larger than any line, packed in a solid chain
        let mut odd = packed(rar_50(15, true), 1 << 30);
        odd.split_before = true;
        odd.split_after = true;
        odd.solid = true;
        odd.unpacked = None;
        assert!(matches!(candidate(&odd).plan, Plan::CheckValue { .. }));

        let mut empty = stored(rar_50(15, true), 0);
        assert!(matches!(candidate(&empty).plan, Plan::CheckValue { .. }));
        empty.kind = EntryKind::Directory;
        assert!(matches!(candidate(&empty).plan, Plan::CheckValue { .. }));
    }

    #[test]
    fn an_entry_that_cannot_carry_data_never_comes_before_one_that_can() {
        let mut directory = stored(rar_50(15, true), 0);
        directory.kind = EntryKind::Directory;
        let empty = stored(rar_50(15, true), 0);
        let file = stored(rar_50(15, true), 64);
        let unchecked = packed(rar_50(15, false), 4096);
        // a line on data costs more than one on a check value, and comes first all the same
        for holds_nothing in [&directory, &empty] {
            assert!(rank(&file) < rank(holds_nothing));
            assert!(rank(&unchecked) < rank(holds_nothing));
        }
    }

    #[test]
    fn data_is_ranked_by_what_it_costs_to_test() {
        // stored before packed, whatever the sizes
        assert!(rank(&stored(RAR_30, 5008)) < rank(&packed(RAR_30, 112)));
        // the smaller of two of a kind
        assert!(rank(&stored(RAR_30, 48)) < rank(&stored(RAR_30, 496)));
        // what a line prefers to carry before what is over that, stored or not
        assert!(rank(&packed(RAR_30, 150_000)) < rank(&stored(RAR_30, 434_464)));
        assert!(rank(&stored(RarEncryption::Rar15, 200_000)) < rank(&stored(RarEncryption::Rar15, 300_000)));
        assert!(rank(&packed(RarEncryption::Rar15, 1000)) < rank(&stored(RarEncryption::Rar15, 300_000)), "256 KiB is what the device tests");
        // a cheaper key before a smaller entry
        assert!(rank(&stored(rar_50(15, false), 4096)) < rank(&stored(rar_50(16, false), 64)));
    }

    #[test]
    fn a_checksum_over_fewer_than_four_bytes_is_weak_and_comes_last() {
        for size in 1..4_u64 {
            let short = stored(RAR_30, 16);
            let short = RarEntry { unpacked: Some(size), ..short };
            let bits = 8 * u32::try_from(size).unwrap();
            assert_eq!((candidate(&short).proves, candidate(&short).note), (Proves::Weak { bits }, Some(Note::ShortEntry { size })));
            // any entry with a full check comes first, however large and however packed
            assert!(rank(&packed(RAR_30, 4 << 20)) < rank(&short));
        }
        let longer = |size: u64| rank(&RarEntry { unpacked: Some(size), ..stored(RAR_30, 16) });
        assert!(longer(3) < longer(2) && longer(2) < longer(1), "more bytes prove more");

        let four = RarEntry { unpacked: Some(4), ..stored(RAR_30, 16) };
        assert_eq!((candidate(&four).proves, candidate(&four).note), (Proves::Exact, None));
    }

    #[test]
    fn schemes_without_a_line_have_their_case() {
        assert_eq!(refused(&stored(RarEncryption::Rar13, 64)), NoLine::NoMode(Scheme::Rar13));
        assert_eq!(refused(&stored(RarEncryption::Unknown { version: 2 }, 64)), NoLine::UnknownScheme);
        assert_eq!(refused(&stored(RarEncryption::Unreadable(Scheme::Rar50), 64)), NoLine::Unreadable);
    }

    #[test]
    fn a_round_count_outside_what_is_accepted_gives_no_line() {
        // above 2^24 UnRAR refuses the archive, with a check value or without
        assert_eq!(refused(&stored(rar_50(25, true), 64)), NoLine::RoundsRefused { power: 25 });
        assert_eq!(refused(&stored(rar_50(255, false), 64)), NoLine::RoundsRefused { power: 255 });
        assert!(assess(&stored(rar_50(24, true), 64), LEN).unwrap().is_ok());
        // mode 46800 loads no line with a count of 2^0
        assert_eq!(refused(&stored(rar_50(0, true), 64)), NoLine::RoundsBelowMode { power: 0 });
        assert!(assess(&stored(rar_50(1, true), 64), LEN).unwrap().is_ok());
    }

    #[test]
    fn an_entry_whose_data_is_not_whole_or_not_there_gives_no_line() {
        let mut split = stored(RAR_30, 64);
        split.split_after = true;
        assert_eq!(refused(&split), NoLine::Split);
        split.split_after = false;
        split.split_before = true;
        assert_eq!(refused(&split), NoLine::Split);

        assert_eq!(refused(&stored(RAR_30, 0)), NoLine::Empty);
        assert_eq!(refused(&RarEntry { unpacked: Some(0), ..stored(RAR_30, 16) }), NoLine::Empty);

        // the data lies behind the end of the archive
        let inside = stored(RAR_30, 64);
        assert!(assess(&inside, 164).unwrap().is_ok());
        assert_eq!(assess(&inside, 163).unwrap(), Err(NoLine::DataOutsideFile));
    }

    #[test]
    fn an_entry_under_rar_3_without_a_salt_gives_no_line() {
        let unsalted = stored(RarEncryption::Rar30 { salt: None }, 64);
        assert_eq!(refused(&unsalted), NoLine::NoSalt);
        assert_eq!(candidate(&stored(RAR_30, 64)).plan, Plan::Data { line: DataLine::Rar30 { salt: [7; 8] }, unpacked: 64 });
    }

    #[test]
    fn an_entry_under_rar_5_without_a_checksum_has_nothing_to_test() {
        let mut bare = stored(rar_50(15, false), 64);
        bare.has_crc32 = false;
        assert_eq!(refused(&bare), NoLine::NoChecksum);
        bare.blake2sp = Some([9; 32]);
        assert!(assess(&bare, LEN).unwrap().is_ok());
        // with a check value the data is not needed at all
        let mut checked = stored(rar_50(15, true), 64);
        checked.has_crc32 = false;
        assert!(assess(&checked, LEN).unwrap().is_ok());
    }

    #[test]
    fn a_packed_member_of_a_solid_archive_gives_no_line() {
        let mut chained = packed(RAR_30, 112);
        chained.solid = true;
        assert_eq!(refused(&chained), NoLine::SolidMember);
        // a stored member does not need the entries before it
        let mut stored_member = stored(RAR_30, 112);
        stored_member.solid = true;
        assert!(assess(&stored_member, LEN).unwrap().is_ok());
    }

    #[test]
    fn a_size_that_is_not_known_or_too_large_gives_no_line() {
        assert_eq!(refused(&RarEntry { unpacked: None, ..packed(RAR_30, 112) }), NoLine::SizeUnknown);

        // the modes for RAR 1.5 to 4 take an unpacked size of 32 bits
        for encryption in [RarEncryption::Rar15, RarEncryption::Rar20, RAR_30] {
            let large = RarEntry { unpacked: Some(1 << 32), ..packed(encryption, 112) };
            assert_eq!(refused(&large), NoLine::UnpacksTooLarge { size: 1 << 32, limit: 0xFFFF_FFFF });
            assert!(assess(&RarEntry { unpacked: Some(0xFFFF_FFFF), ..large }, LEN).unwrap().is_ok());
        }
        assert!(assess(&RarEntry { unpacked: Some(1 << 44), ..packed(rar_50(15, false), 112) }, LEN).unwrap().is_ok(), "the mode for RAR 5 takes 64 bits");

        // a line carries four mebibytes of data and no more
        let limit = 4 << 20;
        for encryption in [RarEncryption::Rar15, RarEncryption::Rar20, RAR_30, rar_50(15, false)] {
            assert!(assess(&packed(encryption, limit), LEN).unwrap().is_ok());
            assert_eq!(refused(&packed(encryption, limit + 16)), NoLine::TooLarge { packed: limit + 16, limit });
        }
    }

    #[test]
    fn a_method_the_mode_does_not_unpack_gives_no_line() {
        for encryption in [RarEncryption::Rar15, RarEncryption::Rar20, RAR_30] {
            for method in [0x2F, 0x36, 0x00, 0xFF] {
                let odd = RarEntry { method, stored: false, ..packed(encryption, 112) };
                assert_eq!(refused(&odd), NoLine::Packing { name: format!("method 0x{method:02x}") });
            }
            assert!(assess(&RarEntry { method: 0x35, ..packed(encryption, 112) }, LEN).unwrap().is_ok());
        }
        let rar5 = |method: u8, algorithm: u8| RarEntry { method, algorithm, stored: method == 0, ..packed(rar_50(15, false), 112) };
        assert_eq!(refused(&rar5(6, 0)), NoLine::Packing { name: "method 6".to_owned() });
        assert_eq!(refused(&rar5(3, 2)), NoLine::Packing { name: "version 2 of the compression algorithm".to_owned() });
        assert!(assess(&rar5(5, 1), LEN).unwrap().is_ok(), "RAR 7");
        // what is stored needs no algorithm
        assert!(assess(&RarEntry { unpacked: Some(100), ..rar5(0, 9) }, LEN).unwrap().is_ok());
    }

    #[test]
    fn sizes_that_do_not_fit_their_cipher_give_no_line() {
        // the ciphers of RAR 2.0, 3 and 5 work on blocks of 16 bytes
        for encryption in [RarEncryption::Rar20, RAR_30, rar_50(15, false)] {
            assert_eq!(refused(&packed(encryption, 100)), NoLine::NotWholeBlocks);
            assert!(assess(&packed(encryption, 96), LEN).unwrap().is_ok());
        }
        assert!(assess(&packed(RarEncryption::Rar15, 100), LEN).unwrap().is_ok(), "RAR 1.5 encrypts byte by byte");

        // a stored entry is as long as its data, filled up to whole blocks where there are blocks
        let sized = |encryption, packed: u64, unpacked: u64| assess(&RarEntry { unpacked: Some(unpacked), ..stored(encryption, packed) }, LEN).unwrap();
        assert!(sized(RarEncryption::Rar15, 100, 100).is_ok());
        assert_eq!(sized(RarEncryption::Rar15, 100, 99), Err(NoLine::SizesDisagree));
        assert!(sized(RarEncryption::Rar20, 112, 100).is_ok() && sized(RarEncryption::Rar20, 112, 112).is_ok());
        assert_eq!(sized(RarEncryption::Rar20, 112, 96), Err(NoLine::SizesDisagree));
        assert_eq!(sized(RarEncryption::Rar20, 112, 113), Err(NoLine::SizesDisagree));
        assert!(sized(RAR_30, 112, 100).is_ok() && sized(RAR_30, 112, 5).is_ok());
        assert_eq!(sized(RAR_30, 112, 113), Err(NoLine::SizesDisagree));
        assert_eq!(sized(rar_50(15, false), 112, 113), Err(NoLine::SizesDisagree));
    }
}
