//! Building 7z archives byte by byte, for tests.
//!
//! The unit tests of this format and its integration tests (`tests/7z_*_test.rs`) both read
//! this file, so that one description of the format builds every crafted archive. The unit
//! tests use the pieces. The integration tests use [`hostile`], the inputs that once ended in
//! a panic, an abort or minutes of work, and so every piece here is used by it.

/// The identifier of the 7zAES coder.
pub(crate) const AES: &[u8] = &[0x06, 0xF1, 0x07, 0x01];
/// The identifier of the LZMA2 coder.
pub(crate) const LZMA2: &[u8] = &[0x21];
/// The identifier of the LZMA coder.
pub(crate) const LZMA: &[u8] = &[0x03, 0x01, 0x01];
/// The identifier of the `PPMd` coder.
pub(crate) const PPMD: &[u8] = &[0x03, 0x04, 0x01];
/// The identifier of the BCJ2 coder.
pub(crate) const BCJ2: &[u8] = &[0x03, 0x03, 0x01, 0x1B];

/// Properties LZMA takes: lc=3, lp=0, pb=2 and a dictionary of 64 KiB.
pub(crate) const LZMA_PROPS: &[u8] = &[0x5D, 0x00, 0x00, 0x01, 0x00];

/// The low `count` bytes of a value, little-endian.
fn le(value: u64, count: usize) -> impl Iterator<Item = u8> {
    value.to_le_bytes().into_iter().take(count)
}

fn len_of<T>(items: &[T]) -> u64 {
    u64::try_from(items.len()).unwrap_or(u64::MAX)
}

/// A number in the variable length form of the format: the high bits of the first byte say
/// how many bytes follow.
pub(crate) fn number(value: u64) -> Vec<u8> {
    if value < 0x80 {
        return le(value, 1).collect();
    }
    for extra in 1..8_usize {
        if value < 1 << (7 * extra + 7) {
            let marker = (0xFF_u64 << (8 - extra)) & 0xFF;
            return le(marker | (value >> (8 * extra)), 1).chain(le(value, extra)).collect();
        }
    }
    le(0xFF, 1).chain(le(value, 8)).collect()
}

/// One coder of a folder. `streams` is how many inputs and outputs it says it has; `None` is
/// the short form of a coder with one of each.
pub(crate) fn coder(id: &[u8], props: &[u8], streams: Option<(u64, u64)>) -> Vec<u8> {
    let flags = len_of(id) | if streams.is_some() { 0x10 } else { 0 } | if props.is_empty() { 0 } else { 0x20 };
    let mut out: Vec<u8> = le(flags, 1).collect();
    out.extend_from_slice(id);
    if let Some((inputs, outputs)) = streams {
        out.extend(number(inputs));
        out.extend(number(outputs));
    }
    if !props.is_empty() {
        out.extend(number(len_of(props)));
        out.extend_from_slice(props);
    }
    out
}

/// The properties of a 7zAES coder: `2^power` rounds, a salt and an initialisation vector of
/// up to 16 bytes each.
pub(crate) fn aes_props(power: u8, salt: &[u8], iv: &[u8]) -> Vec<u8> {
    let first = power | if iv.is_empty() { 0 } else { 0x40 } | if salt.is_empty() { 0 } else { 0x80 };
    if salt.is_empty() && iv.is_empty() {
        return vec![first];
    }
    let sizes = (len_of(salt).saturating_sub(1) << 4) | len_of(iv).saturating_sub(1);
    let mut out = vec![first];
    out.extend(le(sizes, 1));
    out.extend_from_slice(salt);
    out.extend_from_slice(iv);
    out
}

/// An archive: the signature header with both checksums right, the packed streams, and the
/// header behind them.
pub(crate) fn archive(header: &[u8], packed: &[u8]) -> Vec<u8> {
    let start: Vec<u8> = le(len_of(packed), 8).chain(le(len_of(header), 8)).chain(le(u64::from(crc32fast::hash(header)), 4)).collect();
    let mut out = b"7z\xBC\xAF\x27\x1C\x00\x04".to_vec();
    out.extend_from_slice(&crc32fast::hash(&start).to_le_bytes());
    out.extend_from_slice(&start);
    out.extend_from_slice(packed);
    out.extend_from_slice(header);
    out
}

/// The coders of a folder in which each coder reads what the next one writes: the first gives
/// the output of the folder, the last reads the one packed stream. Each is an id with its
/// properties.
pub(crate) fn chain(coders: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = number(len_of(coders));
    for (id, props) in coders {
        out.extend(coder(id, props, None));
    }
    for feeder in 1..len_of(coders) {
        out.extend(number(feeder - 1));
        out.extend(number(feeder));
    }
    out
}

/// The coders of a folder as 7-Zip writes it with BCJ2 and a password: BCJ2 over four streams,
/// three of them packed with LZMA, each of the four behind a 7zAES coder with the properties
/// given for it.
pub(crate) fn bcj2(keys: [&[u8]; 4]) -> Vec<u8> {
    let mut out = number(8);
    out.extend(coder(BCJ2, &[], Some((4, 1))));
    for _ in 0..3 {
        out.extend(coder(LZMA, LZMA_PROPS, None));
    }
    for props in keys {
        out.extend(coder(AES, props, None));
    }
    // the inputs of BCJ2 are 0 to 3, those of the packers 4 to 6, those of the ciphers 7 to 10
    for (input, feeder) in [(0, 1), (1, 2), (2, 3), (3, 7), (4, 4), (5, 5), (6, 6)] {
        out.extend(number(input));
        out.extend(number(feeder));
    }
    for input in 7..11 {
        out.extend(number(input));
    }
    out
}

/// One folder of a crafted archive.
#[derive(Debug, Clone, Default)]
pub(crate) struct Folder {
    /// Its coders and their connections, as the header stores them: [`chain`], [`bcj2`], or
    /// bytes of one's own.
    pub coders: Vec<u8>,
    /// Size of the output of every coder.
    pub sizes: Vec<u64>,
    /// Sizes of its packed streams.
    pub packs: Vec<u64>,
    /// The CRC-32 of what it unpacks to.
    pub crc: Option<u32>,
    /// The files it holds, each with its size and its CRC-32. Empty for one file that is all
    /// the folder unpacks to.
    pub files: Vec<(u64, Option<u32>)>,
}

impl Folder {
    /// A folder of one file. `sizes` are those of its coders, and its one packed stream has
    /// `packed` bytes.
    pub(crate) fn new(coders: Vec<u8>, sizes: &[u64], packed: u64, crc: Option<u32>) -> Self {
        Self { coders, sizes: sizes.to_vec(), packs: vec![packed], crc, files: Vec::new() }
    }

    fn file_count(&self) -> u64 {
        if self.files.is_empty() { 1 } else { len_of(&self.files) }
    }
}

/// A list of CRC-32 values of which some may be missing.
fn digests(values: &[Option<u32>]) -> Vec<u8> {
    let mut out = Vec::new();
    if values.iter().all(Option::is_some) {
        out.push(1);
    } else {
        out.push(0);
        for group in values.chunks(8) {
            out.push(group.iter().enumerate().fold(0_u8, |bits, (place, value)| if value.is_some() { bits | (0x80 >> place) } else { bits }));
        }
    }
    for value in values.iter().flatten() {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

/// The `StreamsInfo` block over these folders: their packed streams one behind the other from
/// `pack_pos` on, the folders, and the files inside them when a folder lists any.
pub(crate) fn streams(folders: &[Folder], pack_pos: u64) -> Vec<u8> {
    let packs: Vec<u64> = folders.iter().flat_map(|folder| folder.packs.iter().copied()).collect();
    let mut out = vec![0x06];
    out.extend(number(pack_pos));
    out.extend(number(len_of(&packs)));
    out.push(0x09);
    out.extend(packs.iter().flat_map(|&size| number(size)));
    out.push(0x00);

    out.extend_from_slice(&[0x07, 0x0B]);
    out.extend(number(len_of(folders)));
    out.push(0x00);
    out.extend(folders.iter().flat_map(|folder| folder.coders.iter().copied()));
    out.push(0x0C);
    out.extend(folders.iter().flat_map(|folder| folder.sizes.iter().flat_map(|&size| number(size))));
    if folders.iter().any(|folder| folder.crc.is_some()) {
        out.push(0x0A);
        out.extend(digests(&folders.iter().map(|folder| folder.crc).collect::<Vec<_>>()));
    }
    out.push(0x00);

    if folders.iter().any(|folder| !folder.files.is_empty()) {
        out.extend_from_slice(&[0x08, 0x0D]);
        out.extend(folders.iter().flat_map(|folder| number(folder.file_count())));
        out.push(0x09);
        for folder in folders {
            // every file but the last has its size here
            out.extend(folder.files.iter().rev().skip(1).rev().flat_map(|&(size, _)| number(size)));
        }
        // a folder of one file with a checksum of its own does not repeat it
        let listed: Vec<Option<u32>> = folders.iter().filter(|folder| !(folder.file_count() == 1 && folder.crc.is_some())).flat_map(|folder| if folder.files.is_empty() { vec![None] } else { folder.files.iter().map(|&(_, crc)| crc).collect() }).collect();
        if listed.iter().any(Option::is_some) {
            out.push(0x0A);
            out.extend(digests(&listed));
        }
        out.push(0x00);
    }

    out.push(0x00);
    out
}

/// The list of files of a header: `names`, of which none is without data.
pub(crate) fn files(names: &[&str]) -> Vec<u8> {
    let text: Vec<u8> = names.iter().flat_map(|name| name.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect::<Vec<u8>>()).collect();
    let mut out = vec![0x05];
    out.extend(number(len_of(names)));
    out.push(0x11);
    out.extend(number(len_of(&text) + 1));
    out.push(0x00);
    out.extend(text);
    out.push(0x00);
    out
}

/// A header over these folders that is not packed, with a file named `f0`, `f1` and so on for
/// every file the folders hold.
pub(crate) fn header(folders: &[Folder]) -> Vec<u8> {
    let count = folders.iter().fold(0, |sum, folder| sum + folder.file_count());
    let names: Vec<String> = (0..count).map(|number| format!("f{number}")).collect();
    let mut out = vec![0x01, 0x04];
    out.extend(streams(folders, 0));
    out.extend(files(&names.iter().map(String::as_str).collect::<Vec<_>>()));
    out.push(0x00);
    out
}

/// An archive of these folders. The packed streams are zero bytes of the sizes the folders
/// name: nothing here decrypts them, so what the headers say is all there is.
pub(crate) fn archive_of(folders: &[Folder]) -> Vec<u8> {
    let packed = folders.iter().flat_map(|folder| folder.packs.iter()).fold(0_u64, |sum, &size| sum.saturating_add(size));
    archive(&header(folders), &vec![0; usize::try_from(packed).unwrap_or(0)])
}

/// A header that is stored packed: the `StreamsInfo` block of one folder with these coders,
/// whose one packed stream of `packed` bytes at `pack_pos` unpacks to `size` bytes.
pub(crate) fn packed_header(coders: Vec<u8>, sizes: &[u64], pack_pos: u64, packed: u64, crc: Option<u32>) -> Vec<u8> {
    let mut out = vec![0x17];
    out.extend(streams(&[Folder::new(coders, sizes, packed, crc)], pack_pos));
    out
}

/// The inputs that once ended in a panic, an abort on a failed allocation, or minutes of
/// work, each with a name. Every one of them is to end in a result or in an error.
pub(crate) fn hostile() -> Vec<(&'static str, Vec<u8>)> {
    const MAX: u64 = u64::MAX;
    let key = aes_props(19, &[], &[0; 16]);
    // one folder of one packed stream of 16 bytes, with these coders and these sizes
    let one = |coders: Vec<u8>, sizes: &[u64], crc: Option<u32>| archive_of(&[Folder::new(coders, sizes, 16, crc)]);
    let files_of = |count: u64, rest: &[u8]| {
        let mut header = vec![0x01, 0x05];
        header.extend(number(count));
        header.extend_from_slice(rest);
        archive(&header, &[])
    };
    let pack_crcs = |count: u64| {
        let mut header = vec![0x01, 0x04, 0x06, 0x00];
        header.extend(number(count));
        header.extend_from_slice(&[0x0A, 0x01]);
        archive(&header, &[])
    };
    // a coder of 400,000 inputs, each fed by one of its own outputs
    let wide = {
        let pairs = 400_000_u64;
        let mut coders = number(1);
        coders.extend(coder(&[0x00], &[], Some((pairs + 1, pairs + 1))));
        coders.extend((0..pairs).flat_map(|input| number(input).into_iter().chain([0])));
        one(coders, &[], None)
    };
    let many = {
        let folder = Folder::new(chain(&[(AES, &aes_props(24, &[], &[]))]), &[16], 16, Some(0));
        archive_of(&vec![folder; 4096])
    };

    vec![
        // a size of 2^64-1 to skip
        ("skip-overflow", archive(&[&[0x01, 0x02, 0x20][..], &number(MAX)].concat(), &[])),
        // a coder of two inputs and no output, and one of one input and three outputs
        ("no-output", one([number(1), coder(&[0x00], &[], Some((2, 0)))].concat(), &[], None)),
        ("three-outputs", one([number(1), coder(&[0x00], &[], Some((1, 3))), vec![0; 4]].concat(), &[], None)),
        // two coders of 2^63 inputs each
        ("inputs-overflow", one([number(2), coder(&[0x00], &[], Some((1 << 63, 1))), coder(&[0x00], &[], Some((1 << 63, 1)))].concat(), &[], None)),
        // a count of files nothing backs, and a name asked of every one of them
        ("files-2e62", files_of(1 << 62, &[0x00, 0x00])),
        ("files-2e36", files_of(1 << 36, &[0x00, 0x00])),
        ("files-2e27", files_of(1 << 27, &[0x00, 0x00])),
        ("names-of-2e40", files_of(1 << 40, &[0x11, 0x01, 0x00, 0x00, 0x00])),
        // a count of checksums nothing backs
        ("crcs-2e40", pack_crcs(1 << 40)),
        ("crcs-2e63", pack_crcs(1 << 63)),
        // a packed header at a position, of a size, and unpacking to a size that do not fit
        ("pack-position", archive(&packed_header(chain(&[(LZMA2, &[0x18])]), &[100], MAX, 16, None), &[0; 16])),
        ("pack-size", archive(&packed_header(chain(&[(LZMA2, &[0x18])]), &[100], 0, MAX, None), &[0; 16])),
        ("unpack-2e62", archive(&packed_header(chain(&[(LZMA2, &[0x18])]), &[1 << 62], 0, 16, None), &[0; 16])),
        ("unpack-max", archive(&packed_header(chain(&[(LZMA2, &[0x18])]), &[MAX], 0, 16, None), &[0; 16])),
        // a folder that says it unpacks to 2^64-1 bytes
        ("crc-length-overflow", one(chain(&[(LZMA2, &[0x18]), (AES, &key)]), &[MAX, 12], Some(0x8CDC_1683))),
        // a PPMd model of gigabytes
        ("ppmd-memory", one(chain(&[(PPMD, &[6, 0, 0, 0, 0xC0]), (AES, &key)]), &[100, 16], Some(0))),
        // a stored folder with no checksum, and a BCJ2 folder with nothing behind it
        ("stored-no-crc", one(chain(&[(AES, &key)]), &[16], None)),
        ("bcj2", archive_of(&[Folder { coders: bcj2([&key, &key, &key, &key]), sizes: vec![40, 30, 5, 5, 30, 5, 5, 16], packs: vec![32, 16, 16, 16], crc: Some(0), files: vec![(28, Some(0)), (12, None)] }])),
        // every lookup of a connection searched all the others, and every folder held a plan
        ("wide-coder", wide),
        ("many-folders", many),
    ]
}
