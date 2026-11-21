//! ZIP archives built by hand, for the tests of this format.
//!
//! No archiver writes most of what the parser has to stand: strong encryption with a cipher
//! other than AES, an encrypted central directory, sizes of 2^64-1, a header that contradicts
//! itself. [`Zip`] writes an archive from a list of [`Member`]s, each with the fields of its
//! headers as the test wants them, true or not.

/// One entry of an archive built here. `member` gives the usual one, and a test changes what
/// it is about.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Member<'a> {
    pub name: &'a str,
    pub flags: u16,
    /// Version needed to extract.
    pub version: u16,
    /// Version made by, with the host system in the high byte.
    pub made_by: u16,
    pub method: u16,
    /// Last modification time.
    pub time: u16,
    /// Extra fields of both headers.
    pub extra: &'a [u8],
    /// Extra fields of the central header alone, behind `extra`: field 0x0017 goes here.
    pub central_extra: &'a [u8],
    /// The bytes that stand as the data of the entry, with any encryption header.
    pub data: &'a [u8],
    /// The CRC-32 the headers state. Without one, that of `data` for an entry that is not
    /// marked and its complement for one that is, as encrypted data does not have the
    /// checksum of what it holds.
    pub crc: Option<u32>,
    /// The uncompressed size the headers state. Without one, the size of `data`, less the 12
    /// bytes of the encryption header for an entry marked as ZipCrypto.
    pub size: Option<u32>,
    /// The compressed size the headers state, when it is not the size of `data`.
    pub declared: Option<u32>,
    /// External file attributes.
    pub external: u32,
    /// The disk the entry starts on.
    pub disk: u16,
    /// Uncompressed size, compressed size and offset for a ZIP64 extra field of the central
    /// header, whose three fields then carry the mark.
    pub zip64: Option<(u64, u64, u64)>,
}

/// A stored entry named `name` with the flags `flags` and the data `data`.
pub(crate) fn member<'a>(name: &'a str, flags: u16, data: &'a [u8]) -> Member<'a> {
    Member { name, flags, version: 20, made_by: 20, method: 0, time: 0, extra: &[], central_extra: &[], data, crc: None, size: None, declared: None, external: 0, disk: 0, zip64: None }
}

/// The ZIP64 records an archive is written with.
#[derive(Debug, Clone, Copy)]
struct Zip64 {
    /// Entries, size and offset of the central directory as the record states them, when they
    /// are not the true ones.
    values: Option<(u64, u64, u64)>,
    /// The offset the locator states, when it is not the true one.
    locator_offset: Option<u64>,
    /// Method, algorithm, key length and flags of a version 2 record.
    protection: Option<[u16; 4]>,
}

/// An archive to build.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Zip<'a> {
    members: &'a [Member<'a>],
    comment: &'a [u8],
    zip64: Option<Zip64>,
    disk: u16,
    descriptors: bool,
}

fn put16(out: &mut Vec<u8>, fields: &[u16]) {
    for field in fields {
        out.extend_from_slice(&field.to_le_bytes());
    }
}

fn put32(out: &mut Vec<u8>, fields: &[u32]) {
    for field in fields {
        out.extend_from_slice(&field.to_le_bytes());
    }
}

fn put64(out: &mut Vec<u8>, fields: &[u64]) {
    for field in fields {
        out.extend_from_slice(&field.to_le_bytes());
    }
}

fn len16(bytes: &[u8]) -> u16 {
    u16::try_from(bytes.len()).unwrap()
}

fn len32(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).unwrap()
}

impl<'a> Zip<'a> {
    /// An archive of `members`, without a comment and without ZIP64 records.
    pub(crate) const fn of(members: &'a [Member<'a>]) -> Self {
        Self { members, comment: &[], zip64: None, disk: 0, descriptors: false }
    }

    /// With an archive comment.
    pub(crate) const fn comment(mut self, comment: &'a [u8]) -> Self {
        self.comment = comment;
        self
    }

    /// With a ZIP64 end record and its locator, and their marks in the end record.
    pub(crate) const fn zip64(mut self) -> Self {
        if self.zip64.is_none() {
            self.zip64 = Some(Zip64 { values: None, locator_offset: None, protection: None });
        }
        self
    }

    /// With a ZIP64 end record that states these entries, this size and this offset of the
    /// central directory.
    pub(crate) const fn zip64_values(mut self, entries: u64, size: u64, offset: u64) -> Self {
        self = self.zip64();
        if let Some(zip64) = &mut self.zip64 {
            zip64.values = Some((entries, size, offset));
        }
        self
    }

    /// With a ZIP64 locator that states this offset of the ZIP64 end record.
    pub(crate) const fn locator_offset(mut self, offset: u64) -> Self {
        self = self.zip64();
        if let Some(zip64) = &mut self.zip64 {
            zip64.locator_offset = Some(offset);
        }
        self
    }

    /// With a version 2 ZIP64 end record that says the central directory is compressed with
    /// `method` and encrypted with `alg_id`, a key of `bits` bits and the flags `flags`. The
    /// directory is then written as bytes that are no directory, as an encrypted one is.
    pub(crate) const fn directory_protection(mut self, method: u16, alg_id: u16, bits: u16, flags: u16) -> Self {
        self = self.zip64();
        if let Some(zip64) = &mut self.zip64 {
            zip64.protection = Some([method, alg_id, bits, flags]);
        }
        self
    }

    /// As disk `disk` of a spanned archive, with its central directory on the same disk.
    pub(crate) const fn disk(mut self, disk: u16) -> Self {
        self.disk = disk;
        self
    }

    /// With a data descriptor behind every entry whose flags have bit 3.
    pub(crate) const fn descriptors(mut self) -> Self {
        self.descriptors = true;
        self
    }

    /// The bytes of the archive.
    pub(crate) fn build(self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();

        for member in self.members {
            let offset = len32(&out);
            let marked_zip_crypto = member.flags & 0x0041 == 0x0001 && member.method != 99;
            let crc = member.crc.unwrap_or_else(|| if member.flags & 1 == 0 { crc32fast::hash(member.data) } else { !crc32fast::hash(member.data) });
            let packed = member.declared.unwrap_or_else(|| len32(member.data));
            let size = member.size.unwrap_or_else(|| if marked_zip_crypto { len32(member.data).saturating_sub(12) } else { len32(member.data) });

            let mut fixed = Vec::new();
            put16(&mut fixed, &[member.version, member.flags, member.method, member.time, 0]);
            fixed.extend_from_slice(&crc.to_le_bytes());

            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&fixed);
            put32(&mut out, &[packed, size]);
            put16(&mut out, &[len16(member.name.as_bytes()), len16(member.extra)]);
            out.extend_from_slice(member.name.as_bytes());
            out.extend_from_slice(member.extra);
            out.extend_from_slice(member.data);
            if self.descriptors && member.flags & 8 != 0 {
                out.extend_from_slice(b"PK\x07\x08");
                put32(&mut out, &[crc, packed, size]);
            }

            let mut extra = member.extra.to_vec();
            extra.extend_from_slice(member.central_extra);
            let (central_packed, central_size, central_offset) = if let Some((uncompressed, compressed, at)) = member.zip64 {
                put16(&mut extra, &[1, 24]);
                put64(&mut extra, &[uncompressed, compressed, at]);
                (u32::MAX, u32::MAX, u32::MAX)
            } else {
                (packed, size, offset)
            };

            central.extend_from_slice(b"PK\x01\x02");
            put16(&mut central, &[member.made_by]);
            central.extend_from_slice(&fixed);
            put32(&mut central, &[central_packed, central_size]);
            put16(&mut central, &[len16(member.name.as_bytes()), len16(&extra), 0, member.disk, 0]);
            put32(&mut central, &[member.external, central_offset]);
            central.extend_from_slice(member.name.as_bytes());
            central.extend_from_slice(&extra);
        }

        let count = u16::try_from(self.members.len()).unwrap();
        let (directory_offset, directory_size) = (len32(&out), len32(&central));
        if self.zip64.is_some_and(|zip64| zip64.protection.is_some()) {
            // an archive decryption header and ciphertext stand where the directory would
            out.extend(central.iter().map(|byte| byte ^ 0xA7));
        } else {
            out.extend_from_slice(&central);
        }

        if let Some(zip64) = self.zip64 {
            let record_at = out.len() as u64;
            let (entries, size, offset) = zip64.values.unwrap_or((u64::from(count), u64::from(directory_size), u64::from(directory_offset)));
            let version = if zip64.protection.is_some() { 62 } else { 45 };
            let tail = zip64.protection.map_or_else(Vec::new, |[method, alg_id, bits, flags]| {
                let mut tail = Vec::new();
                put16(&mut tail, &[method]);
                put64(&mut tail, &[u64::from(directory_size), u64::from(directory_size)]);
                put16(&mut tail, &[alg_id, bits, flags, 0, 0]);
                tail
            });
            out.extend_from_slice(b"PK\x06\x06");
            put64(&mut out, &[44 + tail.len() as u64]);
            put16(&mut out, &[version, version]);
            put32(&mut out, &[u32::from(self.disk), u32::from(self.disk)]);
            put64(&mut out, &[entries, entries, size, offset]);
            out.extend_from_slice(&tail);

            out.extend_from_slice(b"PK\x06\x07");
            put32(&mut out, &[u32::from(self.disk)]);
            put64(&mut out, &[zip64.locator_offset.unwrap_or(record_at)]);
            put32(&mut out, &[u32::from(self.disk) + 1]);
        }

        out.extend_from_slice(b"PK\x05\x06");
        if self.zip64.is_some() {
            put16(&mut out, &[self.disk, self.disk, 0xFFFF, 0xFFFF]);
            put32(&mut out, &[u32::MAX, u32::MAX]);
        } else {
            put16(&mut out, &[self.disk, self.disk, count, count]);
            put32(&mut out, &[directory_size, directory_offset]);
        }
        put16(&mut out, &[len16(self.comment)]);
        out.extend_from_slice(self.comment);
        out
    }
}

/// Extra field 0x9901 of WinZip AES: the AE version, the strength and the real method.
pub(crate) fn aes_extra(ae_version: u16, strength: u8, method: u16) -> Vec<u8> {
    let mut extra = Vec::new();
    put16(&mut extra, &[0x9901, 7, ae_version, 0x4541]);
    extra.push(strength);
    put16(&mut extra, &[method]);
    extra
}

/// Extra field 0x0017 of PKWARE strong encryption: the algorithm, its key length and the flags.
pub(crate) fn pkware_extra(alg_id: u16, bits: u16, flags: u16) -> Vec<u8> {
    let mut extra = Vec::new();
    put16(&mut extra, &[0x0017, 8, 2, alg_id, bits, flags]);
    extra
}

/// A decryption header of PKWARE strong encryption, as it stands in front of the data of an
/// entry.
#[derive(Debug, Clone)]
pub(crate) struct DecryptionHeader {
    pub iv: Vec<u8>,
    pub format: u16,
    pub alg_id: u16,
    pub bits: u16,
    pub flags: u16,
    /// The encrypted random data.
    pub erd: Vec<u8>,
    /// The recipients of a certificate list, each as the bytes of one element behind its size.
    pub recipients: Vec<Vec<u8>>,
    /// The encrypted validation data.
    pub vdata: Vec<u8>,
}

impl DecryptionHeader {
    /// A header for a password, with a vector of 16 bytes, 144 bytes of random data and 16 of
    /// validation data, as SecureZIP writes it for AES.
    pub(crate) fn password(alg_id: u16, bits: u16) -> Self {
        Self { iv: vec![0xA1; 16], format: 3, alg_id, bits, flags: 1, erd: (0..144).map(|byte: u8| byte.wrapping_mul(7)).collect(), recipients: Vec::new(), vdata: vec![0xCC; 16] }
    }

    /// The bytes of the header.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        let mut rest = Vec::new();
        put16(&mut rest, &[self.format, self.alg_id, self.bits, self.flags, len16(&self.erd)]);
        rest.extend_from_slice(&self.erd);
        // the number of recipients, then the list when there is one
        put32(&mut rest, &[u32::try_from(self.recipients.len()).unwrap()]);
        if !self.recipients.is_empty() {
            // the hash algorithm (SHA-1) and the size of a hashed key
            put16(&mut rest, &[0x8004, 20]);
            for recipient in &self.recipients {
                put16(&mut rest, &[len16(recipient)]);
                rest.extend_from_slice(recipient);
            }
        }
        put16(&mut rest, &[len16(&self.vdata)]);
        rest.extend_from_slice(&self.vdata);

        let mut out = Vec::new();
        put16(&mut out, &[len16(&self.iv)]);
        out.extend_from_slice(&self.iv);
        put32(&mut out, &[len32(&rest)]);
        out.extend_from_slice(&rest);
        out
    }
}

/// Raw Deflate of `data`.
pub(crate) fn deflated(data: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// `len` bytes that look like ciphertext: no run, no pattern a decoder takes for a stream.
pub(crate) fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    std::iter::repeat_with(|| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state.to_le_bytes()[3]
    })
    .take(len)
    .collect()
}
