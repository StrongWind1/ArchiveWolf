//! Archives built by hand, for the tests of this format.
//!
//! A test that needs an archive no archiver writes (a size of 2^64, a record cut short, a
//! round count its own software refuses) builds it from the blocks here. Nothing is encrypted
//! by them: where an archive would hold encrypted bytes, the tests put bytes that say where
//! they are, since the tool reads them and never decrypts them.

/// RAR 1.3 and 1.4.
pub(crate) mod rar1 {
    /// File header flag: the entry is encrypted.
    pub(crate) const PASSWORD: u8 = 0x04;

    /// A main header with these flags and nothing in it.
    pub(crate) fn main(flags: u8) -> Vec<u8> {
        let mut out = b"RE~^".to_vec();
        out.extend_from_slice(&[7, 0, flags]);
        out
    }

    /// A file header and the data it announces: `packed` bytes are said to follow, and `data`
    /// does.
    pub(crate) fn file(name: &[u8], flags: u8, attributes: u8, method: u8, packed: u32, unpacked: u32, data: &[u8]) -> Vec<u8> {
        let mut out = packed.to_le_bytes().to_vec();
        out.extend_from_slice(&unpacked.to_le_bytes());
        out.extend_from_slice(&0x1234_u16.to_le_bytes());
        out.extend_from_slice(&u16::try_from(21 + name.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&[attributes, flags, 2, u8::try_from(name.len()).unwrap(), method]);
        out.extend_from_slice(name);
        out.extend_from_slice(data);
        out
    }
}

/// RAR 1.5 to 4.x.
pub(crate) mod rar4 {
    /// The marker an archive starts with.
    pub(crate) const MARKER: &[u8] = b"Rar!\x1a\x07\x00";
    /// Block type: a file.
    pub(crate) const FILE: u8 = 0x74;
    /// Main header flag: the archive is a volume.
    pub(crate) const VOLUME: u16 = 0x0001;
    /// Main header flag: the headers are encrypted.
    pub(crate) const HEADERS_ENCRYPTED: u16 = 0x0080;
    /// File header flag: the data is encrypted.
    pub(crate) const PASSWORD: u16 = 0x0004;
    /// File header flag: the entry continues the entries before it.
    pub(crate) const SOLID: u16 = 0x0010;
    /// File header flag: the sizes have a high half.
    pub(crate) const LARGE: u16 = 0x0100;
    /// File header flag: a salt follows the name.
    pub(crate) const SALT: u16 = 0x0400;

    /// A block of this type and these flags around `body`, which follows the seven bytes
    /// every block starts with, under the checksum that belongs to it: the low half of the
    /// CRC-32 over the block from its type on, which for a main header is its thirteen fixed
    /// bytes.
    pub(crate) fn block(head_type: u8, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 0, head_type];
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&u16::try_from(7 + body.len()).unwrap().to_le_bytes());
        out.extend_from_slice(body);
        let covered = if head_type == 0x73 { out.len().min(13) } else { out.len() };
        let checksum = u16::try_from(crc32fast::hash(&out[2..covered]) & 0xFFFF).unwrap();
        out[..2].copy_from_slice(&checksum.to_le_bytes());
        out
    }

    /// A main header with these flags.
    pub(crate) fn main(flags: u16) -> Vec<u8> {
        block(0x73, flags, &[0; 6])
    }

    /// The end of archive block.
    pub(crate) fn end() -> Vec<u8> {
        block(0x7B, 0x4000, &[])
    }

    /// What a file header says besides its flags.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Head<'a> {
        /// The name.
        pub name: &'a [u8],
        /// The version that is needed to unpack the data: it names the cipher.
        pub unp_ver: u8,
        /// The compression method, 0x30 for stored data.
        pub method: u8,
        /// The low half of the packed size.
        pub packed: u32,
        /// The low half of the unpacked size.
        pub unpacked: u32,
        /// The CRC-32 of the unpacked data.
        pub crc32: u32,
        /// The attributes.
        pub attributes: u32,
        /// What stands between the fixed fields and the name: the high halves of the sizes.
        pub high: &'a [u8],
        /// What follows the name inside the header: a salt.
        pub tail: &'a [u8],
    }

    impl Default for Head<'_> {
        fn default() -> Self {
            Self { name: b"entry.bin", unp_ver: 29, method: 0x30, packed: 0, unpacked: 0, crc32: 0xCAFE_F00D, attributes: 0x20, high: &[], tail: &[] }
        }
    }

    /// A file or service header, followed by `data`.
    pub(crate) fn file(head_type: u8, flags: u16, head: &Head<'_>, data: &[u8]) -> Vec<u8> {
        let mut body = head.packed.to_le_bytes().to_vec();
        body.extend_from_slice(&head.unpacked.to_le_bytes());
        body.push(0);
        body.extend_from_slice(&head.crc32.to_le_bytes());
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&[head.unp_ver, head.method]);
        body.extend_from_slice(&u16::try_from(head.name.len()).unwrap().to_le_bytes());
        body.extend_from_slice(&head.attributes.to_le_bytes());
        body.extend_from_slice(head.high);
        body.extend_from_slice(head.name);
        body.extend_from_slice(head.tail);
        let mut out = block(head_type, flags | 0x8000, &body);
        out.extend_from_slice(data);
        out
    }

    /// An encrypted file under RAR 3 with a salt of 0xA5: `data` is all of its data.
    pub(crate) fn encrypted(name: &[u8], method: u8, unpacked: u32, data: &[u8]) -> Vec<u8> {
        file(FILE, PASSWORD | SALT, &Head { name, method, packed: u32::try_from(data.len()).unwrap(), unpacked, tail: &[0xA5; 8], ..Head::default() }, data)
    }

    /// The marker and these blocks.
    pub(crate) fn archive(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut out = MARKER.to_vec();
        for block in blocks {
            out.extend_from_slice(block);
        }
        out
    }
}

/// RAR 5 and 7.
pub(crate) mod rar5 {
    use sha2::Digest as _;

    /// The signature an archive starts with.
    pub(crate) const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
    /// Block type: a file.
    pub(crate) const FILE: u8 = 2;
    /// Block type: a service record.
    pub(crate) const SERVICE: u8 = 3;
    /// Block flag: the data continues from the volume before.
    pub(crate) const SPLIT_BEFORE: u64 = 0x08;
    /// Block flag: the data continues in the volume after.
    pub(crate) const SPLIT_AFTER: u64 = 0x10;
    /// File flag: a directory.
    pub(crate) const DIRECTORY: u64 = 0x01;
    /// File flag: the unpacked size is not known.
    pub(crate) const SIZE_UNKNOWN: u64 = 0x08;
    /// Flag of an encryption record: a check value follows.
    pub(crate) const CHECK_VALUE: u8 = 0x01;
    /// Flag of an encryption record: the checksums are keyed.
    pub(crate) const KEYED: u8 = 0x02;
    /// The largest number there is, in ten bytes.
    pub(crate) const MAX: [u8; 10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

    /// A number of variable length.
    pub(crate) fn vint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let low = u8::try_from(value & 0x7F).unwrap();
            value >>= 7;
            if value == 0 {
                out.push(low);
                return out;
            }
            out.push(low | 0x80);
        }
    }

    /// A block around `body`, with the CRC-32 that belongs to it.
    pub(crate) fn block(body: &[u8]) -> Vec<u8> {
        let mut sized = vint(u64::try_from(body.len()).unwrap());
        sized.extend_from_slice(body);
        let mut out = crc32fast::hash(&sized).to_le_bytes().to_vec();
        out.extend_from_slice(&sized);
        out
    }

    /// A main header with these archive flags, and the volume number where they call for one.
    pub(crate) fn main(archive_flags: &[u8]) -> Vec<u8> {
        let mut body = vec![1, 0];
        body.extend_from_slice(archive_flags);
        block(&body)
    }

    /// The end of archive block.
    pub(crate) fn end() -> Vec<u8> {
        block(&[5, 0, 0])
    }

    /// The first four bytes of the SHA-256 of a check value: the checksum that is stored
    /// behind it.
    pub(crate) fn checksum_of(value: [u8; 8]) -> [u8; 4] {
        let digest = sha2::Sha256::digest(value);
        [digest[0], digest[1], digest[2], digest[3]]
    }

    /// What an encryption record holds behind its type: this version, these flags and this
    /// count, a salt of 0x11, with `entry` a vector of 0x22, and with the flag for it a check
    /// value of 0xAA and its checksum.
    pub(crate) fn crypt_fields(version: u8, flags: u8, lg2count: u8, entry: bool) -> Vec<u8> {
        let mut out = vec![version, flags, lg2count];
        out.extend_from_slice(&[0x11; 16]);
        if entry {
            out.extend_from_slice(&[0x22; 16]);
        }
        if flags & CHECK_VALUE != 0 {
            out.extend_from_slice(&[0xAA; 8]);
            out.extend_from_slice(&checksum_of([0xAA; 8]));
        }
        out
    }

    /// The encryption record of an entry, of version 0.
    pub(crate) fn crypt_record(flags: u8, lg2count: u8) -> Vec<u8> {
        let mut record = vec![1];
        record.extend_from_slice(&crypt_fields(0, flags, lg2count, true));
        record
    }

    /// The record that holds a BLAKE2sp digest of 0xB2.
    pub(crate) fn blake2_record() -> Vec<u8> {
        let mut record = vec![2, 0];
        record.extend_from_slice(&[0xB2; 32]);
        record
    }

    /// The archive encryption header.
    pub(crate) fn crypt_header(version: u8, flags: u8, lg2count: u8) -> Vec<u8> {
        let mut body = vec![4, 0];
        body.extend_from_slice(&crypt_fields(version, flags, lg2count, false));
        block(&body)
    }

    /// A file or service header and what follows it.
    #[derive(Debug, Clone)]
    pub(crate) struct Entry<'a> {
        /// The type of the block: [`FILE`] or [`SERVICE`].
        pub head_type: u8,
        /// The name.
        pub name: &'a [u8],
        /// Block flags besides the two for an extra area and for data.
        pub flags: u64,
        /// File flags besides the one for a CRC-32.
        pub file_flags: u64,
        /// The unpacked size.
        pub unpacked: u64,
        /// The compression information: the method in bits 7 to 9.
        pub compression: u64,
        /// The CRC-32 of the unpacked data, when the header stores one.
        pub crc32: Option<u32>,
        /// The records of the extra area, each from its type on.
        pub records: Vec<Vec<u8>>,
        /// The size the header gives for the data, when that is not the size of `data`.
        pub packed: Option<u64>,
        /// The data that follows the header.
        pub data: &'a [u8],
    }

    impl Default for Entry<'_> {
        fn default() -> Self {
            Self { head_type: FILE, name: b"entry.bin", flags: 0, file_flags: 0, unpacked: 0, compression: 0, crc32: Some(0xCAFE_F00D), records: Vec::new(), packed: None, data: &[] }
        }
    }

    impl Entry<'_> {
        /// The header and the data.
        pub(crate) fn block(&self) -> Vec<u8> {
            let mut extra = Vec::new();
            for record in &self.records {
                extra.extend_from_slice(&vint(u64::try_from(record.len()).unwrap()));
                extra.extend_from_slice(record);
            }
            let mut body = vec![self.head_type];
            body.extend_from_slice(&vint(self.flags | 0x03));
            body.extend_from_slice(&vint(u64::try_from(extra.len()).unwrap()));
            body.extend_from_slice(&vint(self.packed.unwrap_or(u64::try_from(self.data.len()).unwrap())));
            body.extend_from_slice(&vint(self.file_flags | if self.crc32.is_some() { 0x04 } else { 0 }));
            body.extend_from_slice(&vint(self.unpacked));
            body.push(0x20);
            if let Some(crc32) = self.crc32 {
                body.extend_from_slice(&crc32.to_le_bytes());
            }
            body.extend_from_slice(&vint(self.compression));
            body.push(0);
            body.extend_from_slice(&vint(u64::try_from(self.name.len()).unwrap()));
            body.extend_from_slice(self.name);
            body.extend_from_slice(&extra);
            let mut out = block(&body);
            out.extend_from_slice(self.data);
            out
        }
    }

    /// The signature and these blocks.
    pub(crate) fn archive(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut out = SIGNATURE.to_vec();
        for block in blocks {
            out.extend_from_slice(block);
        }
        out
    }
}
