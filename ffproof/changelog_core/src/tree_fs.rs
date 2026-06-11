//! Shared codec for the relative-inode filesystem prototype.
//!
//! The `/dir` + `/info` model stores each node's [`Inode`] record under its
//! parent's listing prefix:
//!
//! ```text
//! CONTAINER(parent) || b"/info" || inode_id_32
//! ```
//!
//! A directory's own descendants live under:
//!
//! ```text
//! CONTAINER(parent) || b"/dir" || inode_id_32 || ...
//! ```
//!
//! Tree-fs code uses [`Inode`] and the inode-id key helpers.

use encrypted_spaces_storage_encoding::hashstore_hash;
use thiserror::Error;

/// Raw key namespace for every tree-filesystem record.
pub const FS_KEY_NAMESPACE: &[u8; 4] = b"/_fs";

/// Path tag introducing a child directory container.
pub const TAG_DIR: &[u8; 4] = b"/dir";

/// Path tag selecting direct child records inside a directory container.
pub const TAG_INFO: &[u8; 5] = b"/info";

/// Fixed byte width of each inode id.
pub const INODE_ID_LEN: usize = 32;

/// Reserved path component for a node's own record. Never a child label.
///
/// Compatibility only: the shipped flat codec used `u32` child labels and a
/// trailing zero record marker. K2+ callers use 32-byte [`InodeId`] values.
pub const RECORD: u32 = 0;

/// Maximum encoded filesystem key length, in bytes.
///
/// Raised to match merk's storage-level `MAX_KEY_LEN` (`mrt/tree.rs`, `4 * 1024`)
/// so deep records fit — the original 64-byte cap admitted only 14 child labels.
///
/// This codec constant is the *only* ceiling on a record key. Verifier-emitted
/// `/_fs` `WriteOp` keys are exempt from `changelog::MAX_KEY_LEN` (also 64):
/// that cap is enforced only in `ChangelogEntry::new` (`changelog.rs`) on the
/// *signed-entry* kv keys — for a native op the short
/// `native_marker_key()`/`native_payload_key()` — never on the keys a native
/// verifier writes. So raising this constant (and merk's already-4096 cap is
/// enough) suffices; no `changelog` change is needed.
pub const MAX_FS_KEY_LEN: usize = 4096;

/// Bytes added for each directory container step.
pub const DIR_COMPONENT_LEN: usize = TAG_DIR.len() + INODE_ID_LEN;

/// Bytes added for the final child record selector.
pub const INFO_COMPONENT_LEN: usize = TAG_INFO.len() + INODE_ID_LEN;

/// Maximum logical inode path depth (number of inode ids) whose record key fits.
///
/// A record for path length `n >= 1` is:
/// `4 namespace + (n - 1) * 36 (/dir + id) + 37 (/info + id)`.
pub const MAX_CHILD_DEPTH: usize =
    ((MAX_FS_KEY_LEN - FS_KEY_NAMESPACE.len() - INFO_COMPONENT_LEN) / DIR_COMPONENT_LEN) + 1;

/// One 256-bit inode identifier in a logical filesystem path.
pub type InodeId = [u8; INODE_ID_LEN];

/// New tree-fs logical path: root-to-node inode ids. The root path is `[]`.
pub type InodePath = Vec<InodeId>;

/// The only [`Inode`] version this codec encodes or accepts.
pub const INODE_VERSION: u32 = 3;

/// Length of the fixed [`Inode`] header, in bytes.
pub const FIXED_HEADER_LEN: usize = 72;

/// Maximum plaintext filename length stored in an [`Inode`].
pub const MAX_NAME_LEN: usize = 256;

/// Maximum encoded [`Inode`] length, in bytes.
pub const MAX_INODE_LEN: usize = FIXED_HEADER_LEN + MAX_NAME_LEN;

/// Fixed byte width of a content hash.
pub const CONTENT_HASH_LEN: usize = 32;

/// `Inode.flags` bit indicating a file. If absent, the inode is a directory.
pub const INODE_FLAG_FILE: u32 = 1;

const KNOWN_INODE_FLAGS: u32 = INODE_FLAG_FILE;

/// Maximum length, in bytes, of any single variable-length payload field.
pub const MAX_VAR_FIELD_LEN: usize = 64 * 1024;

/// Plaintext node kind. Matches the table backend's `INODE_FILE = 1` /
/// `INODE_FOLDER = 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NodeKind {
    File = 1,
    Directory = 2,
}

impl NodeKind {
    pub fn flags(self) -> u32 {
        match self {
            Self::File => INODE_FLAG_FILE,
            Self::Directory => 0,
        }
    }

    pub fn from_flags(flags: u32) -> Result<Self, CodecError> {
        if flags & !KNOWN_INODE_FLAGS != 0 {
            return Err(CodecError::UnsupportedFlags(flags));
        }
        if flags & INODE_FLAG_FILE != 0 {
            Ok(Self::File)
        } else {
            Ok(Self::Directory)
        }
    }
}

/// The canonical value stored at a `/dir` + `/info` record key.
///
/// Inode identity lives in the record key path, not in this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inode {
    pub version: u32,
    pub flags: u32,
    pub author_uid: u32,
    pub size: u64,
    pub ctime: i64,
    pub mtime: i64,
    pub content_hash: [u8; CONTENT_HASH_LEN],
    pub name: Vec<u8>,
}

/// Every way a tree-filesystem key or record can fail to (de)serialize.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CodecError {
    #[error("zero inode id is reserved")]
    ZeroInodeId,
    #[error("child label 0 is reserved for the record marker")]
    ZeroChildLabel,
    #[error("encoded filesystem key length {len} exceeds the maximum")]
    KeyTooLong { len: usize },
    #[error("encoded filesystem key is too short to hold a namespace and record marker")]
    KeyTooShort,
    #[error("encoded filesystem key length {len} is not 4-byte aligned")]
    KeyMisaligned { len: usize },
    #[error("encoded filesystem key does not begin with the expected namespace")]
    BadNamespace,
    #[error("encoded filesystem key has an unexpected path tag")]
    BadPathTag,
    #[error("encoded filesystem key does not contain the info tag")]
    MissingInfoTag,
    #[error("encoded filesystem key does not end with the record marker")]
    MissingRecordMarker,
    #[error("node record has unknown magic")]
    BadMagic,
    #[error("record has unsupported version {0}")]
    UnsupportedVersion(u32),
    #[error("inode has unsupported flags {0}")]
    UnsupportedFlags(u32),
    #[error("node record declared length {declared} does not match buffer length {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("node record has unknown kind {0}")]
    UnknownKind(u32),
    #[error("node record has nonzero flags {0}")]
    NonzeroFlags(u32),
    #[error("directory inode must have size == 0, got {0}")]
    DirectoryHasSize(u64),
    #[error("directory inode must have a zero content_hash")]
    DirectoryHasContentHash,
    #[error("node record has a nonzero reserved field")]
    NonzeroReserved,
    #[error("file node record must have next_child_label == 0")]
    FileHasChildLabel,
    #[error("inode name length {len} exceeds the maximum")]
    NameTooLong { len: usize },
    #[error("node record variable field length {len} exceeds the maximum")]
    VarFieldTooLong { len: usize },
    #[error("record is truncated")]
    Truncated,
    #[error("record has a nonzero padding byte")]
    NonzeroPadding,
    #[error("record has unexpected trailing bytes")]
    TrailingBytes,
}

/// Encode a record key.
///
/// For inode-id paths this emits:
/// `CONTAINER(parent) || TAG_INFO || child_inode_id`.
pub fn encode_record_key<P: RecordKeyPath + ?Sized>(path: &P) -> Result<Vec<u8>, CodecError> {
    path.encode_record_key()
}

pub trait RecordKeyPath {
    fn encode_record_key(&self) -> Result<Vec<u8>, CodecError>;
}

impl RecordKeyPath for [InodeId] {
    fn encode_record_key(&self) -> Result<Vec<u8>, CodecError> {
        encode_inode_record_key(self)
    }
}

impl RecordKeyPath for Vec<InodeId> {
    fn encode_record_key(&self) -> Result<Vec<u8>, CodecError> {
        encode_inode_record_key(self)
    }
}

impl<const N: usize> RecordKeyPath for [InodeId; N] {
    fn encode_record_key(&self) -> Result<Vec<u8>, CodecError> {
        encode_inode_record_key(self)
    }
}

/// Decode a record key.
///
/// Request [`InodePath`] for the `/dir` + `/info` model.
pub fn decode_record_key<P: DecodedRecordKey>(bytes: &[u8]) -> Result<P, CodecError> {
    P::decode_record_key(bytes)
}

pub trait DecodedRecordKey: Sized {
    fn decode_record_key(bytes: &[u8]) -> Result<Self, CodecError>;
}

impl DecodedRecordKey for InodePath {
    fn decode_record_key(bytes: &[u8]) -> Result<Self, CodecError> {
        decode_inode_record_key(bytes)
    }
}

/// Derive the single child inode id assigned by a `tree_fs_create` change.
pub fn derive_inode_id(parent_clc: [u8; 32]) -> InodeId {
    let mut bytes = Vec::with_capacity(parent_clc.len() + 2);
    bytes.extend_from_slice(&parent_clc);
    bytes.extend_from_slice(b"id");
    hashstore_hash(&bytes)
}

/// Encode `CONTAINER(path)`.
pub fn encode_container_prefix(path: &[InodeId]) -> Result<Vec<u8>, CodecError> {
    let encoded_len = FS_KEY_NAMESPACE.len() + path.len() * DIR_COMPONENT_LEN;
    if encoded_len > MAX_FS_KEY_LEN {
        return Err(CodecError::KeyTooLong { len: encoded_len });
    }
    for id in path {
        validate_inode_id(id)?;
    }

    let mut out = Vec::with_capacity(encoded_len);
    out.extend_from_slice(FS_KEY_NAMESPACE);
    for id in path {
        out.extend_from_slice(TAG_DIR);
        out.extend_from_slice(id);
    }
    Ok(out)
}

/// Encode the one-level listing prefix for direct children of `dir`.
pub fn encode_children_listing_prefix(dir: &[InodeId]) -> Result<Vec<u8>, CodecError> {
    let mut out = encode_container_prefix(dir)?;
    let encoded_len = out.len() + TAG_INFO.len();
    if encoded_len > MAX_FS_KEY_LEN {
        return Err(CodecError::KeyTooLong { len: encoded_len });
    }
    out.extend_from_slice(TAG_INFO);
    Ok(out)
}

pub fn validate_inode_id(id: &InodeId) -> Result<(), CodecError> {
    if id.iter().all(|&b| b == 0) {
        Err(CodecError::ZeroInodeId)
    } else {
        Ok(())
    }
}

pub fn decode_inode_id(bytes: &[u8]) -> Result<InodeId, CodecError> {
    if bytes.len() != INODE_ID_LEN {
        return Err(CodecError::KeyMisaligned { len: bytes.len() });
    }
    let mut id = [0u8; INODE_ID_LEN];
    id.copy_from_slice(bytes);
    validate_inode_id(&id)?;
    Ok(id)
}

fn encode_inode_record_key(path: &[InodeId]) -> Result<Vec<u8>, CodecError> {
    let Some((child, parent)) = path.split_last() else {
        return Err(CodecError::KeyTooShort);
    };
    validate_inode_id(child)?;

    let encoded_len =
        FS_KEY_NAMESPACE.len() + parent.len() * DIR_COMPONENT_LEN + TAG_INFO.len() + INODE_ID_LEN;
    if encoded_len > MAX_FS_KEY_LEN {
        return Err(CodecError::KeyTooLong { len: encoded_len });
    }

    let mut out = encode_container_prefix(parent)?;
    out.extend_from_slice(TAG_INFO);
    out.extend_from_slice(child);
    debug_assert_eq!(out.len(), encoded_len);
    Ok(out)
}

fn decode_inode_record_key(bytes: &[u8]) -> Result<InodePath, CodecError> {
    if bytes.len() > MAX_FS_KEY_LEN {
        return Err(CodecError::KeyTooLong { len: bytes.len() });
    }
    let min_len = FS_KEY_NAMESPACE.len() + TAG_INFO.len() + INODE_ID_LEN;
    if bytes.len() < min_len {
        return Err(CodecError::KeyTooShort);
    }
    if &bytes[..FS_KEY_NAMESPACE.len()] != FS_KEY_NAMESPACE.as_slice() {
        return Err(CodecError::BadNamespace);
    }

    let mut cursor = FS_KEY_NAMESPACE.len();
    let mut path = Vec::new();
    loop {
        let remaining = &bytes[cursor..];
        if remaining.len() >= TAG_INFO.len() && &remaining[..TAG_INFO.len()] == TAG_INFO {
            cursor += TAG_INFO.len();
            let child_end = cursor
                .checked_add(INODE_ID_LEN)
                .ok_or(CodecError::Truncated)?;
            if child_end > bytes.len() {
                return Err(CodecError::KeyTooShort);
            }
            path.push(decode_inode_id(&bytes[cursor..child_end])?);
            if child_end != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            return Ok(path);
        }

        if remaining.len() < DIR_COMPONENT_LEN {
            return Err(CodecError::MissingInfoTag);
        }
        if &remaining[..TAG_DIR.len()] != TAG_DIR {
            return Err(CodecError::BadPathTag);
        }
        cursor += TAG_DIR.len();
        let id_end = cursor
            .checked_add(INODE_ID_LEN)
            .ok_or(CodecError::Truncated)?;
        if id_end > bytes.len() {
            return Err(CodecError::KeyTooShort);
        }
        path.push(decode_inode_id(&bytes[cursor..id_end])?);
        cursor = id_end;
    }
}

impl Inode {
    pub fn kind(&self) -> Result<NodeKind, CodecError> {
        NodeKind::from_flags(self.flags)
    }

    /// Serialize to the canonical fixed-header + padded-name format.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;

        let name_len = self.name.len();
        let padded_name_len = name_len.next_multiple_of(4);
        let mut out = Vec::with_capacity(FIXED_HEADER_LEN + padded_name_len);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.author_uid.to_be_bytes());
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.ctime.to_be_bytes());
        out.extend_from_slice(&self.mtime.to_be_bytes());
        out.extend_from_slice(&self.content_hash);
        out.extend_from_slice(&(name_len as u32).to_be_bytes());
        out.extend_from_slice(&self.name);
        out.resize(FIXED_HEADER_LEN + padded_name_len, 0);
        Ok(out)
    }

    /// Decode and fully validate the canonical wire format.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < FIXED_HEADER_LEN {
            return Err(CodecError::Truncated);
        }

        let version = be32(bytes, 0);
        if version != INODE_VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }
        let flags = be32(bytes, 4);
        let author_uid = be32(bytes, 8);
        let size = be64(bytes, 12);
        let ctime = bei64(bytes, 20);
        let mtime = bei64(bytes, 28);
        let mut content_hash = [0u8; CONTENT_HASH_LEN];
        content_hash.copy_from_slice(&bytes[36..68]);
        let name_len = be32(bytes, 68) as usize;
        if name_len > MAX_NAME_LEN {
            return Err(CodecError::NameTooLong { len: name_len });
        }

        let payload_end = FIXED_HEADER_LEN
            .checked_add(name_len)
            .ok_or(CodecError::Truncated)?;
        let padded_end = FIXED_HEADER_LEN
            .checked_add(name_len.next_multiple_of(4))
            .ok_or(CodecError::Truncated)?;
        if padded_end > bytes.len() {
            return Err(CodecError::Truncated);
        }
        if padded_end != bytes.len() {
            return Err(CodecError::TrailingBytes);
        }
        for &b in &bytes[payload_end..padded_end] {
            if b != 0 {
                return Err(CodecError::NonzeroPadding);
            }
        }

        let record = Self {
            version,
            flags,
            author_uid,
            size,
            ctime,
            mtime,
            content_hash,
            name: bytes[FIXED_HEADER_LEN..payload_end].to_vec(),
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.version != INODE_VERSION {
            return Err(CodecError::UnsupportedVersion(self.version));
        }
        let kind = self.kind()?;
        if self.name.len() > MAX_NAME_LEN {
            return Err(CodecError::NameTooLong {
                len: self.name.len(),
            });
        }
        if kind == NodeKind::Directory {
            if self.size != 0 {
                return Err(CodecError::DirectoryHasSize(self.size));
            }
            if self.content_hash != [0u8; CONTENT_HASH_LEN] {
                return Err(CodecError::DirectoryHasContentHash);
            }
        }
        Ok(())
    }
}

fn be32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn be64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn bei64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> InodeId {
        [byte; INODE_ID_LEN]
    }

    fn sample_file_inode() -> Inode {
        Inode {
            version: INODE_VERSION,
            flags: NodeKind::File.flags(),
            author_uid: 7,
            size: 1024,
            ctime: 1_717_459_200,
            mtime: 1_717_459_300,
            content_hash: [0xAB; CONTENT_HASH_LEN],
            name: b"hello.txt".to_vec(),
        }
    }

    fn sample_dir_inode() -> Inode {
        Inode {
            version: INODE_VERSION,
            flags: NodeKind::Directory.flags(),
            author_uid: 42,
            size: 0,
            ctime: 1_717_459_200,
            mtime: 1_717_459_300,
            content_hash: [0u8; CONTENT_HASH_LEN],
            name: b"projects".to_vec(),
        }
    }

    #[test]
    fn tree_fs_codec_roundtrip() {
        let root_child = vec![id(1)];
        let nested_child = vec![id(1), id(2)];

        let root_key = encode_record_key(&root_child).unwrap();
        let mut expected_root_key = b"/_fs/info".to_vec();
        expected_root_key.extend_from_slice(&id(1));
        assert_eq!(root_key, expected_root_key);
        let decoded_root: InodePath = decode_record_key(&root_key).unwrap();
        assert_eq!(decoded_root, root_child);

        let nested_key = encode_record_key(&nested_child).unwrap();
        let mut expected_nested_key = b"/_fs/dir".to_vec();
        expected_nested_key.extend_from_slice(&id(1));
        expected_nested_key.extend_from_slice(b"/info");
        expected_nested_key.extend_from_slice(&id(2));
        assert_eq!(nested_key, expected_nested_key);
        let decoded_nested: InodePath = decode_record_key(&nested_key).unwrap();
        assert_eq!(decoded_nested, nested_child);

        for inode in [sample_file_inode(), sample_dir_inode()] {
            let encoded = inode.encode().unwrap();
            assert!(encoded.len() <= MAX_INODE_LEN);
            assert_eq!(
                encoded.len(),
                FIXED_HEADER_LEN + inode.name.len().next_multiple_of(4)
            );
            assert_eq!(Inode::decode(&encoded).unwrap(), inode);
        }
    }

    #[test]
    fn tree_fs_codec_rejects() {
        let good = sample_file_inode().encode().unwrap();
        let mutate = |edit: &dyn Fn(&mut Vec<u8>)| {
            let mut bytes = good.clone();
            edit(&mut bytes);
            bytes
        };

        assert_eq!(
            Inode::decode(&mutate(&|b| b[0..4].copy_from_slice(&4u32.to_be_bytes()))),
            Err(CodecError::UnsupportedVersion(4))
        );
        assert_eq!(
            Inode::decode(&mutate(&|b| b[4..8].copy_from_slice(&2u32.to_be_bytes()))),
            Err(CodecError::UnsupportedFlags(2))
        );

        let mut oversized = sample_file_inode();
        oversized.name = vec![b'x'; MAX_NAME_LEN + 1];
        assert_eq!(
            oversized.encode(),
            Err(CodecError::NameTooLong {
                len: MAX_NAME_LEN + 1
            })
        );
        assert_eq!(
            Inode::decode(&mutate(&|b| {
                b[68..72].copy_from_slice(&((MAX_NAME_LEN as u32) + 1).to_be_bytes());
            })),
            Err(CodecError::NameTooLong {
                len: MAX_NAME_LEN + 1
            })
        );

        let padded = Inode {
            name: b"abc".to_vec(),
            ..sample_file_inode()
        }
        .encode()
        .unwrap();
        let mut bad_padding = padded.clone();
        bad_padding[FIXED_HEADER_LEN + 3] = 0xFF;
        assert_eq!(Inode::decode(&bad_padding), Err(CodecError::NonzeroPadding));

        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(Inode::decode(&trailing), Err(CodecError::TrailingBytes));

        let mut bad_dir = sample_dir_inode();
        bad_dir.size = 1;
        assert_eq!(bad_dir.encode(), Err(CodecError::DirectoryHasSize(1)));
        let mut bad_dir = sample_dir_inode();
        bad_dir.content_hash = [1u8; CONTENT_HASH_LEN];
        assert_eq!(bad_dir.encode(), Err(CodecError::DirectoryHasContentHash));

        let zero = [0u8; INODE_ID_LEN];
        assert_eq!(validate_inode_id(&zero), Err(CodecError::ZeroInodeId));
        assert_eq!(encode_record_key(&[zero]), Err(CodecError::ZeroInodeId));
        let mut zero_key = b"/_fs/info".to_vec();
        zero_key.extend_from_slice(&zero);
        assert_eq!(
            decode_record_key::<InodePath>(&zero_key),
            Err(CodecError::ZeroInodeId)
        );

        let too_deep = vec![id(9); MAX_CHILD_DEPTH + 1];
        let too_deep_len =
            FS_KEY_NAMESPACE.len() + (MAX_CHILD_DEPTH) * DIR_COMPONENT_LEN + INFO_COMPONENT_LEN;
        assert_eq!(
            encode_record_key(&too_deep),
            Err(CodecError::KeyTooLong { len: too_deep_len })
        );

        let oversized_key = vec![0u8; MAX_FS_KEY_LEN + 1];
        assert_eq!(
            decode_record_key::<InodePath>(&oversized_key),
            Err(CodecError::KeyTooLong {
                len: MAX_FS_KEY_LEN + 1
            })
        );
    }

    #[test]
    fn tree_fs_listing_prefix_excludes_grandchildren() {
        let d = id(1);
        let c = id(2);
        let g = id(3);

        let child_key = encode_record_key(&[d, c]).unwrap();
        let grandchild_key = encode_record_key(&[d, c, g]).unwrap();
        let listing_prefix = encode_children_listing_prefix(&[d]).unwrap();

        assert!(child_key.starts_with(&listing_prefix));
        assert!(!grandchild_key.starts_with(&listing_prefix));
    }

    /// Quantifies the listing read-amplification the `/dir`+`/info` model removes:
    /// a fixture-shaped subtree (branching 5, 10 files/dir, 3 levels) under one
    /// directory D, comparing the keys a listing scans — the new one-level prefix
    /// `CONTAINER(D) ‖ /info` vs the whole-subtree prefix `CONTAINER(D)` the
    /// replaced flat codec had to scan and filter.
    #[test]
    fn list_directory_read_amplification() {
        use std::collections::BTreeSet;

        fn mk(n: &mut u16) -> InodeId {
            *n += 1;
            let mut b = [0u8; INODE_ID_LEN];
            b[..2].copy_from_slice(&n.to_be_bytes());
            b
        }
        fn put(keys: &mut BTreeSet<Vec<u8>>, path: &[InodeId], is_dir: bool) {
            keys.insert(encode_record_key(path).unwrap());
            if is_dir {
                // mirror tree_fs_create's empty-dir container sentinel
                let mut s = encode_container_prefix(path).unwrap();
                s.extend_from_slice(b"/cnt");
                keys.insert(s);
            }
        }

        let mut keys = BTreeSet::new();
        let mut n = 0u16;
        let d = mk(&mut n);
        put(&mut keys, &[d], true);
        for _ in 0..10 {
            let f = mk(&mut n);
            put(&mut keys, &[d, f], false);
        }
        for _ in 0..5 {
            let l2 = mk(&mut n);
            put(&mut keys, &[d, l2], true);
            for _ in 0..10 {
                let f = mk(&mut n);
                put(&mut keys, &[d, l2, f], false);
            }
            for _ in 0..5 {
                let l3 = mk(&mut n);
                put(&mut keys, &[d, l2, l3], true);
                for _ in 0..10 {
                    let f = mk(&mut n);
                    put(&mut keys, &[d, l2, l3, f], false);
                }
            }
        }

        let one_level = encode_children_listing_prefix(&[d]).unwrap();
        let subtree = encode_container_prefix(&[d]).unwrap();
        let n_one = keys.iter().filter(|k| k.starts_with(&one_level)).count();
        let n_sub = keys.iter().filter(|k| k.starts_with(&subtree)).count();

        // The new listing reads exactly the direct children (5 subdirs + 10 files).
        assert_eq!(n_one, 15);
        // The flat whole-subtree scan dwarfs the result it returns.
        assert!(n_sub > 300, "n_sub = {n_sub}");
        eprintln!(
            "list(D): one-level scan = {n_one} keys, whole-subtree scan = {n_sub} keys, \
             read amplification = {:.0}x",
            n_sub as f64 / n_one as f64
        );
    }

    #[test]
    fn max_depth_record_key_encodes() {
        let deepest = vec![id(7); MAX_CHILD_DEPTH];
        let key = encode_record_key(&deepest).expect("deepest path encodes");
        assert!(key.len() <= MAX_FS_KEY_LEN);
        assert_eq!(key.len(), 4_073);
        assert_eq!(
            decode_record_key::<InodePath>(&key).expect("deepest key decodes"),
            deepest
        );

        let too_deep = vec![id(8); MAX_CHILD_DEPTH + 1];
        assert_eq!(
            encode_record_key(&too_deep),
            Err(CodecError::KeyTooLong { len: 4_109 })
        );
    }
}
