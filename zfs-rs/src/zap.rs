//!
//! Datastructures used by the ZFS Attribute Processor
//!
use std::convert::TryFrom;
use std::fmt;
use std::iter::FromIterator;
use std::num::NonZeroU8;
use std::ops::{Deref, DerefMut};

use nom::{number::complete as number, IResult};

use crc::crc64;
use crc::CalcType;

pub struct ZapString(Vec<MyNonZeroU8>);
impl FromIterator<MyNonZeroU8> for ZapString {
    fn from_iter<I: IntoIterator<Item = MyNonZeroU8>>(iter: I) -> Self {
        Self(Vec::from_iter(iter))
    }
}

impl ZapString {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn with_capacity(cap: usize) -> Self {
        Self(Vec::with_capacity(cap))
    }
    pub fn from_byte_slice(slice: &[u8]) -> Option<Self> {
        slice
            .iter()
            .map(|x| Some(MyNonZeroU8(NonZeroU8::new(*x)?)))
            .collect()
    }
    pub fn from_null_terminated(slice: &[u8]) -> Self {
        slice
            .iter()
            .map(|x| Some(MyNonZeroU8(NonZeroU8::new(*x)?)))
            .take_while(|x| x.is_some())
            .flat_map(|x| x)
            .collect()
    }
}

impl fmt::Debug for ZapString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = String::from_utf8_lossy(self.0[..].as_byte_slice());
        fmt::Debug::fmt(&s, f)
    }
}

impl From<Vec<MyNonZeroU8>> for ZapString {
    fn from(v: Vec<MyNonZeroU8>) -> Self {
        Self(v)
    }
}

impl Into<Vec<MyNonZeroU8>> for ZapString {
    fn into(self) -> Vec<MyNonZeroU8> {
        self.0
    }
}

impl Deref for ZapString {
    type Target = Vec<MyNonZeroU8>;
    fn deref(&self) -> &Vec<MyNonZeroU8> {
        &self.0
    }
}

impl DerefMut for ZapString {
    fn deref_mut(&mut self) -> &mut Vec<MyNonZeroU8> {
        &mut self.0
    }
}

pub type ZapStr = [MyNonZeroU8];

#[derive(Clone, Copy, Eq, PartialEq, Debug, Ord, PartialOrd)]
#[repr(transparent)]
pub struct MyNonZeroU8(NonZeroU8);

impl PartialEq<u8> for MyNonZeroU8 {
    fn eq(&self, other: &u8) -> bool {
        self.0.get().eq(other)
    }
}

impl PartialEq<MyNonZeroU8> for u8 {
    fn eq(&self, other: &MyNonZeroU8) -> bool {
        self.eq(&other.0.get())
    }
}

pub trait ToByteSlice {
    fn as_byte_slice(&self) -> &[u8];
}

impl ToByteSlice for [MyNonZeroU8] {
    fn as_byte_slice(&self) -> &[u8] {
        cast_nonzero_u8(self)
    }
}

fn cast_nonzero_u8<'a>(input: &'a [MyNonZeroU8]) -> &'a [u8] {
    unsafe { &*(input as *const [MyNonZeroU8] as *const [u8]) }
}

#[derive(Debug, Clone)]
pub enum ZapResult {
    U8(Vec<u8>),
    U16(Vec<u16>),
    U32(Vec<u32>),
    U64(Vec<u64>),
}

impl ZapResult {
    fn parse(input: &[u8], int_size: u8) -> Option<ZapResult> {
        match int_size {
            1 => Some(ZapResult::U8(input.to_owned())),
            2 => nom::combinator::all_consuming::<_, _, (), _>(nom::multi::many0(number::be_u16))(
                input,
            )
            .ok()
            .map(|o| ZapResult::U16(o.1)),
            4 => nom::combinator::all_consuming::<_, _, (), _>(nom::multi::many0(number::be_u32))(
                input,
            )
            .ok()
            .map(|o| ZapResult::U32(o.1)),
            8 => nom::combinator::all_consuming::<_, _, (), _>(nom::multi::many0(number::be_u64))(
                input,
            )
            .ok()
            .map(|o| ZapResult::U64(o.1)),
            _ => None,
        }
    }
}

const ZBT_MICRO: u64 = (1 << 63) + 3;
const ZBT_HEADER: u64 = (1 << 63) + 1;
const ZBT_LEAF: u64 = (1 << 63) + 0;

#[derive(Debug, Clone)]
pub enum ZapBlock {
    MicroZap(MZapPhys),
    FatHeader(ZapPhys),
    FatLeaf(ZapLeafPhys),
}

impl ZapBlock {
    /// block_size in bytes
    pub fn parse(input: &[u8], block_size: usize) -> IResult<&[u8], Self> {
        nom::branch::alt((
            nom::combinator::map(|i| MZapPhys::parse(i, block_size), Self::MicroZap),
            nom::combinator::map(|i| ZapPhys::parse(i, block_size), Self::FatHeader),
            nom::combinator::map(|i| ZapLeafPhys::parse(i, block_size), Self::FatLeaf),
        ))(input)
    }
}

#[derive(Debug, Clone)]
pub struct MZapPhys {
    pub block_type: u64,
    pub salt: u64,
    pub normflags: u64,
    pub entries: Vec<MZapEntryPhys>,
}

impl MZapPhys {
    /// block_size in bytes
    pub fn parse(input: &[u8], block_size: usize) -> IResult<&[u8], Self> {
        let (input, (block_type, salt, normflags, _pad, entries)) = nom::combinator::map_parser(
            nom::bytes::complete::take(block_size),
            nom::sequence::tuple((
                nom::combinator::verify(number::le_u64, |btype| *btype == ZBT_MICRO),
                number::le_u64,
                number::le_u64,
                nom::bytes::complete::take(5 * 8usize),
                nom::multi::many1(MZapEntryPhys::parse),
            )),
        )(input)?;
        Ok((
            input,
            Self {
                block_type,
                salt,
                normflags,
                entries,
            },
        ))
    }
    pub fn lookup(&self, key: &ZapStr) -> Option<u64> {
        if key.len() >= 50 {
            // mzap strings are 50 bytes long max, including null terminators
            return None;
        }
        self.entries.iter().find_map(|entry| {
            if entry.name[0] == 0 {
                return None;
            }
            if &entry.name[..key.len()] == key && entry.name[key.len()] == 0 {
                Some(entry.value)
            } else {
                None
            }
        })
        //let hash = zap_hash(self.salt, key);
        //let bits = (self.entries.len() + 1).trailing_zeros();
        //let mut idx = zap_hash_idx(hash, bits as u8) as usize % self.entries.len();
        //loop {
        //    let entry = &self.entries[idx];
        //    if entry.name[0] == 0 {
        //        return None;
        //    }
        //    if &entry.name[..key.len()] == key && entry.name[key.len()] == 0 {
        //        return Some(entry.value);
        //    }
        //    idx = (idx + 1) % self.entries.len();
        //}
    }
    pub fn get_entries(&self) -> Vec<(ZapString, u64)> {
        self.entries
            .iter()
            .filter(|e| e.name[0] != 0)
            .map(|e| (ZapString::from_null_terminated(&e.name), e.value))
            .collect()
    }
}

#[derive(Clone)]
pub struct MZapEntryPhys {
    pub value: u64,
    pub cd: u32,
    //name: [u8; 50],
    pub name: Vec<u8>,
}

impl MZapEntryPhys {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (value, cd, _pad, name)) = nom::sequence::tuple((
            number::le_u64,
            number::le_u32,
            nom::bytes::complete::take(2usize),
            nom::bytes::complete::take(50usize),
        ))(input)?;
        Ok((
            input,
            Self {
                value,
                cd,
                name: name.to_vec(),
            },
        ))
    }
}

impl fmt::Debug for MZapEntryPhys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MZapEntryPhys")
            .field("value", &self.value)
            .field("cd", &self.cd)
            .field("name", &&self.name[..])
            .finish()
    }
}

#[derive(Clone)]
pub struct ZapPhys {
    pub block_type: u64,
    pub magic: u64,
    pub ptrtbl: ZapTablePhys,
    pub freeblk: u64,
    pub num_leafs: u64,
    pub num_entries: u64,
    pub salt: u64,
    //leafs: [u64; 8192],
    pub leafs: Vec<u64>,
}

impl fmt::Debug for ZapPhys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZapPhys")
            .field("block_type", &self.block_type)
            .field("magic", &self.magic)
            .field("ptrtbl", &self.ptrtbl)
            .field("freeblk", &self.freeblk)
            .field("num_leafs", &self.num_leafs)
            .field("num_entries", &self.num_entries)
            .field("salt", &self.salt)
            .field("leafs", &&self.leafs[..])
            .finish()
    }
}

impl ZapPhys {
    pub fn parse(input: &[u8], block_size: usize) -> IResult<&[u8], Self> {
        let (
            input,
            (block_type, magic, ptrtbl, freeblk, num_leafs, num_entries, salt, _pad, leafs),
        ) = nom::sequence::tuple((
            nom::combinator::verify(number::le_u64, |btype| *btype == ZBT_HEADER),
            number::le_u64,
            ZapTablePhys::parse,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            nom::bytes::complete::take((block_size / 2) - 88),
            nom::multi::count(number::le_u64, (block_size / 2) / 8),
        ))(input)?;
        Ok((
            input,
            Self {
                block_type,
                magic,
                ptrtbl,
                freeblk,
                num_leafs,
                num_entries,
                salt,
                leafs,
            },
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ZapTablePhys {
    pub blk: u64, // pointer to first block of pointer table, block ID pointer
    pub numblks: u64,
    pub shift: u64,
    pub nextblk: u64,
    pub blk_copied: u64,
}

impl ZapTablePhys {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (blk, numblks, shift, nextblk, blk_copied)) = nom::sequence::tuple((
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
        ))(input)?;
        Ok((
            input,
            Self {
                blk,
                numblks,
                shift,
                nextblk,
                blk_copied,
            },
        ))
    }
}

const ZAP_LEAF_ARRAY_BYTES: usize = 24 - 3;

pub const fn zap_leaf_hash_numentries(block_size: usize) -> usize {
    block_size / 32
}

pub const fn zap_leaf_numchunks(block_size: usize) -> usize {
    ((block_size - (2 * zap_leaf_hash_numentries(block_size))) / 24) - 2
}

const ZAP_CHAIN_END: u16 = 0xffff;

// take the entry_shift number bits following prefix_len number of bits
// 0 0 0 0 0 0 0 1 1 1 1 1 0 0 ....
// | prefix_len | entry_shift |
//                ^ take these
fn leaf_idx(hash: u64, entry_shift: u32, prefix_len: u16) -> u64 {
    let shifted = hash >> (64 - entry_shift as u64 - prefix_len as u64);
    shifted & ((1 << entry_shift) - 1) // mask the high bits we don't want
}

#[derive(Debug, Clone)]
pub struct ZapLeafPhys {
    pub hdr: ZapLeafHeader,
    //hash: [u16; ZAP_LEAF_HASH_NUMENTRIES],
    pub hash: Vec<u16>,
    //chunks: [ZapLeafChunk; ZAP_LEAF_NUMCHUNKS]
    pub chunks: Vec<ZapLeafChunk>,
}

impl ZapLeafPhys {
    /// block_size in bytes
    pub fn parse(input: &[u8], block_size: usize) -> IResult<&[u8], Self> {
        let (input, (hdr,)) = nom::sequence::tuple((ZapLeafHeader::parse,))(input)?;
        let (input, hash) =
            nom::multi::count(number::le_u16, zap_leaf_hash_numentries(block_size))(input)?;
        let (input, chunks) =
            nom::multi::count(ZapLeafChunk::parse, zap_leaf_numchunks(block_size))(input)?;
        Ok((input, Self { hdr, hash, chunks }))
    }
    pub fn lookup(&self, key: &ZapStr, hash: u64, leaf_block_shift: u32) -> Option<ZapResult> {
        let mut leaf_idx = leaf_idx(hash, leaf_block_shift, self.hdr.prefix_len);
        loop {
            let chunk_idx = match self.hash[leaf_idx as usize] {
                ZAP_CHAIN_END => return None,
                i => i,
            };
            let chunk = match &self.chunks[chunk_idx as usize] {
                ZapLeafChunk::Entry(e) => e,
                _ => return None,
            };
            // get name without the trailing null
            let name = match self.get_array(chunk.name_chunk, chunk.name_length as usize - 1) {
                Some(a) => a,
                _ => return None,
            };
            if name == key {
                let array = self.get_array(
                    chunk.value_chunk,
                    chunk.int_size as usize * chunk.value_length as usize,
                )?;
                return ZapResult::parse(&array, chunk.int_size);
            }
            if chunk.next == ZAP_CHAIN_END {
                return None;
            }
            leaf_idx = chunk.next as u64
        }
    }
    fn get_array(&self, mut array_idx: u16, length: usize) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(length);
        loop {
            let a = match &self.chunks[array_idx as usize] {
                ZapLeafChunk::Array(a) => a,
                _ => return None,
            };
            out.extend(&a.array);
            if a.next == ZAP_CHAIN_END {
                out.truncate(length);
                return Some(out);
            } else {
                array_idx = a.next
            }
        }
    }
    fn get_name(&self, mut array_idx: u16, length: usize) -> Option<ZapString> {
        let mut out = ZapString::with_capacity(length);
        loop {
            let a = match &self.chunks[array_idx as usize] {
                ZapLeafChunk::Array(a) => a,
                _ => return None,
            };
            let res = ZapString::from_null_terminated(&a.array);
            let len = res.len();
            (*out).extend::<Vec<MyNonZeroU8>>(res.into());
            if len != a.array.len() {
                return Some(out);
            } else {
                if a.next == ZAP_CHAIN_END {
                    out.truncate(length);
                    return Some(out);
                } else {
                    array_idx = a.next
                }
            }
        }
    }
    pub fn get_entries(&self) -> Vec<(ZapString, ZapResult)> {
        self.chunks
            .iter()
            .filter_map(ZapLeafChunk::entry_ref)
            .filter_map(|entry| {
                // exclude the terminating null
                let name = self.get_name(entry.name_chunk, entry.name_length as usize - 1)?;

                let value = self.get_array(
                    entry.value_chunk,
                    entry.int_size as usize * entry.value_length as usize,
                )?;
                let value = ZapResult::parse(&value, entry.int_size)?;
                Some((name, value))
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ZapLeafHeader {
    pub block_type: u64,
    pub next: u64,
    pub prefix: u64,
    pub magic: u32,
    pub nfree: u16,
    pub nentries: u16,
    pub prefix_len: u16,
    pub freelist: u16,
    pub flags: u8,
}

impl ZapLeafHeader {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (
            input,
            (block_type, next, prefix, magic, nfree, nentries, prefix_len, freelist, flags, _pad),
        ) = nom::sequence::tuple((
            nom::combinator::verify(number::le_u64, |btype| *btype == ZBT_LEAF),
            number::le_u64,
            number::le_u64,
            number::le_u32,
            number::le_u16,
            number::le_u16,
            number::le_u16,
            number::le_u16,
            number::le_u8,
            nom::bytes::complete::take(11usize),
        ))(input)?;
        Ok((
            input,
            Self {
                block_type,
                next,
                prefix,
                magic,
                nfree,
                nentries,
                prefix_len,
                freelist,
                flags,
            },
        ))
    }
}

const ZAP_LEAF_ENTRY: u8 = 252;
const ZAP_LEAF_ARRAY: u8 = 251;
const ZAP_LEAF_FREE: u8 = 253;

#[derive(Debug, Clone)]
pub enum ZapLeafChunk {
    Entry(ZapLeafEntry),
    Array(ZapLeafArray),
    Free(ZapLeafFree),
}

impl ZapLeafChunk {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        nom::branch::alt((ZapLeafEntry::parse, ZapLeafArray::parse, ZapLeafFree::parse))(input)
    }
    pub fn entry(self) -> Option<ZapLeafEntry> {
        use ZapLeafChunk::*;
        match self {
            Entry(e) => Some(e),
            _ => None,
        }
    }
    pub fn entry_ref(&self) -> Option<&ZapLeafEntry> {
        use ZapLeafChunk::*;
        match self {
            Entry(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZapLeafEntry {
    pub kind: u8,
    pub int_size: u8,
    pub next: u16,
    pub name_chunk: u16,
    pub name_length: u16,
    pub value_chunk: u16,
    pub value_length: u16,
    pub cd: u16,
    pub hash: u64,
}

impl ZapLeafEntry {
    pub fn parse(input: &[u8]) -> IResult<&[u8], ZapLeafChunk> {
        let (
            input,
            (
                kind,
                int_size,
                next,
                name_chunk,
                name_length,
                value_chunk,
                value_length,
                cd,
                _pad,
                hash,
            ),
        ) = nom::sequence::tuple((
            nom::combinator::verify(number::le_u8, |kind| *kind == ZAP_LEAF_ENTRY),
            number::le_u8,
            number::le_u16,
            number::le_u16,
            number::le_u16,
            number::le_u16,
            number::le_u16,
            number::le_u16,
            nom::bytes::complete::take(2usize),
            number::le_u64,
        ))(input)?;
        Ok((
            input,
            ZapLeafChunk::Entry(Self {
                kind,
                int_size,
                next,
                name_chunk,
                name_length,
                value_chunk,
                value_length,
                cd,
                hash,
            }),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ZapLeafArray {
    pub kind: u8,
    pub array: [u8; ZAP_LEAF_ARRAY_BYTES],
    pub next: u16,
}

impl ZapLeafArray {
    pub fn parse(input: &[u8]) -> IResult<&[u8], ZapLeafChunk> {
        let (input, (kind, array, next)) = nom::sequence::tuple((
            nom::combinator::verify(number::le_u8, |kind| *kind == ZAP_LEAF_ARRAY),
            nom::bytes::complete::take(ZAP_LEAF_ARRAY_BYTES),
            number::le_u16,
        ))(input)?;
        Ok((
            input,
            ZapLeafChunk::Array(Self {
                kind,
                array: TryFrom::try_from(array).unwrap(),
                next,
            }),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ZapLeafFree {
    pub kind: u8,
    pub next: u16,
}

impl ZapLeafFree {
    pub fn parse(input: &[u8]) -> IResult<&[u8], ZapLeafChunk> {
        let (input, (kind, _pad, next)) = nom::sequence::tuple((
            nom::combinator::verify(number::le_u8, |kind| *kind == ZAP_LEAF_FREE),
            nom::bytes::complete::take(ZAP_LEAF_ARRAY_BYTES),
            number::le_u16,
        ))(input)?;
        Ok((input, ZapLeafChunk::Free(Self { kind, next })))
    }
}

pub fn zap_hash_idx(hash: u64, shift: u8) -> u64 {
    if shift > 0 {
        hash >> (64 - shift)
    } else {
        0
    }
}

pub fn zap_hash(salt: u64, key: &[MyNonZeroU8]) -> u64 {
    let table = crc64::make_table(crc64::ECMA, true);
    crc64::update(salt, &table, key.as_byte_slice(), &CalcType::Reverse)
}
