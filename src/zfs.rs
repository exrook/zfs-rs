use std::convert::{TryFrom, TryInto};
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::Error as IoError;
use std::io::Result as IoResult;
use std::os::unix::fs::FileExt;
use std::path::Path;

use nom::{number::complete as number, IResult};

use enum_repr_derive::TryFrom;

use crc::crc64;
use crc::CalcType;

use crate::compression::decompress_lz4;
use crate::fletcher::{Fletcher2, Fletcher4};

pub struct Disk {
    file: File,
}

impl Disk {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let f = File::open(path).unwrap();
        Self { file: f }
    }
    pub fn read(&self, address: u64, len: u64) -> IoResult<Vec<u8>> {
        let mut buf = vec![0; len as usize];
        self.file.read_exact_at(&mut buf, address)?;
        Ok(buf)
    }
}

pub trait RawDevice {
    type Block: AsRef<[u8]>;
    /// Read the requested amount, given in bytes
    fn read_raw(&self, addr: u64, size: u64) -> IoResult<Self::Block>;
}

impl RawDevice for Disk {
    type Block = Vec<u8>;
    fn read_raw(&self, addr: u64, size: u64) -> IoResult<Self::Block> {
        self.read(addr, size)
    }
}

pub enum ZfsError {
    Checksum,
    Parse(nom::error::ErrorKind),
    Invalid,
    UnsupportedFeature,
    NotFound,
    Io(IoError),
}

impl From<IoError> for ZfsError {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

impl<T> From<nom::Err<(T, nom::error::ErrorKind)>> for ZfsError {
    fn from(e: nom::Err<(T, nom::error::ErrorKind)>) -> Self {
        Self::Parse(match e {
            nom::Err::Incomplete(_) => nom::error::ErrorKind::Complete,
            nom::Err::Error(e) => e.1,
            nom::Err::Failure(f) => f.1,
        })
    }
}

// TODO: better name
#[derive(Debug)]
pub enum RawOrNah<B> {
    Raw(B),
    Nah(Vec<u8>),
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for RawOrNah<B> {
    fn as_ref(&self) -> &[u8] {
        match self {
            RawOrNah::Raw(b) => b.as_ref(),
            RawOrNah::Nah(b) => b.as_ref(),
        }
    }
}

pub trait Device {
    type Block: AsRef<[u8]>;
    fn get(&self, ptr: &BlockPtr) -> Result<RawOrNah<Self::Block>, ZfsError> {
        if ptr.encryption || ptr.embedded_data || ptr.compression_type != CompressionType::LZ4 {
            return Err(ZfsError::UnsupportedFeature);
        }
        let r: Result<Vec<ZfsError>, RawOrNah<Self::Block>> = ptr
            .addresses
            .iter()
            .map(|dva| {
                let block = self.read(*dva)?;
                // check checksums
                match ptr.checksum_type {
                    ChecksumType::ZILog | ChecksumType::Fletcher2 => {
                        // fletcher2
                        let (_input, cksum) = Fletcher2::parse(block.as_ref())?;
                        if ptr.checksum == cksum.into() {
                            Ok(())
                        } else {
                            Err(ZfsError::Checksum)
                        }
                    }
                    ChecksumType::On | ChecksumType::Fletcher4 => {
                        // fletcher4
                        let (_input, cksum) = Fletcher4::parse(block.as_ref())?;
                        if ptr.checksum == cksum.into() {
                            Ok(())
                        } else {
                            Err(ZfsError::Checksum)
                        }
                    }
                    ChecksumType::Label | ChecksumType::GangHeader | ChecksumType::SHA256 => {
                        // SHA256
                        Err(ZfsError::UnsupportedFeature)
                    }
                    ChecksumType::Off => Ok(()), // do nothing
                    _ => {
                        // unsupported
                        Err(ZfsError::UnsupportedFeature)
                    }
                }?;
                // decompress
                Ok(match ptr.compression_type {
                    CompressionType::Off => RawOrNah::Raw(block),
                    CompressionType::LZ4 => RawOrNah::Nah(decompress_lz4(block.as_ref())?.1),
                    _ => Err(ZfsError::UnsupportedFeature)?,
                })
            })
            .map(|r| match r {
                Ok(o) => Err(o),
                Err(e) => Ok(e),
            })
            .collect();
        match r.map(|mut v| v.pop().unwrap()) {
            Ok(e) => Err(e),
            Err(o) => Ok(o),
        }
    }
    fn read(&self, addr: DVA) -> Result<Self::Block, ZfsError>;
}

impl<T, B: AsRef<[u8]>> Device for T
where
    T: RawDevice<Block = B>,
{
    type Block = B;
    fn read(&self, addr: DVA) -> Result<Self::Block, ZfsError> {
        if addr.gang {
            return Err(ZfsError::UnsupportedFeature);
        }
        // offset is stored in units of 512, byte read_raw takes units of bytes
        // this could overflow offset, but I don't have any 2^55 byte drives to test on
        Ok(self.read_raw(addr.offset << 9 + 0x400000, (addr.asize as u64) << 9)?)
    }
}

#[derive(Debug)]
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
            2 => nom::combinator::all_consuming::<_, _, (), _>(nom::multi::many0(number::le_u16))(
                input,
            )
            .ok()
            .map(|o| ZapResult::U16(o.1)),
            4 => nom::combinator::all_consuming::<_, _, (), _>(nom::multi::many0(number::le_u32))(
                input,
            )
            .ok()
            .map(|o| ZapResult::U32(o.1)),
            8 => nom::combinator::all_consuming::<_, _, (), _>(nom::multi::many0(number::le_u64))(
                input,
            )
            .ok()
            .map(|o| ZapResult::U64(o.1)),
            _ => None,
        }
    }
}

/// first tuple element is the id into the top level array, the rest is the remainder
const fn get_block_number(id: u64, level: u8, level_shift: u8) -> (u64, u64) {
    (
        id >> (level as u64 * level_shift as u64),
        id % (1 << (level as u64 * level_shift as u64)),
    )
}

pub trait ZFS {
    type Block: AsRef<[u8]>;
    fn read_block(&self, dnode: &DNodePhys, block_id: u64) -> Result<Self::Block, ZfsError> {
        if block_id > dnode.header.max_block_id {
            return Err(ZfsError::NotFound);
        }
        let level_shift = dnode.header.indirect_block_shift - 7;
        let data_block_size = dnode.header.datablkszsec as u32 * 512;
        let (idx, new_id) = get_block_number(block_id, dnode.header.levels, level_shift);
        self.lookup_block(
            &dnode.block_pointers[idx as usize],
            new_id,
            dnode.header.levels - 1,
            level_shift,
            data_block_size,
        )
    }
    fn lookup_block(
        &self,
        block: &BlockPtr,
        id: u64,
        level: u8,
        level_shift: u8,
        data_block_size: u32,
    ) -> Result<Self::Block, ZfsError>;
    fn read_zap(&self, zap_dnode: &DNodePhys, key: &[u8]) -> Result<Option<ZapResult>, ZfsError> {
        let input = self.read_block(zap_dnode, 0)?;
        let block_size = zap_dnode.header.datablkszsec as usize * 512;
        let leaf_block_shift = ZAP_LEAF_HASH_NUMENTRIES(block_size).trailing_zeros();
        let (input, zap_header) = ZapBlock::parse(input.as_ref(), block_size)?;
        match zap_header {
            ZapBlock::MicroZap(micro) => Ok(micro.lookup(key).map(|k| ZapResult::U64(vec![k]))),
            ZapBlock::FatHeader(zap_header) => {
                let hash = zap_hash(zap_header.salt, key);
                let idx = zap_hash_idx(hash, zap_header.ptrtbl.shift as u8);
                let mut leaf_block_num = match if (zap_header.ptrtbl.blk == 0) {
                    // use embedded pointer table
                    zap_header.leafs[idx as usize]
                } else {
                    let block_idx = (idx) / (block_size as u64 / 8);
                    let idx = idx as usize % (block_size / 8);
                    if block_idx > zap_header.ptrtbl.numblks {
                        return Err(ZfsError::Invalid);
                    }
                    let tbl = self.read_block(zap_dnode, zap_header.ptrtbl.blk + block_idx)?;
                    let (_, num) = number::le_u64(&tbl.as_ref()[idx * 8..])?;
                    num
                    // use external pointer table
                } {
                    0 => return Ok(None), // Entry not found
                    p => p,
                };
                // loop through the chained leaf blocks
                loop {
                    let input = self.read_block(zap_dnode, leaf_block_num)?;
                    let (input, leaf_block) = ZapLeafPhys::parse(input.as_ref(), block_size)?;
                    match leaf_block.lookup(key, hash, leaf_block_shift) {
                        Some(v) => return Ok(Some(v)),
                        None => {}
                    }
                    if leaf_block.hdr.next == 0 {
                        return Ok(None);
                    }
                    leaf_block_num = leaf_block.hdr.next;
                }
            }
            ZapBlock::FatLeaf(_) => Err(ZfsError::Invalid),
        }
    }
    fn zap_entries(&self, zap_dnode: &DNodePhys) -> Result<Vec<(CString, ZapResult)>, ZfsError> {
        let input = self.read_block(zap_dnode, 0)?;
        let block_size = zap_dnode.header.datablkszsec as usize * 512;
        let (input, zap_header) = ZapBlock::parse(input.as_ref(), block_size)?;
        match zap_header {
            ZapBlock::MicroZap(micro) => Ok(micro
                .get_entries()
                .into_iter()
                .map(|(key, val)| (key, ZapResult::U64(vec![val])))
                .collect()),
            ZapBlock::FatHeader(zap_header) => {
                let block_list: Vec<u64> = if zap_header.ptrtbl.blk == 0 {
                    zap_header
                        .leafs
                        .iter()
                        .filter(|p| **p != 0)
                        .map(|i| *i)
                        .collect()
                } else {
                    let mut out = vec![];
                    for i in (0..zap_header.ptrtbl.numblks) {
                        let block = self.read_block(zap_dnode, zap_header.ptrtbl.blk + i)?;
                        let nums = nom::multi::many0(number::le_u64)(block.as_ref())?.1;
                        out.extend(nums.into_iter().filter(|p| *p != 0));
                    }
                    out
                };
                let mut out = vec![];
                for blocknum in block_list {
                    let input = self.read_block(zap_dnode, blocknum)?;
                    let (input, leaf_block) = ZapLeafPhys::parse(input.as_ref(), block_size)?;
                    out.extend(leaf_block.get_entries())
                }
                Ok(out)
            }
            ZapBlock::FatLeaf(_) => Err(ZfsError::Invalid),
        }
    }
}

impl<T, B> ZFS for T
where
    T: Device<Block = B>,
    B: AsRef<[u8]>,
{
    type Block = RawOrNah<B>;
    fn lookup_block(
        &self,
        block: &BlockPtr,
        block_id: u64,
        level: u8,
        level_shift: u8,
        data_block_size: u32,
    ) -> Result<Self::Block, ZfsError> {
        let block = self.get(block)?;
        if level != 0 {
            let (idx, new_id) = get_block_number(block_id, level, level_shift);
            let (_input, block_pointer) = BlockPtr::parse(&block.as_ref()[idx as usize * 128..])?;
            self.lookup_block(
                &block_pointer,
                new_id,
                level - 1,
                level_shift,
                data_block_size,
            )
        } else {
            Ok(block)
        }
    }
}

#[derive(Copy, Clone)]
pub struct DVA {
    vdev: u32,
    grid: u8,
    asize: u32,
    offset: u64,
    gang: bool,
}

impl fmt::Debug for DVA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DVA")
            .field("vdev", &self.vdev)
            .field("grid", &self.grid)
            .field("asize", &self.asize)
            .field("offset", &format!("{:x}", self.offset << 9))
            .field("gang", &self.gang)
            .finish()
    }
}

impl DVA {
    pub fn from_raw(bytes: &[u8]) -> Self {
        assert!(bytes.len() == 16);
        Self::parse(bytes).unwrap().1
    }
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        use nom::{bits, take_bits, tuple};
        let (input, (asize, grid, vdev)) =
            nom::sequence::tuple((number::le_u24, number::le_u8, number::le_u32))(input)?;
        let (input, (offset, gang)): (_, (u64, u8)) =
            bits!(input, tuple!(take_bits!(63usize), take_bits!(1usize)))?;
        let gang = if gang == 0 { false } else { true };
        Ok((
            input,
            Self {
                vdev,
                grid,
                asize,
                offset,
                gang,
            },
        ))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Checksum {
    checksum: [u64; 4],
}

impl From<Fletcher4> for Checksum {
    fn from(f: Fletcher4) -> Self {
        Self {
            checksum: [f.a, f.b, f.c, f.d],
        }
    }
}

impl From<Fletcher2> for Checksum {
    fn from(f: Fletcher2) -> Self {
        Self {
            checksum: [f.a0, f.a1, f.b0, f.b1],
        }
    }
}

impl Checksum {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (c1, c2, c3, c4)) = nom::sequence::tuple((
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
        ))(input)?;
        Ok((
            input,
            Self {
                checksum: [c1, c2, c3, c4],
            },
        ))
    }
}

#[repr(u8)]
#[derive(Debug, TryFrom, Eq, PartialEq)]
enum CompressionType {
    Inherit = 0,
    On = 1,
    Off = 2,
    LZJB = 3,
    Empty = 4,
    GZIP1 = 5,
    GZIP2 = 6,
    GZIP3 = 7,
    GZIP4 = 8,
    GZIP5 = 9,
    GZIP6 = 10,
    GZIP7 = 11,
    GZIP8 = 12,
    GZIP9 = 13,
    ZLE = 14,
    LZ4 = 15,
}

impl CompressionType {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        nom::combinator::map_res(number::le_u8, |x| Self::try_from(x))(input)
    }
}

#[repr(u8)]
#[derive(Debug, TryFrom, Eq, PartialEq)]
enum ChecksumType {
    Inherit = 0,
    On = 1,
    Off = 2,
    Label = 3,
    GangHeader = 4,
    ZILog = 5,
    Fletcher2 = 6,
    Fletcher4 = 7,
    SHA256 = 8,
    ZILog2 = 9,
    NoParity = 10,
    SHA512 = 11,
    Skein = 12,
}

impl ChecksumType {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        nom::combinator::map_res(number::le_u8, |x| Self::try_from(x))(input)
    }
}

#[derive(Debug)]
pub struct BlockPtr {
    addresses: [DVA; 3],
    byteorder: bool,
    dedup: bool,
    encryption: bool,
    indirection_level: u8,
    kind: u8,
    checksum_type: ChecksumType,
    compression_type: CompressionType,
    embedded_data: bool,
    physical_size: u16,
    logical_size: u16,
    physical_transaction: u64,
    logical_transaction: u64,
    fill_count: u64,
    checksum: Checksum,
}

impl BlockPtr {
    pub fn from_raw(bytes: &[u8]) -> Self {
        assert!(bytes.len() == 128);
        Self::parse(bytes).unwrap().1
    }
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        use nom::{bits, map_res, take_bits, tuple};
        let (input, (a1, a2, a3)) =
            nom::sequence::tuple((DVA::parse, DVA::parse, DVA::parse))(input)?;
        let addresses = [a1, a2, a3];
        let (input, (logical_size, physical_size)) =
            nom::sequence::tuple((number::le_u16, number::le_u16))(input)?;
        let (input, (compression_type, embedded_data)): (_, (_, u8)) = bits!(
            input,
            tuple!(
                map_res!(take_bits!(7usize), TryFrom::<u8>::try_from),
                take_bits!(1usize)
            )
        )?;
        let embedded_data = embedded_data != 0;
        let (input, (checksum_type, kind)) =
            nom::sequence::tuple((ChecksumType::parse, number::le_u8))(input)?;
        let (input, (indirection_level, encryption, dedup, byteorder)): (_, (_, u8, u8, u8)) = bits!(
            input,
            tuple!(
                take_bits!(5usize),
                take_bits!(1usize),
                take_bits!(1usize),
                take_bits!(1usize)
            )
        )?;
        let encryption = encryption != 0;
        let dedup = dedup != 0;
        let byteorder = byteorder != 0;
        let (input, (_pad, physical_transaction, logical_transaction, fill_count)) =
            nom::sequence::tuple((
                nom::bytes::complete::take(16usize),
                number::le_u64,
                number::le_u64,
                number::le_u64,
            ))(input)?;
        let (input, checksum) = Checksum::parse(input)?;
        Ok((
            input,
            Self {
                addresses,
                logical_size,
                physical_size,
                compression_type,
                embedded_data,
                checksum_type,
                kind,
                indirection_level,
                encryption,
                dedup,
                byteorder,
                physical_transaction,
                logical_transaction,
                fill_count,
                checksum,
            },
        ))
    }
}

#[derive(Debug)]
pub struct ZioGbh {
    blkptr: [BlockPtr; 3],
    tail: ZioBlockTail,
}

impl ZioGbh {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (b0, b1, b2, _pad, tail)) = nom::sequence::tuple((
            BlockPtr::parse,
            BlockPtr::parse,
            BlockPtr::parse,
            nom::bytes::complete::take(512usize - (128 * 3) - (5 * 8)),
            ZioBlockTail::parse,
        ))(input)?;
        Ok((
            input,
            Self {
                blkptr: [b0, b1, b2],
                tail,
            },
        ))
    }
}

#[derive(Debug)]
pub struct ZioBlockTail {
    magic: u64,
    checksum: Checksum,
}

impl ZioBlockTail {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (magic, checksum)) =
            nom::sequence::tuple((number::le_u64, Checksum::parse))(input)?;
        Ok((input, Self { magic, checksum }))
    }
}

#[derive(Debug)]
pub struct DNodePhysHeader {
    pub kind: u8,
    pub indirect_block_shift: u8,
    pub levels: u8,
    pub num_block_ptr: u8,
    pub bonus_type: u8,
    pub checksum: u8,
    pub compress: u8,
    pub datablkszsec: u16, // idk what this one is
    pub bonus_len: u16,
    pub max_block_id: u64,
    pub sec_phys: u64,
}

impl DNodePhysHeader {
    pub fn from_raw(bytes: &[u8]) -> Self {
        assert!(bytes.len() == 64);
        Self::parse(bytes).unwrap().1
    }
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (
            input,
            (kind, indirect_block_shift, levels, num_block_ptr, bonus_type, checksum, compress),
        ) = nom::sequence::tuple((
            number::le_u8,
            number::le_u8,
            number::le_u8,
            number::le_u8,
            number::le_u8,
            number::le_u8,
            number::le_u8,
        ))(input)?;
        let (input, _pad) = nom::bytes::complete::take(1usize)(input)?;
        let (input, (datablkszsec, bonus_len)) =
            nom::sequence::tuple((number::le_u16, number::le_u16))(input)?;
        let (input, _pad) = nom::bytes::complete::take(4usize)(input)?;
        let (input, (max_block_id, sec_phys)) =
            nom::sequence::tuple((number::le_u64, number::le_u64))(input)?;
        Ok((
            input,
            Self {
                kind,
                indirect_block_shift,
                levels,
                num_block_ptr,
                bonus_type,
                checksum,
                compress,
                datablkszsec,
                bonus_len,
                max_block_id,
                sec_phys,
            },
        ))
    }
}

#[derive(Debug)]
pub struct DNodePhys {
    header: DNodePhysHeader,
    block_pointers: Vec<BlockPtr>,
    bonus: Vec<u8>,
}

impl DNodePhys {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        nom::combinator::map_parser(nom::bytes::complete::take(512usize), |input| {
            let (input, header) = DNodePhysHeader::parse(input)?;
            let (input, block_pointers) =
                nom::multi::count(BlockPtr::parse, header.num_block_ptr as usize)(input)?;
            let (input, bonus) = nom::bytes::complete::take(header.bonus_len as usize)(input)?;
            Ok((
                input,
                Self {
                    header,
                    block_pointers,
                    bonus: bonus.to_vec(),
                },
            ))
        })(input)
    }
}

#[derive(Debug)]
pub struct ObjsetPhys {
    metadnode: DNodePhys,
    os_zil_header: ZilHeader,
    os_type: OsType,
}

impl ObjsetPhys {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (metadnode, os_zil_header, os_type)) = nom::combinator::map_parser(
            nom::bytes::complete::take(1024usize),
            nom::sequence::tuple((DNodePhys::parse, ZilHeader::parse, OsType::parse)),
        )(input)?;
        Ok((
            input,
            Self {
                metadnode,
                os_zil_header,
                os_type,
            },
        ))
    }
}

#[derive(Debug)]
pub struct ZilHeader {
    claim_txg: u64,
    replay_seq: u64,
    log: BlockPtr,
}

impl ZilHeader {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (claim_txg, replay_seq, log)) =
            nom::sequence::tuple((number::le_u64, number::le_u64, BlockPtr::parse))(input)?;
        Ok((
            input,
            Self {
                claim_txg,
                replay_seq,
                log,
            },
        ))
    }
}

#[derive(Debug, TryFrom)]
#[repr(u64)]
pub enum OsType {
    NONE = 0,
    META = 1,
    ZFS = 2,
    ZVOL = 3,
}

impl OsType {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        nom::combinator::map_res(number::le_u64, |x| OsType::try_from(x))(input)
    }
}

#[derive(Debug)]
pub struct DatasetPhys {
    dir_obj: u64,
    prev_snap_obj: u64,
    prev_snap_obj_transaction: u64,
    next_snap_obj: u64,
    snapnames_zapobj: u64,
    num_children: u64,
    creation_time: u64,
    creation_txg: u64,
    deadlist_obj: u64,
    referenced_bytes: u64,
    compressed_bytes: u64,
    uncompressed_bytes: u64,
    unique_bytes: u64,
    fsid_guid: u64,
    guid: u64,
    flags: u64,
    bp: BlockPtr,
    next_clones_obj: u64,
    props_obj: u64,
    userrefs_obj: u64,
}

impl DatasetPhys {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (
            input,
            (
                dir_obj,
                prev_snap_obj,
                prev_snap_obj_transaction,
                next_snap_obj,
                snapnames_zapobj,
                num_children,
                creation_time,
                creation_txg,
                deadlist_obj,
                referenced_bytes,
                compressed_bytes,
                uncompressed_bytes,
                unique_bytes,
                fsid_guid,
                guid,
                flags,
                bp,
                next_clones_obj,
                props_obj,
                userrefs_obj,
            ),
        ) = nom::combinator::map_parser(
            nom::bytes::complete::take(320usize),
            nom::sequence::tuple((
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                BlockPtr::parse,
                number::le_u64,
                number::le_u64,
                number::le_u64,
            )),
        )(input)?;
        Ok((
            input,
            Self {
                dir_obj,
                prev_snap_obj,
                prev_snap_obj_transaction,
                next_snap_obj,
                snapnames_zapobj,
                num_children,
                creation_time,
                creation_txg,
                deadlist_obj,
                referenced_bytes,
                compressed_bytes,
                uncompressed_bytes,
                unique_bytes,
                fsid_guid,
                guid,
                flags,
                bp,
                next_clones_obj,
                props_obj,
                userrefs_obj,
            },
        ))
    }
}

#[derive(Debug)]
pub struct DirPhys {
    creation_time: u64,
    head_dataset_obj: u64,
    parent_obj: u64,
    clone_parent_obj: u64,
    clone_dir_zapobj: u64,
    used_bytes: u64,
    compressed_bytes: u64,
    uncompressed_bytes: u64,
    quota: u64,
    reserved: u64,
    props_zapobj: u64,
    deleg_zapobj: u64,
    flags: u64,
    used_breakdown: [u64; 5],
    clones: u64,
}

impl DirPhys {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (
            input,
            (
                creation_time,
                head_dataset_obj,
                parent_obj,
                clone_parent_obj,
                clone_dir_zapobj,
                used_bytes,
                compressed_bytes,
                uncompressed_bytes,
                quota,
                reserved,
                props_zapobj,
                deleg_zapobj,
                flags,
                b1,
                b2,
                b3,
                b4,
                b5,
                clones,
            ),
        ) = nom::combinator::map_parser(
            nom::bytes::complete::take(320usize),
            nom::sequence::tuple((
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                number::le_u64,
            )),
        )(input)?;
        Ok((
            input,
            Self {
                creation_time,
                head_dataset_obj,
                parent_obj,
                clone_parent_obj,
                clone_dir_zapobj,
                used_bytes,
                compressed_bytes,
                uncompressed_bytes,
                quota,
                reserved,
                props_zapobj,
                deleg_zapobj,
                flags,
                used_breakdown: [b1, b2, b3, b4, b5],
                clones,
            },
        ))
    }
}

const ZBT_MICRO: u64 = (1 << 63) + 3;
const ZBT_HEADER: u64 = (1 << 63) + 1;
const ZBT_LEAF: u64 = (1 << 63) + 0;

enum ZapBlock {
    MicroZap(MZapPhys),
    FatHeader(ZapPhys),
    FatLeaf(ZapLeafPhys),
}

impl ZapBlock {
    /// block_size in bytes
    pub fn parse(input: &[u8], block_size: usize) -> IResult<&[u8], Self> {
        nom::branch::alt((
            nom::combinator::map(|i| MZapPhys::parse(i, block_size), Self::MicroZap),
            nom::combinator::map(ZapPhys::parse, Self::FatHeader),
            nom::combinator::map(|i| ZapLeafPhys::parse(i, block_size), Self::FatLeaf),
        ))(input)
    }
}

#[derive(Debug)]
pub struct MZapPhys {
    block_type: u64,
    salt: u64,
    normflags: u64,
    entries: Vec<MZapEntryPhys>,
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
                nom::bytes::complete::take(40usize),
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
    pub fn lookup(&self, key: &[u8]) -> Option<u64> {
        if key.len() >= 50 {
            // mzap strings are 50 bytes long max, including null terminators
            return None;
        }
        let hash = zap_hash(self.salt, key);
        let bits = (self.entries.len() + 1).trailing_zeros();
        let mut idx = zap_hash_idx(hash, bits as u8) as usize & self.entries.len();
        loop {
            let entry = &self.entries[idx];
            if entry.name[0] == 0 {
                return None;
            }
            if &entry.name[..key.len()] == key && entry.name[key.len()] == 0 {
                return Some(entry.value);
            }
            idx = (idx + 1) & self.entries.len();
        }
    }
    pub fn get_entries(&self) -> Vec<(CString, u64)> {
        self.entries
            .iter()
            .filter(|e| e.name[0] != 0)
            .map(|e| {
                let null_idx = e.name.iter().position(|c| *c == 0).unwrap_or(e.name.len());
                (CString::new(&e.name[..null_idx]).unwrap(), e.value) // we found the null byte so this should never panic
            })
            .collect()
    }
}

pub struct MZapEntryPhys {
    value: u64,
    cd: u32,
    //name: [u8; 50],
    name: Vec<u8>,
}

impl MZapEntryPhys {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (value, cd, name)) = nom::sequence::tuple((
            number::le_u64,
            number::le_u32,
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

pub struct ZapPhys {
    block_type: u64,
    magic: u64,
    ptrtbl: ZapTablePhys,
    freeblk: u64,
    num_leafs: u64,
    num_entries: u64,
    salt: u64,
    //leafs: [u64; 8192],
    leafs: Vec<u64>,
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
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
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
            nom::bytes::complete::take(8181 * 8usize),
            nom::multi::count(number::le_u64, 8192),
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

#[derive(Debug)]
pub struct ZapTablePhys {
    blk: u64, // pointer to first block of pointer table, block ID pointer
    numblks: u64,
    shift: u64,
    nextblk: u64,
    blk_copied: u64,
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

//const ZAP_LEAF_HASH_NUMENTRIES: usize = 4096;
//const ZAP_LEAF_NUMCHUNKS: usize = 0; // TODO find correct value
const ZAP_LEAF_ARRAY_BYTES: usize = 24 - 3;

const fn ZAP_LEAF_HASH_NUMENTRIES(block_size: usize) -> usize {
    block_size / 32
}

const fn ZAP_LEAF_NUMCHUNKS(block_size: usize) -> usize {
    (block_size - (2 * ZAP_LEAF_HASH_NUMENTRIES(block_size)) / 24) - 2
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

#[derive(Debug)]
pub struct ZapLeafPhys {
    hdr: ZapLeafHeader,
    //hash: [u16; ZAP_LEAF_HASH_NUMENTRIES],
    hash: Vec<u16>,
    //chunks: [ZapLeafChunk; ZAP_LEAF_NUMCHUNKS]
    chunks: Vec<ZapLeafChunk>,
}

impl ZapLeafPhys {
    /// block_size in bytes
    pub fn parse(input: &[u8], block_size: usize) -> IResult<&[u8], Self> {
        let (input, (hdr, hash, chunks)) = nom::sequence::tuple((
            ZapLeafHeader::parse,
            nom::multi::count(number::le_u16, ZAP_LEAF_HASH_NUMENTRIES(block_size)),
            nom::multi::count(ZapLeafChunk::parse, ZAP_LEAF_NUMCHUNKS(block_size)),
        ))(input)?;
        Ok((input, Self { hdr, hash, chunks }))
    }
    pub fn lookup(&self, key: &[u8], hash: u64, leaf_block_shift: u32) -> Option<ZapResult> {
        let mut leaf_idx = leaf_idx(hash, leaf_block_shift, self.hdr.prefix_len);
        loop {
            let chunk = match &self.chunks[leaf_idx as usize] {
                ZapLeafChunk::Entry(e) => e,
                _ => return None,
            };
            // get name without the trailing null
            let name = match self.get_array(chunk.name_chunk, chunk.name_length as usize - 1) {
                Some(a) => a,
                _ => return None,
            };
            if name == key {
                let array = self.get_array(chunk.value_chunk, chunk.value_length as usize)?;
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
    pub fn get_entries(&self) -> Vec<(CString, ZapResult)> {
        self.chunks
            .iter()
            .filter_map(ZapLeafChunk::entry_ref)
            .filter_map(|entry| {
                // exclude the terminating null
                let name =
                    CString::new(self.get_array(entry.name_chunk, entry.name_length as usize - 1)?)
                        .ok()?;
                let value = self.get_array(entry.value_chunk, entry.value_length as usize)?;
                let value = ZapResult::parse(&value, entry.int_size)?;
                Some((name, value))
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct ZapLeafHeader {
    block_type: u64,
    next: u64,
    prefix: u64,
    magic: u32,
    nfree: u16,
    nentries: u16,
    prefix_len: u16,
    freelist: u16,
    flags: u8,
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

#[derive(Debug)]
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

#[derive(Debug)]
pub struct ZapLeafEntry {
    kind: u8,
    int_size: u8,
    next: u16,
    name_chunk: u16,
    name_length: u16,
    value_chunk: u16,
    value_length: u16,
    cd: u16,
    hash: u64,
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

#[derive(Debug)]
pub struct ZapLeafArray {
    kind: u8,
    array: [u8; ZAP_LEAF_ARRAY_BYTES],
    next: u16,
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

#[derive(Debug)]
pub struct ZapLeafFree {
    kind: u8,
    next: u16,
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

fn zap_hash_idx(hash: u64, shift: u8) -> u64 {
    if shift > 0 {
        hash >> (64 - shift)
    } else {
        0
    }
}

fn zap_hash(salt: u64, key: &[u8]) -> u64 {
    let table = crc64::make_table(crc64::ECMA, true);
    crc64::update(salt, &table, key, &CalcType::Reverse)
}

#[derive(Debug)]
pub struct ZNodePhys {
    atime: [u64; 2],
    mtime: [u64; 2],
    ctime: [u64; 2],
    crtime: [u64; 2],
    gen: u64,
    mode: u64,
    parent: u64,
    links: u64,
    xattr: u64,
    rdev: u64,
    flags: u64,
    uid: u64,
    gid: u64,
    acl: ZNodeAcl,
}

impl ZNodePhys {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (
            input,
            (
                at0,
                at1,
                mt0,
                mt1,
                ct0,
                ct1,
                crt0,
                crt1,
                gen,
                mode,
                parent,
                links,
                xattr,
                rdev,
                flags,
                uid,
                gid,
                _pad,
                acl,
            ),
        ) = nom::sequence::tuple((
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            nom::bytes::complete::take(8 * 4usize),
            ZNodeAcl::parse,
        ))(input)?;
        Ok((
            input,
            Self {
                atime: [at0, at1],
                mtime: [mt0, mt1],
                ctime: [ct0, ct1],
                crtime: [crt0, crt1],
                gen,
                mode,
                parent,
                links,
                xattr,
                rdev,
                flags,
                uid,
                gid,
                acl,
            },
        ))
    }
}

pub const ACE_SLOT_CNT: usize = 6;

#[derive(Debug)]
pub struct ZNodeAcl {
    extern_obj: u64,
    count: u32,
    version: u16,
    ace_data: [Ace; ACE_SLOT_CNT],
}

impl ZNodeAcl {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (extern_obj, count, version, _pad, ace_data)) = nom::sequence::tuple((
            number::le_u64,
            number::le_u32,
            number::le_u16,
            nom::bytes::complete::take(2usize),
            nom::multi::count(Ace::parse, ACE_SLOT_CNT),
        ))(input)?;
        let ace_data: &[_; ACE_SLOT_CNT] = (*ace_data).try_into().unwrap();
        Ok((
            input,
            Self {
                extern_obj,
                count,
                version,
                ace_data: ace_data.clone(),
            },
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Ace {
    who: u64,
    access_mask: u32,
    flags: u16,
    kind: u16,
}

impl Ace {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (who, access_mask, flags, kind)) = nom::sequence::tuple((
            number::le_u64,
            number::le_u32,
            number::le_u16,
            number::le_u16,
        ))(input)?;
        Ok((
            input,
            Ace {
                who,
                access_mask,
                flags,
                kind,
            },
        ))
    }
}

#[derive(Debug)]
pub struct ZilTrailer {
    next_blk: BlockPtr,
    nused: u64,
    bt: ZioBlockTail,
}

impl ZilTrailer {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (next_blk, nused, bt)) =
            nom::sequence::tuple((BlockPtr::parse, number::le_u64, ZioBlockTail::parse))(input)?;
        Ok((
            input,
            Self {
                next_blk,
                nused,
                bt,
            },
        ))
    }
}

#[derive(Debug)]
pub struct ZilLogRecord {
    txtype: u64,
    reclen: u64,
    txg: u64,
    seq: u64,
}

impl ZilLogRecord {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (txtype, reclen, txg, seq)) = nom::sequence::tuple((
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
        ))(input)?;
        Ok((
            input,
            Self {
                txtype,
                reclen,
                txg,
                seq,
            },
        ))
    }
}
