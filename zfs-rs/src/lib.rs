#![feature(backtrace)]
use std::backtrace::Backtrace;
use std::convert::{TryFrom, TryInto};
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::Error as IoError;
use std::io::Result as IoResult;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use thiserror::Error;

use nom::{number::complete as number, IResult};

use enum_repr_derive::TryFrom;

use crc::crc64;
use crc::CalcType;

mod compression;
mod fletcher;

use crate::compression::decompress_lz4;
use crate::fletcher::{Fletcher2, Fletcher4};

#[derive(Debug)]
pub struct Disk {
    file: File,
}

impl Disk {
    pub fn new<P: AsRef<Path>>(path: P) -> IoResult<Self> {
        let f = File::open(path)?;
        Ok(Self { file: f })
    }
    pub fn read(&self, address: u64, len: u64) -> IoResult<Vec<u8>> {
        let mut buf = vec![0; len as usize];
        (&self.file).seek(SeekFrom::Start(address))?;
        (&self.file).read_exact(&mut buf)?;
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

#[derive(Debug, Error)]
#[error("{source}, {backtrace}")]
pub struct ZfsError {
    #[from]
    pub source: ZfsErrorKind,
    backtrace: Backtrace,
}

impl From<IoError> for ZfsError {
    fn from(e: IoError) -> Self {
        ZfsErrorKind::from(e).into()
    }
}

impl<T> From<nom::Err<(T, nom::error::ErrorKind)>> for ZfsError {
    fn from(e: nom::Err<(T, nom::error::ErrorKind)>) -> Self {
        ZfsErrorKind::from(e).into()
    }
}

#[derive(Debug, Error)]
pub enum ZfsErrorKind {
    #[error("Checksum validation error")]
    Checksum,
    #[error("Data parse error {0:?}")]
    Parse(nom::error::ErrorKind),
    #[error("Invalid data error")]
    Invalid,
    #[error("Unsupported feature present")]
    UnsupportedFeature,
    #[error("Required data not found")]
    NotFound,
    #[error("IO Error {0}")]
    Io(IoError),
}

impl From<IoError> for ZfsErrorKind {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

impl<T> From<nom::Err<(T, nom::error::ErrorKind)>> for ZfsErrorKind {
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
        if ptr.encryption
            || !(ptr.compression_type == CompressionType::LZ4
                || ptr.compression_type == CompressionType::Off
                || ptr.compression_type == CompressionType::On)
        {
            return Err(ZfsErrorKind::UnsupportedFeature)?;
        }
        match &ptr.embedded {
            BlockPtrKind::Ptr(ptrdata) => {
                let r: Result<Vec<ZfsError>, RawOrNah<Self::Block>> = ptrdata
                    .addresses
                    .iter()
                    .filter(|dva| dva.asize != 0)
                    .map(|dva| {
                        let block = self.read(*dva)?;
                        let data_size = if ptr.logical_size % 2 == 1 {
                            ptr.physical_size + 1
                        } else {
                            ptr.physical_size
                        } as usize
                            * 512;
                        let data_size = if data_size == 0 { 512 } else { data_size };
                        let data = &block.as_ref()[..data_size];
                        // check checksums
                        match ptrdata.checksum_type {
                            ChecksumType::ZILog | ChecksumType::Fletcher2 => {
                                // fletcher2
                                let (_input, cksum) = Fletcher2::parse(data)?;
                                if ptrdata.checksum == cksum.into() {
                                    Ok(())
                                } else {
                                    Err(ZfsErrorKind::Checksum)
                                }
                            }
                            ChecksumType::On | ChecksumType::Fletcher4 => {
                                // fletcher4
                                let (_input, cksum) = Fletcher4::parse(data)?;
                                if ptrdata.checksum == cksum.into() {
                                    Ok(())
                                } else {
                                    Err(ZfsErrorKind::Checksum)
                                }
                            }
                            ChecksumType::Label
                            | ChecksumType::GangHeader
                            | ChecksumType::SHA256 => {
                                // SHA256
                                Err(ZfsErrorKind::UnsupportedFeature)
                            }
                            ChecksumType::Off => Ok(()), // do nothing
                            _ => {
                                // unsupported
                                Err(ZfsErrorKind::UnsupportedFeature)
                            }
                        }?;
                        // decompress
                        Ok(match ptr.compression_type {
                            CompressionType::Off => RawOrNah::Raw(block),
                            CompressionType::LZ4 | CompressionType::On => {
                                RawOrNah::Nah(decompress_lz4(data)?.1)
                            }
                            _ => Err(ZfsErrorKind::UnsupportedFeature)?,
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
            BlockPtrKind::Data(block) => Ok(RawOrNah::Nah(match ptr.compression_type {
                CompressionType::Off => block.clone(),
                CompressionType::LZ4 | CompressionType::On => decompress_lz4(block)?.1,
                _ => Err(ZfsErrorKind::UnsupportedFeature)?,
            })),
        }
    }
    fn get_label(&self, label_num: u8) -> Result<Label, ZfsError>;
    fn read(&self, addr: DVA) -> Result<Self::Block, ZfsError>;
}

impl<T, B: AsRef<[u8]>> Device for T
where
    T: RawDevice<Block = B>,
{
    type Block = B;
    fn get_label(&self, label_num: u8) -> Result<Label, ZfsError> {
        if label_num < 2 {
            Ok(Label::parse(
                self.read_raw(label_num as u64 * 256 * 1024, 256 * 1024)?
                    .as_ref(),
            )?
            .1)
        } else {
            Err(ZfsErrorKind::UnsupportedFeature.into())
        }
    }
    fn read(&self, addr: DVA) -> Result<Self::Block, ZfsError> {
        if addr.gang {
            return Err(ZfsErrorKind::UnsupportedFeature.into());
        }
        // offset is stored in units of 512, byte read_raw takes units of bytes
        // this could overflow offset, but I don't have any 2^55 byte drives to test on
        Ok(self.read_raw((addr.offset << 9) + 0x400000, (addr.asize as u64) << 9)?)
    }
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

const fn get_level_index(id: u64, level: u8, level_shift: u8) -> u64 {
    (id >> (level as u64 * level_shift as u64)) % (1 << (level_shift as u64))
}

pub trait ZFS {
    type Block: AsRef<[u8]>;
    fn read_block(&self, dnode: &DNodePhys, block_id: u64) -> Result<Self::Block, ZfsError> {
        if block_id > dnode.header.max_block_id {
            return Err(ZfsErrorKind::NotFound.into());
        }
        let level_shift = dnode.header.indirect_block_shift - 7;
        let data_block_size = dnode.header.datablkszsec as u32 * 512;
        let idx = get_level_index(block_id, dnode.header.levels - 1, level_shift);
        self.lookup_block(
            &dnode.block_pointers[idx as usize],
            block_id,
            dnode.header.levels - 1,
            level_shift,
            data_block_size,
        )
    }
    fn read_dnode(&self, dnode: &DNodePhys, dnode_id: u64) -> Result<DNodePhys, ZfsError> {
        let dnode_per_block = dnode.header.datablkszsec as u64; // dnodes are 512 bytes so this just works
        let block_id = dnode_id / dnode_per_block;
        let dnode_id = dnode_id % dnode_per_block;
        let block = self.read_block(dnode, block_id)?;
        let input = &block.as_ref()[dnode_id as usize * 512..];
        let (_input, dnode) = DNodePhys::parse(&input)?;
        Ok(dnode)
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
                        return Err(ZfsErrorKind::Invalid.into());
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
            ZapBlock::FatLeaf(_) => Err(ZfsErrorKind::Invalid.into()),
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
                let mut block_list: Vec<u64> = if zap_header.ptrtbl.blk == 0 {
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
                block_list.sort_unstable();
                block_list.dedup();
                let mut out = vec![];
                for blocknum in block_list {
                    let input = self.read_block(zap_dnode, blocknum)?;
                    let (input, leaf_block) = ZapLeafPhys::parse(input.as_ref(), block_size)?;
                    out.extend(leaf_block.get_entries())
                }
                Ok(out)
            }
            ZapBlock::FatLeaf(_) => Err(ZfsErrorKind::Invalid.into()),
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
            let idx = get_level_index(block_id, level - 1, level_shift);
            let (_input, block_pointer) = BlockPtr::parse(&block.as_ref()[idx as usize * 128..])?;
            self.lookup_block(
                &block_pointer,
                block_id,
                level - 1,
                level_shift,
                data_block_size,
            )
        } else {
            Ok(block)
        }
    }
}

// TODO: implement boot_header and nv_pairs parsing
#[derive(Debug, Clone)]
pub struct Label {
    pub boot_header: Vec<u8>,
    pub nv_pairs: Vec<u8>,
    pub uberblocks: Vec<Uberblock>,
}

impl Label {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (_pad, boot_header, nv_pairs, uberblocks)) = nom::sequence::tuple((
            nom::bytes::complete::take(8 * 1024usize),
            nom::bytes::complete::take(8 * 1024usize),
            nom::bytes::complete::take(112 * 1024usize),
            nom::bytes::complete::take(128 * 1024usize),
        ))(input)?;
        let asize = 12; // TODO: read this from nv_pairs
        let uberblock_count = 1 << (17 - asize.max(10));
        let uberblock_size = 1 << asize.max(10);
        let (_, uberblocks) = nom::multi::count(
            |i| Uberblock::parse(i, uberblock_size),
            uberblock_count,
        )(uberblocks)?;
        Ok((
            input,
            Self {
                boot_header: boot_header.to_vec(),
                nv_pairs: nv_pairs.to_vec(),
                uberblocks,
            },
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Uberblock {
    pub magic: u64,
    pub version: u64,
    pub txg: u64,
    pub guid_sum: u64,
    pub timestamp: u64,
    pub rootbp: BlockPtr,
    pub software_version: u64,
    pub mmp_magic: u64,
    pub mmp_delay: u64,
    pub mmp_config: u64,
    pub checkpoint_txg: u64,
}

impl Uberblock {
    pub fn parse(input: &[u8], size: usize) -> IResult<&[u8], Self> {
        let (input, block) = nom::bytes::complete::take(size)(input)?;
        let (
            block,
            (
                magic,
                version,
                txg,
                guid_sum,
                timestamp,
                rootbp,
                software_version,
                mmp_magic,
                mmp_delay,
                mmp_config,
                checkpoint_txg,
            ),
        ) = nom::sequence::tuple((
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            BlockPtr::parse,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
            number::le_u64,
        ))(block)?;
        Ok((
            input,
            Self {
                magic,
                version,
                txg,
                guid_sum,
                timestamp,
                rootbp,
                software_version,
                mmp_magic,
                mmp_delay,
                mmp_config,
                checkpoint_txg,
            },
        ))
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
        let (input, offset_gang) = number::le_u64(input)?;
        let gang = offset_gang & (1 << 63);
        let offset = offset_gang & ((1 << 63) - 1);
        //let (input, (offset, gang)): (_, (u64, u8)) =
        //    bits!(input, tuple!(take_bits!(63usize), take_bits!(1usize)))?;
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

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Checksum {
    pub checksum: [u64; 4],
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
#[derive(Debug, Clone, TryFrom, Eq, PartialEq)]
pub enum CompressionType {
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
#[derive(Debug, Clone, TryFrom, Eq, PartialEq)]
pub enum ChecksumType {
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

#[derive(Debug, Clone)]
pub struct BlockPtr {
    pub embedded: BlockPtrKind,
    pub byteorder: bool,
    pub dedup: bool,
    pub encryption: bool,
    pub kind: u8,
    pub compression_type: CompressionType,
    pub embedded_data: bool,
    pub indirection_level: u8,
    pub physical_size: u16,
    pub logical_size: u16,
    pub logical_transaction: u64,
}

#[derive(Debug, Clone)]
pub struct BlockPtrPtr {
    pub addresses: [DVA; 3],
    pub physical_transaction: u64,
    pub checksum_type: ChecksumType,
    pub fill_count: u64,
    pub checksum: Checksum,
}

#[derive(Debug, Clone)]
pub enum BlockPtrKind {
    Ptr(BlockPtrPtr),
    Data(Vec<u8>),
}

impl BlockPtr {
    pub fn from_raw(bytes: &[u8]) -> Self {
        assert!(bytes.len() == 128);
        Self::parse(bytes).unwrap().1
    }
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        use nom::{bits, map_res, take_bits, tuple};
        let (input, (_pad, flags)) = nom::combinator::peek(nom::sequence::tuple((
            nom::bytes::complete::take(6 * 8usize),
            number::le_u64,
        )))(input)?;
        let embedded_data = (flags & (1 << 39)) != 0;
        if embedded_data {
            let (input, data0) = nom::bytes::complete::take(6 * 8usize)(input)?;
            let (input, (logical_size, physical_size)) =
                nom::sequence::tuple((number::le_u24, number::le_u8))(input)?;
            let (input, compression_type_embedded) = number::le_u8(input)?;
            let embedded_data = compression_type_embedded & (1 << 7);
            let compression_type =
                CompressionType::try_from(compression_type_embedded & ((1 << 7) - 1)).unwrap();
            let embedded_data = embedded_data != 0;
            let (input, (embedded_type, kind)) =
                nom::sequence::tuple((number::le_u8, number::le_u8))(input)?;
            let (input, level_flags) = number::le_u8(input)?;
            let indirection_level = level_flags & ((1 << 5) - 1);
            let encryption = level_flags & (1 << 5) != 0;
            let dedup = level_flags & (1 << 6) != 0;
            let byteorder = level_flags & (1 << 7) != 0;
            //let (input, (indirection_level, encryption, dedup, byteorder)): (_, (_, u8, u8, u8)) =
            //    bits!(
            //        input,
            //        tuple!(
            //            take_bits!(5usize),
            //            take_bits!(1usize),
            //            take_bits!(1usize),
            //            take_bits!(1usize)
            //        )
            //    )?;
            let (input, (data1, logical_transaction, data2)) = nom::sequence::tuple((
                nom::bytes::complete::take(3 * 8usize),
                number::le_u64,
                nom::bytes::complete::take(5 * 8usize),
            ))(input)?;

            let mut data = Vec::with_capacity(data0.len() + data1.len() + data2.len());
            data.extend(data0);
            data.extend(data1);
            data.extend(data2);

            let embedded = BlockPtrKind::Data(data);
            Ok((
                input,
                Self {
                    embedded,
                    byteorder,
                    dedup,
                    encryption,
                    kind,
                    compression_type,
                    embedded_data,
                    indirection_level,
                    physical_size: physical_size as u16 / 512,
                    logical_size: logical_size as u16 / 512,
                    logical_transaction,
                },
            ))
        } else {
            let (input, (a1, a2, a3)) =
                nom::sequence::tuple((DVA::parse, DVA::parse, DVA::parse))(input)?;
            let addresses = [a1, a2, a3];
            let (input, (logical_size, physical_size)) =
                nom::sequence::tuple((number::le_u16, number::le_u16))(input)?;
            let (input, compression_type_embedded) = number::le_u8(input)?;
            let embedded_data = compression_type_embedded & (1 << 7);
            let compression_type =
                CompressionType::try_from(compression_type_embedded & ((1 << 7) - 1)).unwrap();
            let embedded_data = embedded_data != 0;
            let (input, (checksum_type, kind)) =
                nom::sequence::tuple((ChecksumType::parse, number::le_u8))(input)?;
            let (input, level_flags) = number::le_u8(input)?;

            let indirection_level = level_flags & ((1 << 5) - 1);
            let encryption = level_flags & (1 << 5) != 0;
            let dedup = level_flags & (1 << 6) != 0;
            let byteorder = level_flags & (1 << 7) != 0;

            //let (input, (indirection_level, encryption, dedup, byteorder)): (_, (_, u8, u8, u8)) =
            //    bits!(
            //        input,
            //        tuple!(
            //            take_bits!(5usize),
            //            take_bits!(1usize),
            //            take_bits!(1usize),
            //            take_bits!(1usize)
            //        )
            //    )?;

            //let encryption = encryption != 0;
            //let dedup = dedup != 0;
            //let byteorder = byteorder != 0;
            let (input, (_pad, physical_transaction, logical_transaction, fill_count)) =
                nom::sequence::tuple((
                    nom::bytes::complete::take(16usize),
                    number::le_u64,
                    number::le_u64,
                    number::le_u64,
                ))(input)?;
            let (input, checksum) = Checksum::parse(input)?;
            let embedded = BlockPtrKind::Ptr(BlockPtrPtr {
                addresses,
                physical_transaction,
                checksum_type,
                fill_count,
                checksum,
            });
            Ok((
                input,
                Self {
                    embedded,
                    byteorder,
                    dedup,
                    encryption,
                    kind,
                    compression_type,
                    embedded_data,
                    indirection_level,
                    physical_size,
                    logical_size,
                    logical_transaction,
                },
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZioGbh {
    pub blkptr: [BlockPtr; 3],
    pub tail: ZioBlockTail,
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

#[derive(Debug, Clone)]
pub struct ZioBlockTail {
    pub magic: u64,
    pub checksum: Checksum,
}

impl ZioBlockTail {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (magic, checksum)) =
            nom::sequence::tuple((number::le_u64, Checksum::parse))(input)?;
        Ok((input, Self { magic, checksum }))
    }
}

#[derive(Debug, Clone)]
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
        let (input, _pad) = nom::bytes::complete::take(4 * 8usize)(input)?;
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

#[derive(Debug, Clone)]
pub struct DNodePhys {
    pub header: DNodePhysHeader,
    pub block_pointers: Vec<BlockPtr>,
    pub bonus: Vec<u8>,
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

#[derive(Debug, Clone)]
pub struct ObjsetPhys {
    pub metadnode: DNodePhys,
    pub os_zil_header: ZilHeader,
    pub os_type: OsType,
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

#[derive(Debug, Clone)]
pub struct ZilHeader {
    pub claim_txg: u64,
    pub replay_seq: u64,
    pub log: BlockPtr,
    pub claim_block_seq: u64,
    pub flags: u64,
    pub claim_lr_seq: u64,
}

impl ZilHeader {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (claim_txg, replay_seq, log, claim_block_seq, flags, claim_lr_seq, _pad)) =
            nom::sequence::tuple((
                number::le_u64,
                number::le_u64,
                BlockPtr::parse,
                number::le_u64,
                number::le_u64,
                number::le_u64,
                nom::bytes::complete::take(3 * 8usize),
            ))(input)?;
        Ok((
            input,
            Self {
                claim_txg,
                replay_seq,
                log,
                claim_block_seq,
                flags,
                claim_lr_seq,
            },
        ))
    }
}

#[derive(Debug, Clone, TryFrom)]
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

#[derive(Debug, Clone)]
pub struct DatasetPhys {
    pub dir_obj: u64,
    pub prev_snap_obj: u64,
    pub prev_snap_obj_transaction: u64,
    pub next_snap_obj: u64,
    pub snapnames_zapobj: u64,
    pub num_children: u64,
    pub creation_time: u64,
    pub creation_txg: u64,
    pub deadlist_obj: u64,
    pub referenced_bytes: u64,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub unique_bytes: u64,
    pub fsid_guid: u64,
    pub guid: u64,
    pub flags: u64,
    pub bp: BlockPtr,
    pub next_clones_obj: u64,
    pub props_obj: u64,
    pub userrefs_obj: u64,
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

#[derive(Debug, Clone)]
pub struct DirPhys {
    pub creation_time: u64,
    pub head_dataset_obj: u64,
    pub parent_obj: u64,
    pub clone_parent_obj: u64,
    pub clone_dir_zapobj: u64,
    pub used_bytes: u64,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub quota: u64,
    pub reserved: u64,
    pub props_zapobj: u64,
    pub deleg_zapobj: u64,
    pub flags: u64,
    pub used_breakdown: [u64; 5],
    pub clones: u64,
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
            nom::bytes::complete::take(256usize),
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

#[derive(Debug, Clone)]
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
    pub fn lookup(&self, key: &[u8]) -> Option<u64> {
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

//const ZAP_LEAF_HASH_NUMENTRIES: usize = 4096;
//const ZAP_LEAF_NUMCHUNKS: usize = 0; // TODO find correct value
const ZAP_LEAF_ARRAY_BYTES: usize = 24 - 3;

const fn ZAP_LEAF_HASH_NUMENTRIES(block_size: usize) -> usize {
    block_size / 32
}

const fn ZAP_LEAF_NUMCHUNKS(block_size: usize) -> usize {
    ((block_size - (2 * ZAP_LEAF_HASH_NUMENTRIES(block_size))) / 24) - 2
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
            nom::multi::count(number::le_u16, ZAP_LEAF_HASH_NUMENTRIES(block_size))(input)?;
        let (input, chunks) =
            nom::multi::count(ZapLeafChunk::parse, ZAP_LEAF_NUMCHUNKS(block_size))(input)?;
        Ok((input, Self { hdr, hash, chunks }))
    }
    pub fn lookup(&self, key: &[u8], hash: u64, leaf_block_shift: u32) -> Option<ZapResult> {
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
    pub fn get_entries(&self) -> Vec<(CString, ZapResult)> {
        self.chunks
            .iter()
            .filter_map(ZapLeafChunk::entry_ref)
            .filter_map(|entry| {
                // exclude the terminating null
                let name =
                    CString::new(self.get_array(entry.name_chunk, entry.name_length as usize - 1)?)
                        .ok()?;
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

#[derive(Debug, Clone)]
pub struct ZNodePhys {
    pub atime: [u64; 2],
    pub mtime: [u64; 2],
    pub ctime: [u64; 2],
    pub crtime: [u64; 2],
    pub gen: u64,
    pub mode: u64,
    pub parent: u64,
    pub links: u64,
    pub xattr: u64,
    pub rdev: u64,
    pub flags: u64,
    pub uid: u64,
    pub gid: u64,
    pub acl: ZNodeAcl,
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

#[derive(Debug, Clone)]
pub struct ZNodeAcl {
    pub extern_obj: u64,
    pub count: u32,
    pub version: u16,
    pub ace_data: [Ace; ACE_SLOT_CNT],
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
    pub who: u64,
    pub access_mask: u32,
    pub flags: u16,
    pub kind: u16,
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

#[derive(Debug, Clone)]
pub struct ZilTrailer {
    pub next_blk: BlockPtr,
    pub nused: u64,
    pub bt: ZioBlockTail,
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

#[derive(Debug, Clone)]
pub struct ZilLogRecord {
    pub txtype: u64,
    pub reclen: u64,
    pub txg: u64,
    pub seq: u64,
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
