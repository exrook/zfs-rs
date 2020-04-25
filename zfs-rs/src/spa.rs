use std::convert::TryFrom;
use std::fmt;

use nom::{number::complete as number, IResult};

use enum_repr_derive::TryFrom;

use crate::fletcher::{Fletcher2, Fletcher4};

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
            _block,
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
    pub vdev: u32,
    pub grid: u8,
    pub asize: u32,
    pub offset: u64,
    pub gang: bool,
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
    Data { embedded_type: u8, data: Vec<u8> },
}

impl BlockPtr {
    pub fn from_raw(bytes: &[u8]) -> Self {
        assert!(bytes.len() == 128);
        Self::parse(bytes).unwrap().1
    }
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
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

            let embedded = BlockPtrKind::Data {
                embedded_type,
                data,
            };
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
