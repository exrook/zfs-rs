use std::fs::File;
use std::path::Path;
use std::os::unix::fs::FileExt;
use std::convert::TryInto;
use std::fmt;

use nom::{IResult, number::complete as number};

pub struct Device {
    file: File
}

impl Device {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let f = File::open(path).unwrap();
        Self {
            file: f
        }
    }
    pub fn read(&self, address: u64, len: u64) -> Vec<u8> {
        let mut buf = vec![0; len as usize];
        self.file.read_exact_at(&mut buf, address);
        buf
    }
}

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
            .field("offset", &format!("{:x}",self.offset<<9))
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
        use nom::{bits, tuple, take_bits};
        let (input, (asize, grid, vdev)) = nom::sequence::tuple((number::le_u24, number::le_u8, number::le_u32))(input)?;
        let (input, (offset, gang)): (_,(u64, u8)) = bits!(input, tuple!(take_bits!(63usize), take_bits!(1usize)))?;
        let gang = if gang == 0 { false } else { true };
        Ok((input, Self {
            vdev,
            grid,
            asize,
            offset,
            gang
        }))
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
    checksum_type: u8,
    compression_type: u8,
    embedded_data: bool,
    physical_size: u16,
    logical_size: u16,
    physical_transaction: u64,
    logical_transaction: u64,
    fill_count: u64,
    checksum: [u64; 4]
}

impl BlockPtr {
    pub fn from_raw(bytes: &[u8]) -> Self {
        assert!(bytes.len() == 128);
        Self::parse(bytes).unwrap().1
    }
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        use nom::{bits, tuple, take_bits};
        let (input, (a1, a2, a3)) = nom::sequence::tuple((DVA::parse, DVA::parse, DVA::parse))(input)?;
        let addresses = [a1, a2, a3];
        let (input, (logical_size, physical_size)) = nom::sequence::tuple((number::le_u16, number::le_u16))(input)?;
        let (input, (compression_type, embedded_data)): (_,(_, u8)) = bits!(input, tuple!(take_bits!(7usize), take_bits!(1usize)))?;
        let embedded_data = embedded_data != 0;
        let (input, (checksum_type, kind)) = nom::sequence::tuple((number::le_u8, number::le_u8))(input)?;
        let (input, (indirection_level, encryption, dedup, byteorder)): (_, (_, u8, u8, u8)) = bits!(input, tuple!(take_bits!(5usize), take_bits!(1usize), take_bits!(1usize), take_bits!(1usize)))?;
        let encryption = encryption != 0;
        let dedup = dedup != 0;
        let byteorder = byteorder != 0;
        let (input, (_pad, physical_transaction, logical_transaction, fill_count)) =  nom::sequence::tuple((nom::bytes::complete::take(16usize), number::le_u64, number::le_u64, number::le_u64))(input)?;
        let (input, (c1, c2, c3, c4)) = nom::sequence::tuple((number::le_u64, number::le_u64, number::le_u64, number::le_u64))(input)?;
        let checksum = [c1, c2, c3 ,c4];
        Ok((input, Self {
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
            checksum
        }))
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
    pub sec_phys: u64
}

impl DNodePhysHeader {
    pub fn from_raw(bytes: &[u8]) -> Self {
        assert!(bytes.len() == 64);
        Self::parse(bytes).unwrap().1
    }
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (kind, indirect_block_shift, levels, num_block_ptr, bonus_type, checksum, compress)) = nom::sequence::tuple((number::le_u8,number::le_u8,number::le_u8,number::le_u8,number::le_u8,number::le_u8, number::le_u8))(input)?;
        let (input, _pad) = nom::bytes::complete::take(1usize)(input)?;
        let (input, (datablkszsec, bonus_len)) = nom::sequence::tuple((number::le_u16, number::le_u16))(input)?;
        let (input, _pad) = nom::bytes::complete::take(4usize)(input)?;
        let (input, (max_block_id, sec_phys)) = nom::sequence::tuple((number::le_u64, number::le_u64))(input)?;
        Ok((input, Self {
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
            sec_phys
        }))
    }
}

#[derive(Debug)]
pub struct DNodePhys {
    header: DNodePhysHeader,
    block_pointers: Vec<BlockPtr>,
    bonus: Vec<u8>
}

impl DNodePhys {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = DNodePhysHeader::parse(input)?;
        let (input, block_pointers) = nom::multi::count(BlockPtr::parse, header.num_block_ptr as usize)(input)?;
        let (input, bonus) = nom::bytes::complete::take(header.bonus_len as usize)(input)?;
        Ok((input, Self {
            header,
            block_pointers,
            bonus: bonus.to_vec()
        }))
    }
}
