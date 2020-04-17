use std::fs::File;
use std::path::Path;
use std::os::unix::fs::FileExt;
use std::convert::TryFrom;
use std::fmt;

use nom::{IResult, number::complete as number};

use enum_repr_derive::TryFrom;

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
        nom::combinator::map_parser(nom::bytes::complete::take(512usize), |input| {
            let (input, header) = DNodePhysHeader::parse(input)?;
            let (input, block_pointers) = nom::multi::count(BlockPtr::parse, header.num_block_ptr as usize)(input)?;
            let (input, bonus) = nom::bytes::complete::take(header.bonus_len as usize)(input)?;
            Ok((input, Self {
                header,
                block_pointers,
                bonus: bonus.to_vec()
            }))
        })(input)
    }
}

#[derive(Debug)]
pub struct ObjsetPhys {
    metadnode: DNodePhys,
    os_zil_header: ZilHeader,
    os_type: OsType
}

impl ObjsetPhys {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (metadnode, os_zil_header, os_type)) = nom::combinator::map_parser(nom::bytes::complete::take(1024usize), nom::sequence::tuple((DNodePhys::parse, ZilHeader::parse, OsType::parse)))(input)?;
        Ok((input, Self {
            metadnode,
            os_zil_header,
            os_type
        }))
    }
}

#[derive(Debug)]
pub struct ZilHeader {
    claim_txg: u64,
    replay_seq: u64,
    log: BlockPtr
}

impl ZilHeader {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (claim_txg, replay_seq, log)) = nom::sequence::tuple((number::le_u64, number::le_u64, BlockPtr::parse))(input)?;
        Ok((input, Self {
            claim_txg,
            replay_seq,
            log
        }))
    }
}

#[derive(Debug, TryFrom)]
#[repr(u64)]
pub enum OsType {
    NONE = 0,
    META = 1,
    ZFS = 2,
    ZVOL = 3
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
        let (input, (dir_obj, prev_snap_obj, prev_snap_obj_transaction, next_snap_obj, snapnames_zapobj, num_children, creation_time, creation_txg, deadlist_obj, referenced_bytes, compressed_bytes, uncompressed_bytes, unique_bytes, fsid_guid, guid, flags, bp, next_clones_obj, props_obj, userrefs_obj)) =  nom::combinator::map_parser(nom::bytes::complete::take(320usize), nom::sequence::tuple((number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, BlockPtr::parse, number::le_u64, number::le_u64, number::le_u64)))(input)?;
        Ok((input, Self {
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
        }))
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
    clones: u64
}

impl DirPhys {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (creation_time, head_dataset_obj, parent_obj, clone_parent_obj, clone_dir_zapobj, used_bytes, compressed_bytes, uncompressed_bytes, quota, reserved, props_zapobj, deleg_zapobj, flags, b1, b2, b3, b4, b5, clones)) = nom::combinator::map_parser(nom::bytes::complete::take(320usize), nom::sequence::tuple((number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64, number::le_u64)))(input)?;
        Ok((input, Self {
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
            clones
        }))
    }
}
