//!
//! Datastructures used by the ZFS Posix Layer
//!
use std::convert::TryInto;

use nom::{number::complete as number, IResult};

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
