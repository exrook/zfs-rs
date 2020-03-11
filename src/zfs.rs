use std::fs::File;
use std::path::Path;
use std::os::unix::fs::FileExt;
use std::convert::TryInto;
use std::fmt;

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
        let mut asize_bytes: [u8; 4] = bytes[0..4].try_into().unwrap();
        asize_bytes[3] = 0;
        let asize = u32::from_le_bytes(asize_bytes);
        let grid = bytes[3];
        let vdev = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let mut offset = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let gang = (offset & 1<<63) != 0;
        offset &= !(1u64<<63);
        Self {
            vdev,
            grid,
            asize,
            offset,
            gang
        }
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
        Self {
            addresses: [
                DVA::from_raw(&bytes[0..16]),
                DVA::from_raw(&bytes[16..32]),
                DVA::from_raw(&bytes[32..48])
            ],
            logical_size: u16::from_le_bytes(bytes[48..50].try_into().unwrap()),
            physical_size: u16::from_le_bytes(bytes[50..52].try_into().unwrap()),
            compression_type: bytes[52] & !(1u8<<7),
            embedded_data: (bytes[52] & (1u8<<7)) != 0,
            checksum_type: bytes[53],
            kind: bytes[54],
            indirection_level: bytes[55] & 31,
            encryption: (bytes[55] & (1u8<<5)) != 0,
            dedup: (bytes[55] & (1u8<<6)) != 0,
            byteorder: (bytes[55] & (1u8<<7)) != 0,
            physical_transaction: u64::from_le_bytes(bytes[72..80].try_into().unwrap()),
            logical_transaction: u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
            fill_count: u64::from_le_bytes(bytes[88..96].try_into().unwrap()),
            checksum: [
                u64::from_le_bytes(bytes[96..104].try_into().unwrap()),
                u64::from_le_bytes(bytes[104..112].try_into().unwrap()),
                u64::from_le_bytes(bytes[112..120].try_into().unwrap()),
                u64::from_le_bytes(bytes[120..128].try_into().unwrap())
            ]
        }
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
        Self {
            kind: bytes[0],
            indirect_block_shift: bytes[1],
            levels: bytes[2],
            num_block_ptr: bytes[3],
            bonus_type: bytes[4],
            checksum: bytes[5],
            compress: bytes[6],
            datablkszsec: u16::from_le_bytes(bytes[8..10].try_into().unwrap()),
            bonus_len: u16::from_le_bytes(bytes[10..12].try_into().unwrap()),
            max_block_id: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            sec_phys: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        }
    }
}
