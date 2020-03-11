#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

use std::env::args_os;
use std::fmt::Write;
use std::num::ParseIntError;
use std::convert::TryInto;

use rocket::{State, Request, Outcome};
use rocket::request::FromParam;
use rocket::http::{Status,RawStr};

mod zfs;

use zfs::Device;

fn main() {
    println!("Hello, world!");
    let dev = Device::new(args_os().nth(1).expect("An argument is required"));
    rocket::ignite().manage(dev).mount("/", routes![block_compressed, block]).launch();
}

struct NumFromHex(pub u64);

impl<'a> FromParam<'a> for NumFromHex {
    type Error = ParseIntError;
    fn from_param(param: &'a RawStr) -> Result<Self, Self::Error> {
        u64::from_str_radix(param.as_str(), 16).map(Self)
    }
}

#[get("/block/<vdev>/<id>/<asize>?<view>")]
fn block(dev: State<Device>, vdev: u32, id: NumFromHex, asize: u32, view: Option<String>) -> String {
    let address = id.0 + 0x400000;
    let mut output = String::new();
    match view.as_deref() {
        None => {

        }
        Some("d") => {
            let data = dev.read(address, 64);
            let address = address + 64;
            let dnode = zfs::DNodePhysHeader::from_raw(&data);
            writeln!(output, "{:#?}", dnode);
            for i in (0..dnode.num_block_ptr as u64) {
                let data = dev.read(address + i*128, 128);
                let blockptr = zfs::BlockPtr::from_raw(&data);
                writeln!(output, "{:#?}", blockptr);
            }
        }
        Some("b") => {
            let data = dev.read(address, 128);
            let blockptr = zfs::BlockPtr::from_raw(&data);
            write!(output, "{:?}", blockptr);
        }
        _ => {}
    }
    output
}
#[get("/block/<vdev>/<id>/<asize>?<view>&compress&<phys_size>&<logical_size>")]
fn block_compressed(dev: State<Device>, vdev: u32, id: NumFromHex, asize: u32, view: Option<String>, phys_size: u32, logical_size: u32) -> String {
    let address = id.0 + 0x400000;
    let compressed_data = dev.read(address, phys_size as u64 * 512);
    let size = u32::from_be_bytes(compressed_data[0..4].try_into().unwrap());
    let compressed_data = &compressed_data[4..size as usize + 4];
    assert_eq!(compressed_data.len(), size as usize);
    let data = lz4_compression::decompress::decompress(&compressed_data).unwrap();
    let mut output = String::new();
    match view.as_deref() {
        None => {

        }
        Some("d") => {
            let dnode = zfs::DNodePhysHeader::from_raw(&data[0..64]);
            writeln!(output, "{:#?}", dnode);
            for i in (0..dnode.num_block_ptr as usize) {
                let blockptr = zfs::BlockPtr::from_raw(&data[(64 + i*128)..(64 + 128 + i*128)]);
                writeln!(output, "{:#?}", blockptr);
            }
            if dnode.bonus_len > 0 {
                let bonus_start = 64 + dnode.num_block_ptr as usize * 128;
                let bonus = &data[bonus_start..bonus_start + dnode.bonus_len as usize];
                writeln!(output, "{:?}", bonus);
            }
        }
        Some("b") => {
            let blockptr = zfs::BlockPtr::from_raw(&data[0..128]);
            write!(output, "{:?}", blockptr);
        }
        Some("r") => {
            write!(output, "{:?}", data);
        }
        _ => {}
    }
    output
}
