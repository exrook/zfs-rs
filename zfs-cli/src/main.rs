use std::env::args_os;
use zfs_rs::{DNodePhys, ObjsetPhys};
use zfs_rs::{Device, Disk, ZFS};

fn main() {
    let path = args_os().nth(1).expect("First argument is required");
    let disk = Disk::new(path).expect("Unable to open disk");
    let label = disk.get_label(0).unwrap();
    let mut uber = label.uberblocks;
    uber.sort_unstable_by_key(|u| u.txg);
    for u in uber.iter().rev().take(1) {
        //u.rootbp.indirection_level = 0;
        //println!("{:#?}", u);
        let block = disk.get(&u.rootbp).unwrap();
        let (_input, objset) = ObjsetPhys::parse(block.as_ref()).unwrap();
        //println!("objset: {:?}", objset);
        let dir = disk.read_dnode(&objset.metadnode, 1).unwrap();
        //println!("{}: {:?}", dir.as_ref().len(), dir.as_ref());
        println!("yeet: {:?}", dir);
        let mos_config = disk.zap_entries(&dir).unwrap();
        println!("CONFIG {:?}", mos_config);
    }
    println!("Hello, world!");
}
