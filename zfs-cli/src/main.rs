use std::env::args_os;
use zfs_rs::{Device, Disk, ZFS};

fn main() {
    let path = args_os().nth(1).expect("First argument is required");
    let disk = Disk::new(path).expect("Unable to open disk");
    let label = disk.get_label(0).unwrap();
    let mut uber = label.uberblocks;
    uber.sort_unstable_by_key(|u| u.txg);
    let mut u = uber.pop().unwrap();
    u.rootbp.indirection_level = 0;
    println!("{:#?}", u);
    let block = disk.get(&u.rootbp);
    println!("{}", block.unwrap_err());
    //println!("Block pointers: {:#?}", label.uberblocks);
    println!("Hello, world!");
}
