use std::env::args_os;
use std::ffi::CString;
use zfs_rs::{dmu::ObjsetPhys, dsl::DatasetPhys, dsl::DirPhys, zap::ZapResult, zpl::ZNodePhys};
use zfs_rs::{Device, Disk, DMU, SPA, ZAP};

fn main() {
    let path = args_os().nth(1).expect("First argument is required");
    let disk = Disk::new(path).expect("Unable to open disk");
    let label = disk.get_label(0).unwrap().unwrap();
    let mut uber = label.uberblocks;
    uber.sort_unstable_by_key(|u| u.txg);
    for u in uber.iter().rev().take(1) {
        //u.rootbp.indirection_level = 0;
        //println!("{:#?}", u);
        let block = disk.get(&u.rootbp).unwrap();
        let (_input, objset) = ObjsetPhys::parse(block.as_ref()).unwrap();
        //println!("objset: {:?}", objset);
        let dir = disk.get_dnode(&objset, 1).unwrap();
        //println!("{}: {:?}", dir.as_ref().len(), dir.as_ref());
        println!("yeet: {:?}", dir);
        let mos_config = disk.list_zap(&dir).unwrap();
        println!("CONFIG {:?}", mos_config);
        let entry = match disk
            .lookup_zap(&dir, &CString::new("root_dataset").unwrap())
            .unwrap()
            .unwrap()
        {
            ZapResult::U64(a) => a[0],
            r => panic!("Wrong ZapResult kind: {:?}", r),
        };
        println!("{:?}", entry);
        let root = disk.get_dnode(&objset, entry).unwrap();
        println!("{:?}", root);
        let dir = DirPhys::parse(&root.bonus).unwrap().1;
        println!("{:#?}", dir);
        let dataset_node = disk.get_dnode(&objset, dir.head_dataset_obj).unwrap();
        let dataset = DatasetPhys::parse(&dataset_node.bonus).unwrap().1;
        println!("{:?}", dataset);
        let block = disk.get(&dataset.bp).unwrap();
        let (_input, zpl_objset) = ObjsetPhys::parse(block.as_ref()).unwrap();
        println!("OBJSET {:?}", zpl_objset);
        let master_node = disk.get_dnode(&zpl_objset, 1).unwrap();
        println!("{:?}", master_node);
        let root_dir_num = match disk
            .lookup_zap(&master_node, &CString::new("ROOT").unwrap())
            .unwrap()
            .unwrap()
        {
            ZapResult::U64(a) if a.len() == 1 => a[0],
            r => panic!("Wrong ZapResult kind: {:?}", r),
        };
        println!("{:?}", root_dir_num);
        let root_dir = disk.get_dnode(&zpl_objset, root_dir_num).unwrap();
        println!("{:?}", root_dir);
        println!("{:?}", disk.list_zap(&root_dir));
        let file_num = match disk
            .lookup_zap(&root_dir, &CString::new("test.txt").unwrap())
            .unwrap()
            .unwrap()
        {
            ZapResult::U64(a) if a.len() == 1 => a[0],
            r => panic!("Wrong ZapResult kind: {:?}", r),
        };
        let file_type = file_num >> 60;
        let file_num = file_num & ((1 << 48) - 1);
        println!("File Type: {}", file_type);
        println!("File Num: {}", file_num);
        let file = disk.get_dnode(&zpl_objset, file_num).unwrap();
        println!("{:?}", file);
        //let znode = ZNodePhys::parse(&file.bonus).unwrap();
        //println!("{:#?}", znode);
        //(0..file.header.max_block_id).iter().flat_map(|i| {
        //    disk.read_block(&file, i).unwrap()
        //})
        let bytes = disk.read_block(&file, 0).unwrap();
        println!(
            "{}",
            CString::new(bytes.as_ref()).unwrap().to_string_lossy()
        );
    }
    println!("Hello, world!");
}
