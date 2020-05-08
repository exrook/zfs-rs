use std::env::args_os;
use std::path::{Component, PathBuf};
use zfs_rs::{dsl::DirPhys, zap::ZapString};
use zfs_rs::{Device, Disk, ZfsDirEntry, ZfsDrive, ZfsDslDir, ZfsError, ZfsErrorKind};

fn main() {
    let path = args_os().nth(1).expect("First argument is required");
    let zfs_dataset_path = PathBuf::from(args_os().nth(2).unwrap_or("/".into()));
    let zfs_fs_path = args_os().nth(3).map(PathBuf::from);
    let disk = Disk::new(path).expect("Unable to open disk");
    let label = disk.get_label(0).unwrap().unwrap();
    let mut uber = label.uberblocks;
    uber.sort_unstable_by_key(|u| u.txg);
    let drive = ZfsDrive::new(disk).unwrap();
    for u in uber.iter().rev().take(1) {
        //u.rootbp.indirection_level = 0;
        //println!("{:#?}", u);
        let meta_objset = drive.get_object_set(&u.rootbp).unwrap().as_mos().unwrap();
        //println!("objset: {:?}", objset);
        //
        //
        let obj_dir = meta_objset.get_root_dir();
        let obj_dir = match obj_dir {
            Ok(e) => e,
            Err(_) => {
                println!("Error reading MOS ZAP object, searching for root dataset");
                let mut entry = None;
                for i in 0..(meta_objset.as_os().os.metadnode.header.max_block_id
                    * meta_objset.as_os().os.metadnode.header.datablkszsec as u64)
                {
                    if let Ok(dnode) = meta_objset.as_os().get_dnode(i) {
                        if dnode.header.kind == 12 {
                            if let Ok((_, dir)) = DirPhys::parse(&dnode.bonus) {
                                if dir.parent_obj == 0 {
                                    println!("Found root dataset with object id {}", i);
                                    entry = Some(ZfsDslDir::new(&meta_objset, dir));
                                    break;
                                }
                            }
                        }
                    }
                }
                entry.unwrap()
            }
        };

        let obj_dir = zfs_dataset_path
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => {
                    ZapString::from_byte_slice(s.to_str().expect("Unicode gang ONLY").as_bytes())
                }
                _ => None,
            })
            .try_fold::<_, _, Result<_, ZfsError>>(obj_dir, |dir, path| {
                dir.get_child(&path)?.ok_or(ZfsErrorKind::NotFound.into())
            })
            .unwrap();

        match &zfs_fs_path {
            &Some(ref zfs_fs_path) => {
                let dataset = obj_dir.get_head_dataset().unwrap();
                let zpl_objset = dataset.get_object_set().unwrap().as_zpl().unwrap();
                let root_dir = zpl_objset.get_root().unwrap();

                let dir = zfs_fs_path
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(s) => ZapString::from_byte_slice(
                            s.to_str().expect("Unicode gang ONLY").as_bytes(),
                        ),
                        _ => None,
                    })
                    .try_fold::<_, _, Result<_, ZfsError>>(root_dir, |dir, path| {
                        match dir.get_child(&path)?.ok_or(ZfsErrorKind::NotFound)? {
                            ZfsDirEntry::Dir(d) => Ok(d),
                            _ => Err(ZfsErrorKind::NotFound.into()),
                        }
                    })
                    .unwrap();

                print!("Drectory listing: (");
                for (name, e) in dir.children().unwrap() {
                    print!(
                        "{:?}: {},",
                        name,
                        match e {
                            ZfsDirEntry::File(_) => "file",
                            ZfsDirEntry::Dir(_) => "dir",
                        }
                    )
                }
                println!(")");
            }
            None => {
                print!("Drectory listing: (");
                for (name, _e) in obj_dir.children().unwrap() {
                    print!("{:?},", name,)
                }
                println!(")");
            }
        };
    }
}
