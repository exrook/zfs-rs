use std::env::args_os;
use std::path::{Component, Path, PathBuf};
use zfs_rs::{
    dmu::ObjsetPhys,
    dsl::DirPhys,
    zap::{ZapResult, ZapString},
    zpl::{DirEntry, DirEntryType},
};
use zfs_rs::{Device, Disk, ZfsError, ZfsErrorKind, DMU, DSL, SPA, ZAP, ZPL};

fn main() {
    let path = args_os().nth(1).expect("First argument is required");
    let zfs_dataset_path = PathBuf::from(args_os().nth(2).unwrap_or("/".into()));
    let zfs_fs_path = args_os().nth(3).map(PathBuf::from);
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
        //
        //
        let entry: Result<_, ZfsError> = (|| {
            let dir = disk.get_dnode(&objset, 1)?;
            //let mos_config = disk.list_zap(&dir)?;
            //println!("CONFIG {:?}", mos_config);
            match disk
                .lookup_zap(&dir, &ZapString::from_byte_slice(b"root_dataset").unwrap())?
                .ok_or(ZfsErrorKind::NotFound)?
            {
                ZapResult::U64(a) => Ok(a[0]),
                r => panic!("Wrong ZapResult kind: {:?}", r),
            }
        })();
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                println!("Error reading MOS ZAP object, searching for root dataset");
                let mut entry = None;
                for i in 0..(objset.metadnode.header.max_block_id
                    * objset.metadnode.header.datablkszsec as u64)
                {
                    if let Ok(dnode) = disk.get_dnode(&objset, i) {
                        if dnode.header.kind == 12 {
                            if let Ok((_, dir)) = DirPhys::parse(&dnode.bonus) {
                                if dir.parent_obj == 0 {
                                    println!("Found root dataset with object id {}", i);
                                    entry = Some(i);
                                    break;
                                }
                            }
                        }
                    }
                }
                entry.unwrap()
            }
        };

        let obj_dir = find_obj_dir(&disk, &objset, entry, &zfs_dataset_path)
            .unwrap()
            .unwrap();

        match &zfs_fs_path {
            &Some(ref zfs_fs_path) => {
                let dataset = disk.get_dataset(&objset, obj_dir.head_dataset_obj).unwrap();
                let zpl_objset = disk.get_objset(&dataset.bp).unwrap();
                let master_node = disk.get_dnode(&zpl_objset, 1).unwrap();
                let root_dir_num = match disk
                    .lookup_zap(&master_node, &ZapString::from_byte_slice(b"ROOT").unwrap())
                    .unwrap()
                    .unwrap()
                {
                    ZapResult::U64(a) if a.len() == 1 => a[0],
                    r => panic!("Wrong ZapResult kind: {:?}", r),
                };
                let dirent = match zfs_fs_path.components().next_back() {
                    Some(Component::RootDir) | Some(Component::CurDir) => {
                        DirEntry::new(DirEntryType::Directory, root_dir_num)
                    }
                    _ => {
                        let mut rest = zfs_fs_path.components();
                        let prefix = rest.next();
                        let path = match prefix {
                            Some(Component::RootDir) | Some(Component::CurDir) => rest.as_path(),
                            _ => zfs_fs_path,
                        };

                        find_dirent(&disk, &zpl_objset, root_dir_num, path)
                            .unwrap()
                            .unwrap()
                    }
                };
                match dirent.get_type() {
                    DirEntryType::Directory => println!(
                        "Drectory listing: {:?}",
                        disk.list_dir_entries(&zpl_objset, dirent.get_objnum())
                    ),
                    ty => println!("Type {:?}", ty),
                };
            }
            None => {
                let child_dir = disk.get_dnode(&objset, obj_dir.child_dir_zapobj).unwrap();
                let listing = disk.list_zap(&child_dir).unwrap();
                println!("Object Directory listing: {:?}", listing);
            }
        };
    }
}

fn find_obj_dir<P: AsRef<Path>>(
    disk: &Disk,
    dsl_objset: &ObjsetPhys,
    root_dsl_dir: u64,
    path: P,
) -> Result<Option<DirPhys>, ZfsError> {
    let root_dsl_dir = disk.get_dir(dsl_objset, root_dsl_dir)?;
    let children = disk.get_dnode(dsl_objset, root_dsl_dir.child_dir_zapobj)?;
    let mut components = path.as_ref().components();
    let prefix = match components.next() {
        None | Some(Component::RootDir) => return Ok(Some(root_dsl_dir)),
        Some(s) => s,
    };
    let rest = components.as_path();
    let child = match disk.lookup_zap(
        &children,
        &ZapString::from_byte_slice(
            prefix
                .as_os_str()
                .to_str()
                .expect("Use unicode or perish, fool")
                .as_bytes(),
        )
        .unwrap(),
    )? {
        Some(ZapResult::U64(u)) if u.len() == 1 => u[0],
        _ => return Ok(None),
    };
    find_obj_dir(disk, dsl_objset, child, rest)
}

fn find_dirent<P: AsRef<Path>>(
    disk: &Disk,
    zpl_objset: &ObjsetPhys,
    root_dir: u64,
    path: P,
) -> Result<Option<DirEntry>, ZfsError> {
    let mut components = path.as_ref().components();
    let prefix = match components.next() {
        Some(s) => s,
        None => return Ok(None),
    };
    let rest = components.as_path();
    let entry = match disk.lookup_dir_entry(
        zpl_objset,
        root_dir,
        &ZapString::from_byte_slice(
            prefix
                .as_os_str()
                .to_str()
                .expect("Unicode gang ONLY")
                .as_bytes(),
        )
        .unwrap(),
    )? {
        Some(e) => e,
        None => return Ok(None),
    };
    if rest.as_os_str().len() == 0 {
        return Ok(Some(entry));
    } else {
        find_dirent(disk, zpl_objset, entry.get_objnum(), rest)
    }
}
