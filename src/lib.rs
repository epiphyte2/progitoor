// Copyright 2021 Edwin Peer and Simeon Miteff

extern crate time;

pub mod metadata {
    use std::collections::HashMap;
    use std::ffi::{OsStr, OsString};
    use time::Timespec;

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct FileInfo {
        pub time: Timespec,
        pub perm: u16,
        pub uid: u32,
        pub gid: u32,
    }

    pub struct Store {
        map: HashMap<OsString, FileInfo>,
    }

    impl Store {
        pub fn new() -> Store {
            Store {
                map: HashMap::new(),
            }
        }

        pub fn get(&self, name: &OsStr) -> Option<&FileInfo> {
            return self.map.get(&*name.to_os_string());
        }

        pub fn set(&mut self, name: &OsStr, info: FileInfo) {
            *self.map.entry(name.to_os_string()).or_insert(info) = info;
        }

        pub fn remove(&mut self, name: &OsStr) {
            self.map.remove(name);
        }

        // fn flush(&mut self) {
        //
        // }
        //
        // fn drop(&mut self) {
        //
        // }
    }
}

#[cfg(test)]
mod test {
    use super::metadata::{FileInfo, Store};
    use std::ffi::OsStr;
    use time::Timespec;

    #[test]
    fn basic_metadata_test() {
        let f1 = FileInfo {
            time: Timespec { sec: 1, nsec: 1 },
            perm: 1,
            uid: 1,
            gid: 1,
        };
        let f2 = FileInfo {
            time: Timespec { sec: 2, nsec: 2 },
            perm: 2,
            uid: 2,
            gid: 2,
        };

        let mut s = Store::new();

        assert!(s.get(OsStr::new("/non-existent")).is_none());

        s.set(OsStr::new("/f1"), f1);
        s.set(OsStr::new("/f2"), f2);

        let gf1 = s.get(OsStr::new("/f1")).unwrap();
        let gf2 = s.get(OsStr::new("/f2")).unwrap();

        assert_eq!(f1, *gf1);
        assert_eq!(f2, *gf2);

        s.remove(OsStr::new("/f1"));

        assert!(s.get(OsStr::new("/f1")).is_none());
    }
}
