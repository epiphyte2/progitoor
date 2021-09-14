// Copyright 2021 Edwin Peer and Simeon Miteff

extern crate time;

pub mod metadata {
    use std::borrow::Borrow;
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::fs::{File, OpenOptions};
    use std::io::prelude::*;
    use std::io::{BufReader, LineWriter};
    use std::path::{Path, PathBuf};
    use thiserror::Error;
    use time::Timespec;

    #[derive(Error, Debug)]
    pub enum MetadataError {
        #[error("Error parsing FileInfo record from string")]
        FileInfoParsingError,

        #[error("Generic error")]
        GenericError,

        #[error(transparent)]
        IOError(#[from] std::io::Error),
        #[error(transparent)]
        ParseIntError(#[from] std::num::ParseIntError),
    }

    /// FileInfo tracks file attributes progitoor is going to remap
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct FileInfo {
        pub time: Timespec,
        pub mode: u16,
        pub uid: u32,
        pub gid: u32,
    }

    /// ZERO_FILE_INFO is used to write tombstones to the journal
    const ZERO_FILE_INFO: FileInfo = FileInfo {
        time: Timespec { sec: 0, nsec: 0 },
        mode: 0,
        uid: 0,
        gid: 0,
    };

    /// FileEntry is a name, info tuple
    pub struct FileEntry {
        pub name: PathBuf,
        pub info: FileInfo,
    }

    /// Serialise a FileEntry to a String
    impl Into<String> for &FileEntry {
        fn into(self) -> String {
            format!(
                "{:04x} {:04x} {:04x} {:09x} {:08x} {}",
                self.info.mode,
                self.info.uid,
                self.info.gid,
                self.info.time.sec,
                self.info.time.nsec,
                self.name.to_str().unwrap(), // FIXME this might be a bad idea
            )
        }
    }

    /// De-serialise a FileEntry from a String
    impl TryFrom<&str> for FileEntry {
        type Error = MetadataError;

        fn try_from(value: &str) -> Result<Self, Self::Error> {
            // DB/Journal file format:
            // ======================
            // <mode> <uid> <gid> <sec> <nsec> <filename>
            //
            // All fields but last are integers are hex lowercase,
            // no 0x prefix, padding to {4, 4, 4, 9, 8} digits each.
            //
            // In the journal, if <mode> is 0000 - it is a tombstone.

            let parts: Vec<&str> = value.splitn(6, " ").collect();
            if parts.len() != 6 {
                return Err(MetadataError::FileInfoParsingError);
            }

            Ok(FileEntry {
                name: parts[5].parse().unwrap(),
                info: FileInfo {
                    mode: u16::from_str_radix(parts[0], 16)?,
                    uid: u32::from_str_radix(parts[1], 16)?,
                    gid: u32::from_str_radix(parts[2], 16)?,
                    time: Timespec {
                        sec: i64::from_str_radix(parts[3], 16)?,
                        nsec: i32::from_str_radix(parts[4], 16)?,
                    },
                },
            })
        }
    }

    /// Store is a file metadata store to support progitoor mapping
    pub struct Store {
        // private stuff forces the use of Store::new() to construct
        map: HashMap<PathBuf, FileInfo>,
        path_db: PathBuf,
        path_journal: PathBuf,
    }

    impl Store {
        /// Construct a new Store instance
        pub fn new(base_dir: &Path) -> Result<Self, MetadataError> {
            if !base_dir.is_dir() {
                // TODO: improve error
                return Err(MetadataError::GenericError);
            }

            // FIXME: move filenames into const at the top of the module
            let mut store = Self {
                map: HashMap::new(),
                path_db: base_dir.join(".progitoor"),
                path_journal: base_dir.join(".progitoor_"),
            };

            Store::load_file(&mut store.map, &store.path_db)?;

            if store.path_journal.exists() {
                Store::load_file(&mut store.map, &store.path_journal)?;
                store.flush(); // write db + delete journal
            }

            // TODO: start thread to periodically call flush()

            Ok(store)
        }

        /// load_file is used for loading both the db and journal
        fn load_file(
            map: &mut HashMap<PathBuf, FileInfo>,
            path: &Path,
        ) -> Result<(), std::io::Error> {
            if path.exists() {
                let file_db = OpenOptions::new().read(true).open(path)?;
                let reader = BufReader::new(file_db);
                for res in reader.lines() {
                    match res {
                        Ok(line) => {
                            if let Ok(parse) = FileEntry::try_from(&*line) {
                                if parse.info.mode == 0 {
                                    // Tombstone value
                                    map.remove(parse.name.as_path());

                                    continue;
                                }

                                map.entry(parse.name.clone())
                                    .and_modify(|v| *v = parse.info)
                                    .or_insert(parse.info);
                            } else {
                                panic!("failed to parse line"); // FIXME: don't panic, return error instead
                            }
                        }
                        Err(e) => {
                            panic!("failed to read line: {}", e); // FIXME: don't panic, return error instead
                        }
                    }
                }
            }

            Ok(())
        }

        /// Look up file metadata
        pub fn get(&self, name: &Path) -> Option<&FileInfo> {
            return self.map.get(&name.to_path_buf());
        }

        /// Persist file metadata
        pub fn set(&mut self, name: &Path, info: FileInfo) -> Result<(), MetadataError> {
            self.map
                .entry(name.to_path_buf())
                .and_modify(|v| *v = info)
                .or_insert(info);

            let entry = FileEntry {
                name: name.to_path_buf(),
                info,
            };
            self.journal(&entry)?;

            Ok(())
        }

        /// Delete file metadata
        pub fn remove(&mut self, name: &Path) -> Result<(), MetadataError> {
            self.map.remove(name);

            // Write tombstone value to journal
            let entry = FileEntry {
                name: name.to_path_buf(),
                info: ZERO_FILE_INFO,
            };
            self.journal(&entry)?;

            Ok(())
        }

        /// journal appends a FileEntry to the journal file and does a fsync
        fn journal(&mut self, entry: &FileEntry) -> Result<(), MetadataError> {
            let mut line: String = entry.into();
            line += "\n";

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path_journal)?;

            let mut writer = LineWriter::new(&file);

            // Note: LineWriter should flush() here because of the newline
            writer.write_all(line.as_ref())?;

            file.sync_all()?;

            Ok(())
        }

        /// flush writes the in-memory database to disk and closes/deletes the journal
        pub(crate) fn flush(&mut self) -> Result<(), std::io::Error> {
            // Create or open database
            let mut file_db;
            if self.path_db.exists() {
                file_db = OpenOptions::new().write(true).open(&self.path_db)?;
            } else {
                file_db = File::create(&self.path_db)?;
            }

            // Dump map to database
            for (k, v) in &self.map {
                let entry = FileEntry {
                    name: k.to_path_buf(),
                    info: *v,
                };
                let mut line: String = entry.borrow().into();
                line += "\n";

                file_db.write_all(line.as_ref())?;
            }

            // Delete journal
            fs::remove_file(&self.path_journal)?;

            Ok(())
        }
    }

    /// Call flush on dropping Store instances
    impl Drop for Store {
        fn drop(&mut self) {
            self.flush();
        }
    }
}

#[cfg(test)]
mod test {
    use super::metadata::{FileEntry, FileInfo, Store};
    use std::convert::TryFrom;
    use std::ffi::OsStr;
    use std::fs::OpenOptions;
    use std::io::{BufRead, BufReader};
    use std::mem::forget;
    use std::path::Path;
    use tempfile::tempdir;
    use time::Timespec;

    fn dump_file(path: &Path) {
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .expect("could not open file");
        let reader = BufReader::new(file);
        for res in reader.lines() {
            let line = res.expect("could not read line");
            println!(
                "{}: {}",
                path.to_str().expect("could not get string from path"),
                line
            )
        }
    }

    #[test]
    fn basic_store_test() {
        let f1 = FileInfo {
            time: Timespec { sec: 1, nsec: 1 },
            mode: 1,
            uid: 1,
            gid: 1,
        };
        let f2 = FileInfo {
            time: Timespec { sec: 2, nsec: 2 },
            mode: 2,
            uid: 2,
            gid: 2,
        };

        let dir = tempdir().expect("could not create tempdir");
        let dir_pathbuf = dir.path().to_path_buf(); // We'll need a copy later on
        let dir_path = dir_pathbuf.as_path();

        assert!(dir_path.exists());

        let mut s = Store::new(dir.path()).unwrap();

        let journal_file_pathbuf = dir_path.join(".progitoor_journal_v1_dont_commit_me");
        let journal_file = journal_file_pathbuf.as_path();

        assert!(s.get(Path::new("/non-existent")).is_none());

        s.set(Path::new("/f1"), f1);
        s.set(Path::new("/f2"), f2);

        let gf1 = s.get(Path::new("/f1")).unwrap();
        let gf2 = s.get(Path::new("/f2")).unwrap();

        assert_eq!(f1, *gf1);
        assert_eq!(f2, *gf2);

        s.remove(Path::new("/f1"));

        assert!(s.get(Path::new("/f1")).is_none());

        // Check that journal gets flushed
        drop(s);
        assert!(!journal_file.exists());

        // Make sure we've cleaned up temporary files
        drop(dir);
        assert!(!dir_path.exists());
    }

    #[test]
    fn crashy_store_test() {
        let f1 = FileInfo {
            time: Timespec { sec: 1, nsec: 1 },
            mode: 1,
            uid: 1,
            gid: 1,
        };
        let f2 = FileInfo {
            time: Timespec { sec: 2, nsec: 2 },
            mode: 2,
            uid: 2,
            gid: 2,
        };

        let dir = tempdir().expect("could not create tempdir");
        let dir_pathbuf = dir.path().to_path_buf(); // We'll need a copy later on
        let dir_path = dir_pathbuf.as_path();
        let journal_file_pathbuf = dir_path.join(".progitoor_journal_v1_dont_commit_me");
        let journal_file = journal_file_pathbuf.as_path();
        let db_file_pathbuf = dir_path.join(".progitoor_db_v1");
        let db_file = db_file_pathbuf.as_path();

        {
            let mut s = Store::new(dir.path()).unwrap();
            s.set(Path::new("/f1"), f1);
            s.flush(); // so we get a db on disk, with one entry
            s.set(Path::new("/f2"), f2);
            let gf1 = s.get(Path::new("/f1")).unwrap();
            let gf2 = s.get(Path::new("/f2")).unwrap();
            assert_eq!(f1, *gf1);
            assert_eq!(f2, *gf2);

            s.remove(Path::new("/f1"));

            forget(s); // Simulate crash
        }

        dump_file(journal_file);
        dump_file(db_file);

        {
            let mut s = Store::new(dir.path()).unwrap();

            // After new() has run, the journal should have been replayed and deleted
            assert!(!journal_file.exists());

            let gf2 = s.get(Path::new("/f2")).unwrap(); // Replayed from journal
            assert_eq!(f2, *gf2);

            // First loaded from DB then deleted due to tombstone in journal
            assert!(s.get(Path::new("/f1")).is_none());
        }

        // Make sure we've cleaned up temporary files
        drop(dir);
        assert!(!dir_path.exists());
    }

    #[test]
    fn fileentry_deserialisation_test() {
        let good = FileEntry::try_from("01a4 0000 0000 0613ab659 00000000 /etc/passwd").unwrap();
        assert_eq!(good.info.mode, 0o644);
        assert_eq!(good.info.uid, 0);
        assert_eq!(good.info.gid, 0);
        assert_eq!(
            good.info.time,
            Timespec {
                sec: 1631237721,
                nsec: 0
            }
        );
        assert_eq!(good.name, Path::new("/etc/passwd"));

        // FIXME: write tests for error cases
    }

    #[test]
    fn fileentry_serialisation_test() {
        let model = &FileEntry {
            name: "/etc/passwd".parse().unwrap(),
            info: FileInfo {
                time: Timespec {
                    sec: 1631237721,
                    nsec: 0,
                },
                mode: 0o644,
                uid: 0,
                gid: 0,
            },
        };

        let good: String = model.into();

        assert_eq!(good, "01a4 0000 0000 0613ab659 00000000 /etc/passwd")

        // FIXME: write tests for error cases
    }
}
