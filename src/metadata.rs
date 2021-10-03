// Copyright 2021 Edwin Peer and Simeon Miteff

extern crate libc;
extern crate nix;
extern crate time;

use nix::fcntl;
use nix::sys::stat;
use nix::unistd;
use std::borrow::Borrow;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, LineWriter};
use std::os::unix::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use time::Timespec;

static FILENAME_JOURNAL: &str = ".progitoor_";
static FILENAME_DB: &str = ".progitoor";
static FILENAME_TMP: &str = ".progitoor$";

/// MetadataError is the general error type for the metadata module
#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("Error parsing FileInfo record from string")]
    FileInfoParsingError,
    #[error("Metadata store path [{0:?}] is not a directory")]
    InvalidMetadataStorePathError(PathBuf),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("Write Lock Poisoned")]
    WriteLockPoisonError,
    #[error(transparent)]
    NIXError(#[from] nix::Error),
}

/// FileInfo tracks file attributes progitoor is going to remap
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct FileInfo {
    pub time: Option<Timespec>,
    pub mode: Option<libc::mode_t>,
    pub uid: Option<unistd::Uid>,
    pub gid: Option<unistd::Gid>,
}

/// ZERO_FILE_INFO is used to write tombstones to the journal
const ZERO_FILE_INFO: FileInfo = FileInfo {
    time: Some(Timespec { sec: 0, nsec: 0 }),
    mode: Some(0 as libc::mode_t),
    uid: Some(unistd::Uid::from_raw(0 as libc::uid_t)),
    gid: Some(unistd::Gid::from_raw(0 as libc::gid_t)),
};

/// FileEntry is a name, info tuple
pub struct FileEntry {
    pub name: PathBuf,
    pub info: FileInfo,
}

// FIXME: clippy says: an implementation of `From` is preferred since it gives you `Into<_>` for free where the reverse isn't true

/// Serialise a FileEntry to a String
impl Into<String> for &FileEntry {
    fn into(self) -> String {
        format!(
            "{:04x} {:04x} {:04x} {:09x} {:08x} {}",
            self.info.mode.unwrap_or_default(),
            self.info.uid.unwrap_or(unistd::Uid::from_raw(0)).as_raw(),
            self.info.gid.unwrap_or(unistd::Gid::from_raw(0)).as_raw(),
            self.info.time.unwrap_or(Timespec { sec: 0, nsec: 0 }).sec,
            self.info.time.unwrap_or(Timespec { sec: 0, nsec: 0 }).nsec,
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
                mode: Some(u16::from_str_radix(parts[0], 16)? as libc::mode_t),
                uid: Some(unistd::Uid::from_raw(
                    u32::from_str_radix(parts[1], 16)? as libc::uid_t
                )),
                gid: Some(unistd::Gid::from_raw(
                    u32::from_str_radix(parts[2], 16)? as libc::gid_t
                )),
                time: Some(Timespec {
                    sec: i64::from_str_radix(parts[3], 16)?,
                    nsec: i32::from_str_radix(parts[4], 16)?,
                }),
            },
        })
    }
}

/// MtMap is a type alias for the heavily wrapped BTreeMap
type MtMap = Arc<RwLock<BTreeMap<PathBuf, FileInfo>>>;

/// Store is a file metadata store to support progitoor mapping
pub struct Store {
    map: MtMap,
    root: RawFd,
    flusher_thread_run: Arc<AtomicBool>,
}

impl Store {
    /// Construct a new Store instance
    pub fn new(root: RawFd) -> Result<Self, MetadataError> {
        log::debug!("Initialising metadata store");
        match Self::new_without_flusher_thread(root) {
            Ok(store) => {
                log::debug!("Metadata store created, starting flusher thread.");
                store.start_flusher_thread();
                Ok(store)
            }
            Err(e) => Err(e),
        }
    }

    /// Construct a Store instance that doesn't start a periodic flusher thread
    pub fn new_without_flusher_thread(root: RawFd) -> Result<Self, MetadataError> {
        let mut store = Self {
            map: Arc::new(RwLock::new(BTreeMap::new())),
            root: root,
            flusher_thread_run: Arc::new(AtomicBool::new(true)),
        };

        Store::load_file(&mut store.map, root, FILENAME_DB)?;

        if Store::load_file(&mut store.map, root, FILENAME_JOURNAL)? {
            store
                .internal_flush()
                .expect("error during flush in metadata store constructor")
        }

        Ok(store)
    }

    /// Start the periodic flusher thread
    fn start_flusher_thread(&self) {
        let thread_map = Arc::clone(&self.map);
        let thread_root = self.root.clone();
        let thread_flag = self.flusher_thread_run.clone();

        log::info!("Periodic flusher thread starting");

        std::thread::spawn(move || {
            log::info!("Periodic flusher thread running");
            while thread_flag.load(Ordering::SeqCst) {
                //log::debug!("Metadata flush.");
                // TODO: make sleep configurable
                std::thread::sleep(std::time::Duration::from_secs(30));
                Store::flush(&thread_map, thread_root)
                    .expect("metadata store periodic flush thread failed");
            }
        });
    }

    /// load_file is used for loading both the db and journal
    fn load_file(map: &mut MtMap, root: RawFd, file: &str) -> Result<bool, MetadataError> {
        let file_db = unsafe {
            File::from_raw_fd(
                match fcntl::openat(root, file, fcntl::OFlag::O_RDONLY, stat::Mode::empty()) {
                    Ok(fd) => fd,
                    Err(nix::Error::ENOENT) => return Ok(false),
                    Err(e) => return Err(MetadataError::NIXError(e)),
                },
            )
        };
        let reader = BufReader::new(file_db);
        for res in reader.lines() {
            match res {
                Ok(line) => {
                    match FileEntry::try_from(&*line) {
                        Ok(parse) => {
                            if parse.info.mode.unwrap_or_default() == 0 {
                                // Tombstone value
                                map.write().unwrap().remove(parse.name.as_path());

                                continue;
                            }

                            map.write()
                                .unwrap()
                                .entry(parse.name.clone())
                                .and_modify(|v| *v = parse.info)
                                .or_insert(parse.info);
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(MetadataError::IOError(e)),
            }
        }

        Ok(true)
    }

    /// Look up file metadata
    pub fn get(&self, name: &Path) -> Option<FileInfo> {
        if let Some(file_info_ref) = self.map.read().unwrap().get(&name.to_path_buf()) {
            return Some(file_info_ref.clone());
        }

        None
    }

    pub fn update<F, G>(&self, name: &Path, updater: F, initializer: G) -> Result<(), MetadataError>
    where
        F: FnOnce(&mut FileInfo) -> (),
        G: FnOnce() -> Option<FileInfo>,
    {
        let mut map = match self.map.write() {
            Ok(map) => map,
            Err(_) => return Err(MetadataError::WriteLockPoisonError),
        };
        let info = match map.entry(name.to_path_buf()) {
            Entry::Occupied(mut e) => {
                let mut info = e.get_mut();
                updater(&mut info);
                info.clone()
            }
            Entry::Vacant(e) => {
                let info = initializer();
                if info.is_none() {
                    return Ok(());
                };
                let mut info = info.unwrap();
                updater(&mut info);
                e.insert(info);
                info
            }
        };
        self.journal(&FileEntry {
            name: name.to_path_buf(),
            info,
        })
    }

    /// Walks the metadata store calling the visitor for each entry
    pub fn walk<F>(&self, visitor: F) -> Result<(), MetadataError>
    where
        F: Fn(&Path, &FileInfo) -> (),
    {
        let map = self.map.read().unwrap();
        for (k, v) in map.iter() {
            visitor(k, v);
        }
        Ok(())
    }

    /// Persist file metadata
    pub fn set(&self, name: &Path, info: FileInfo) -> Result<(), MetadataError> {
        self.map
            .write()
            .unwrap()
            .entry(name.to_path_buf())
            .and_modify(|v| *v = info)
            .or_insert(info);

        let entry = FileEntry {
            name: name.to_path_buf(),
            info,
        };
        Ok(self.journal(&entry)?)
    }

    /// Delete file metadata
    pub fn remove(&self, name: &Path) -> Result<(), MetadataError> {
        self.map.write().unwrap().remove(name);

        // Write tombstone value to journal
        let entry = FileEntry {
            name: name.to_path_buf(),
            info: ZERO_FILE_INFO,
        };
        self.journal(&entry)
    }

    /// journal appends a FileEntry to the journal file and does a fsync
    fn journal(&self, entry: &FileEntry) -> Result<(), MetadataError> {
        let mut line: String = entry.into();
        line += "\n";

        let file = unsafe {
            File::from_raw_fd(fcntl::openat(
                self.root,
                FILENAME_JOURNAL,
                fcntl::OFlag::O_CREAT | fcntl::OFlag::O_WRONLY | fcntl::OFlag::O_APPEND,
                stat::Mode::S_IRUSR | stat::Mode::S_IWUSR,
            )?)
        };

        let mut writer = LineWriter::new(&file);

        // Note: LineWriter will flush() here because of the newline
        writer.write_all(line.as_ref())?;

        Ok(file.sync_all()?)
    }

    /// flush writes the in-memory database to disk and closes/deletes the journal
    fn flush(map: &MtMap, root: RawFd) -> Result<(), MetadataError> {
        // Don't want updates to map during flush and one flush at a time
        let map = match map.write() {
            Ok(map) => map,
            Err(_) => return Err(MetadataError::WriteLockPoisonError),
        };

        // Check for existing journal
        match stat::fstatat(root, FILENAME_JOURNAL, fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(_) => (),
            Err(nix::Error::ENOENT) => return Ok(()), // nothing to do
            Err(e) => return Err(MetadataError::NIXError(e)),
        };

        // Durably dump map to database
        let mut file_tmp = unsafe {
            File::from_raw_fd(fcntl::openat(
                root,
                FILENAME_TMP,
                fcntl::OFlag::O_CREAT | fcntl::OFlag::O_TRUNC | fcntl::OFlag::O_WRONLY,
                stat::Mode::S_IRUSR | stat::Mode::S_IWUSR,
            )?)
        };
        for (k, v) in map.iter() {
            let entry = FileEntry {
                name: k.to_path_buf(),
                info: *v,
            };
            let mut line: String = entry.borrow().into();
            line += "\n";

            file_tmp.write_all(line.as_ref())?;
        }
        file_tmp.sync_all()?;
        fcntl::renameat(Some(root), FILENAME_TMP, Some(root), FILENAME_DB)?;

        // In memory map was authoritative, delete the journal
        Ok(unistd::unlinkat(
            Some(root),
            FILENAME_JOURNAL,
            unistd::UnlinkatFlags::NoRemoveDir,
        )?)
    }

    /// Non-static version of flush()
    pub(crate) fn internal_flush(&mut self) -> Result<(), MetadataError> {
        Store::flush(&self.map, self.root)
    }
}

/// Clean up on dropping Store instances
impl Drop for Store {
    fn drop(&mut self) {
        self.flusher_thread_run.store(false, Ordering::SeqCst);
        self.internal_flush()
            .expect("failure during flush in metadata store drop");
    }
}

#[cfg(test)]
mod test {
    use super::nix::fcntl;
    use super::nix::sys::stat;
    use crate::metadata::{FileEntry, FileInfo, Store};
    use nix::unistd;
    use std::convert::TryFrom;
    use std::mem::forget;
    use std::path::Path;
    use tempfile::tempdir;
    use time::Timespec;

    #[test]
    fn basic_store_test() {
        let f1 = FileInfo {
            time: Some(Timespec { sec: 1, nsec: 1 }),
            mode: Some(1),
            uid: Some(unistd::Uid::from_raw(1)),
            gid: Some(unistd::Gid::from_raw(1)),
        };
        let f2 = FileInfo {
            time: Some(Timespec { sec: 2, nsec: 2 }),
            mode: Some(2),
            uid: Some(unistd::Uid::from_raw(2)),
            gid: Some(unistd::Gid::from_raw(2)),
        };

        let dir = tempdir().expect("could not create tempdir");
        let dir_pathbuf = dir.path().to_path_buf(); // We'll need a copy later on
        let dir_path = dir_pathbuf.as_path();

        assert!(dir_path.exists());

        let mount_fd = fcntl::open(
            dir_path.into(),
            fcntl::OFlag::O_PATH | fcntl::OFlag::O_DIRECTORY,
            stat::Mode::empty(),
        )
        .expect("could not open root");

        let s = Store::new(mount_fd).unwrap();

        let journal_file_pathbuf = dir_path.join(".progitoor_journal_v1_dont_commit_me");
        let journal_file = journal_file_pathbuf.as_path();

        assert!(s.get(Path::new("/non-existent")).is_none());

        s.set(Path::new("/f1"), f1).expect("failed to set /f1");
        s.set(Path::new("/f2"), f2).expect("failed to set /f2");

        let gf1 = s.get(Path::new("/f1")).expect("failed to get /f1");
        let gf2 = s.get(Path::new("/f2")).expect("failed to get /f2");

        assert_eq!(f1, gf1);
        assert_eq!(f2, gf2);

        s.remove(Path::new("/f1")).expect("failed to remove /f1");

        assert!(s.get(Path::new("/f1")).is_none());

        // Check that journal gets flushed
        drop(s);
        assert!(!journal_file.exists());

        // Make sure we've FS cleaned up temporary files
        drop(dir);
        assert!(!dir_path.exists());
    }

    #[test]
    fn crashy_store_test() {
        let f1 = FileInfo {
            time: Some(Timespec { sec: 1, nsec: 1 }),
            mode: Some(1),
            uid: Some(unistd::Uid::from_raw(1)),
            gid: Some(unistd::Gid::from_raw(1)),
        };
        let f2 = FileInfo {
            time: Some(Timespec { sec: 2, nsec: 2 }),
            mode: Some(2),
            uid: Some(unistd::Uid::from_raw(2)),
            gid: Some(unistd::Gid::from_raw(2)),
        };

        let dir = tempdir().expect("could not create tempdir");
        let dir_pathbuf = dir.path().to_path_buf(); // We'll need a copy later on
        let dir_path = dir_pathbuf.as_path();
        let journal_file_pathbuf = dir_path.join(".progitoor_journal_v1_dont_commit_me");
        let journal_file = journal_file_pathbuf.as_path();
        let mount_fd = fcntl::open(
            dir_path.into(),
            fcntl::OFlag::O_PATH | fcntl::OFlag::O_DIRECTORY,
            stat::Mode::empty(),
        )
        .expect("could not open root");

        {
            let mut s =
                Store::new_without_flusher_thread(mount_fd).expect("failed to construct store");

            s.set(Path::new("/f1"), f1).expect("failed to set /f1");
            s.internal_flush().expect("failed to flush"); // so we get a db on disk, with one entry
            s.set(Path::new("/f2"), f2).expect("failed to set /f2");
            let gf1 = s.get(Path::new("/f1")).expect("failed to get /f1");
            let gf2 = s.get(Path::new("/f2")).expect("failed to get /f2");
            assert_eq!(f1, gf1);
            assert_eq!(f2, gf2);

            s.remove(Path::new("/f1")).expect("failed to remove /f1");

            forget(s); // Simulate crash
        }

        {
            let s = Store::new_without_flusher_thread(mount_fd).expect("failed to construct store");

            // After new() has run, the journal should have been replayed and deleted
            assert!(!journal_file.exists());

            // Replayed from journal
            let gf2 = s.get(Path::new("/f2")).expect("failed to get /f2");
            assert_eq!(f2, gf2);

            // First loaded from DB then deleted due to tombstone in journal
            assert!(s.get(Path::new("/f1")).is_none());
        }

        // Make sure we've cleaned up temporary files
        drop(dir);
        assert!(!dir_path.exists());
    }

    #[test]
    fn fileentry_deserialisation_test() {
        let good = FileEntry::try_from("01a4 0000 0000 0613ab659 00000000 /etc/passwd")
            .expect("failed to parse db string");
        assert_eq!(good.info.mode.unwrap(), 0o644);
        assert_eq!(good.info.uid.unwrap(), unistd::Uid::from_raw(0));
        assert_eq!(good.info.gid.unwrap(), unistd::Gid::from_raw(0));
        assert_eq!(
            good.info.time.unwrap(),
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
            name: "/etc/passwd".parse().expect("failed to create db string"),
            info: FileInfo {
                time: Some(Timespec {
                    sec: 1631237721,
                    nsec: 0,
                }),
                mode: Some(0o644),
                uid: Some(unistd::Uid::from_raw(0)),
                gid: Some(unistd::Gid::from_raw(0)),
            },
        };

        let good: String = model.into();

        assert_eq!(good, "01a4 0000 0000 0613ab659 00000000 /etc/passwd")

        // FIXME: write tests for error cases
    }
}
