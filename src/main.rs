// Copyright 2021 Edwin Peer and Simeon Miteff

extern crate daemonize;
extern crate fuse_mt;
extern crate libc;
extern crate nix;
extern crate time;

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::os::unix::prelude::*;
use std::path::{Component, Path};
use std::{fs, io};

use anyhow::{anyhow, Context, Result};
use clap::{
    arg_enum, crate_authors, crate_description, crate_name, crate_version, value_t, App, Arg,
};
use daemonize::{Daemonize, DaemonizeError};
use fuse_mt::*;
use nix::dir::{Dir, Type};
use nix::fcntl;
use nix::sys::{stat, statfs};
use nix::unistd;
use log::{error, info};

use progitoor::metadata::FileInfo;

struct MountOwner {
    uid: unistd::Uid,
    gid: unistd::Gid,
}

struct FS {
    root: RawFd,
    owner: MountOwner,
    metadata: progitoor::metadata::Store,
}

fn relative_path(path: &Path) -> &Path {
    let mut i = path.components();
    assert!(matches!(i.next(), Some(Component::RootDir)));
    match i.next() {
        Some(_) => path.strip_prefix("/").unwrap(),
        None => Path::new("."),
    }
}

fn utime(time: Option<time::Timespec>) -> nix::sys::time::TimeSpec {
    nix::sys::time::TimeSpec::from(match time {
        Some(time) => libc::timespec {
            tv_sec: time.sec as libc::time_t,
            tv_nsec: time.nsec as libc::c_long,
        },
        None => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
    })
}

fn result_entry(mapping: FileInfo, result: Result<stat::FileStat, nix::Error>) -> ResultEntry {
    match result {
        Ok(stat) => {
            let mode = match mapping.mode {
                Some(mode) => mode,
                None => stat.st_mode as libc::mode_t,
            };
            let atime = time::Timespec::new(stat.st_atime, stat.st_atime_nsec as i32);
            let ctime = time::Timespec::new(stat.st_ctime, stat.st_ctime_nsec as i32);
            let mtime = match mapping.time {
                Some(time) => time,
                None => time::Timespec::new(stat.st_mtime, stat.st_mtime_nsec as i32),
            };
            Ok((
                time::Timespec::new(1, 0),
                FileAttr {
                    size: stat.st_size as u64,
                    blocks: stat.st_blocks as u64,
                    atime: if atime > mtime { atime } else { mtime },
                    mtime: mtime,
                    ctime: if ctime > mtime { ctime } else { mtime },
                    crtime: time::Timespec::new(0, 0),
                    kind: match mode & libc::S_IFMT {
                        libc::S_IFIFO => FileType::NamedPipe,
                        libc::S_IFCHR => FileType::CharDevice,
                        libc::S_IFBLK => FileType::BlockDevice,
                        libc::S_IFDIR => FileType::Directory,
                        libc::S_IFLNK => FileType::Symlink,
                        libc::S_IFSOCK => FileType::Socket,
                        _ => FileType::RegularFile,
                    },
                    perm: (mode & !libc::S_IFMT) as u16,
                    nlink: stat.st_nlink as u32,
                    uid: match mapping.uid {
                        Some(uid) => uid.as_raw() as u32,
                        None => stat.st_uid,
                    },
                    gid: match mapping.gid {
                        Some(gid) => gid.as_raw() as u32,
                        None => stat.st_gid,
                    },
                    rdev: stat.st_rdev as u32,
                    flags: 0,
                },
            ))
        }
        Err(e) => Err(e as libc::c_int),
    }
}

fn result_open(flags: u32, result: Result<RawFd, nix::Error>) -> ResultOpen {
    match result {
        Ok(fd) => Ok((fd as u64, flags)),
        Err(e) => Err(e as libc::c_int),
    }
}

fn result_empty(result: Result<(), nix::Error>) -> ResultEmpty {
    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(e as libc::c_int),
    }
}

fn result_data(result: Result<OsString, nix::Error>) -> ResultData {
    match result {
        Ok(data) => Ok(data.into_vec()),
        Err(e) => Err(e as libc::c_int),
    }
}

fn result_write(result: Result<usize, nix::Error>) -> ResultWrite {
    match result {
        Ok(size) => Ok(size as u32),
        Err(e) => Err(e as libc::c_int),
    }
}

fn result_statfs(result: Result<statfs::Statfs, nix::Error>) -> ResultStatfs {
    match result {
        Ok(stats) => Ok(Statfs {
            blocks: stats.blocks(),
            bfree: stats.blocks_free(),
            bavail: stats.blocks_available(),
            files: stats.files(),
            ffree: stats.files_free(),
            bsize: stats.optimal_transfer_size() as u32,
            namelen: stats.maximum_name_length() as u32,
            frsize: stats.block_size() as u32,
        }),
        Err(e) => Err(e as libc::c_int),
    }
}

impl FS {
    fn mapping(&self, req: &RequestInfo, path: &Path) -> FileInfo {
        let mut info = self.metadata.get(path).unwrap_or(FileInfo {
            uid: Some(unistd::Uid::from_raw(0)),
            gid: Some(unistd::Gid::from_raw(0)),
            ..Default::default()
        });
        if unistd::Uid::from_raw(req.uid as libc::uid_t) == self.owner.uid {
            info.uid.take();
        };
        if unistd::Gid::from_raw(req.gid as libc::gid_t) == self.owner.gid {
            info.gid.take();
        };
        info
    }

    fn stat(&self, path: &Path, fh: Option<u64>) -> nix::Result<stat::FileStat> {
        match fh {
            Some(fd) => stat::fstat(fd as RawFd),
            None => stat::fstatat(
                self.root,
                relative_path(path),
                fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            ),
        }
    }

    fn init_info(&self, path: &Path, fh: Option<u64>) -> FileInfo {
        match self.stat(path, fh) {
            Ok(stat) => FileInfo {
                time: Some(time::Timespec::new(
                    stat.st_mtime,
                    stat.st_mtime_nsec as i32,
                )),
                mode: Some(stat.st_mode as libc::mode_t),
                uid: Some(unistd::Uid::from_raw(stat.st_uid)),
                gid: Some(unistd::Gid::from_raw(stat.st_gid)),
            },
            Err(_) => FileInfo::default(),
        }
    }

    fn update<F, G>(&self, path: &Path, updater: F, initializer: G) -> ResultEmpty
    where
        F: FnOnce(&mut FileInfo) -> (),
        G: FnOnce() -> FileInfo,
    {
        match self.metadata.update(path, updater, initializer) {
            Ok(()) => Ok(()),
            Err(_) => Err(libc::ENODEV),
        }
    }
}

impl FilesystemMT for FS {
    fn getattr(&self, req: RequestInfo, path: &Path, fh: Option<u64>) -> ResultEntry {
        result_entry(self.mapping(&req, path), self.stat(path, fh))
    }

    fn chmod(&self, _req: RequestInfo, path: &Path, fh: Option<u64>, mode: u32) -> ResultEmpty {
        let update = |info: &mut FileInfo| {
            if let Some(ref mut m) = info.mode {
                *m &= libc::S_IFMT;
                *m |= mode & !libc::S_IFMT;
            };
        };
        self.update(path, update, || self.init_info(path, fh))?;
        let mut mode = stat::Mode::from_bits_truncate(mode as stat::mode_t);
        mode &= stat::Mode::S_IRWXU | stat::Mode::S_IRWXG | stat::Mode::S_IRWXO;
        result_empty(match fh {
            Some(fd) => stat::fchmod(fd as RawFd, mode),
            None => stat::fchmodat(
                Some(self.root),
                relative_path(path),
                mode,
                stat::FchmodatFlags::FollowSymlink,
            ),
        })
    }

    fn chown(
        &self,
        req: RequestInfo,
        path: &Path,
        fh: Option<u64>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> ResultEmpty {
        let uid = match uid {
            Some(uid) => Some(unistd::Uid::from_raw(uid as libc::uid_t)),
            None => None,
        };
        let gid = match gid {
            Some(gid) => Some(unistd::Gid::from_raw(gid as libc::gid_t)),
            None => None,
        };
        let req_uid = unistd::Uid::from_raw(req.uid as libc::uid_t);
        let req_gid = unistd::Gid::from_raw(req.gid as libc::gid_t);
        if req_uid != self.owner.uid || req_gid != self.owner.gid {
            let update = |info: &mut FileInfo| {
                if uid.is_some() && req_uid != self.owner.uid {
                    info.uid = uid;
                };
                if gid.is_some() && req_gid != self.owner.gid {
                    info.gid = gid;
                };
            };
            return self.update(path, update, || self.init_info(path, fh));
        };

        // not sure pass through is useful, but is consistent with getattr() for owner
        result_empty(match fh {
            Some(fd) => unistd::fchown(fd as RawFd, uid, gid),
            None => unistd::fchownat(
                Some(self.root),
                relative_path(path),
                uid,
                gid,
                unistd::FchownatFlags::FollowSymlink,
            ),
        })
    }

    fn truncate(&self, _req: RequestInfo, path: &Path, fh: Option<u64>, size: u64) -> ResultEmpty {
        let fd = match fh {
            Some(fd) => fd,
            None => {
                result_open(
                    0,
                    fcntl::openat(
                        self.root,
                        relative_path(path),
                        fcntl::OFlag::O_WRONLY,
                        stat::Mode::empty(),
                    ),
                )?
                .0
            }
        } as RawFd;
        result_empty(unistd::ftruncate(fd, size as i64))?;
        if fh.is_none() {
            result_empty(unistd::close(fd))?;
        }
        Ok(())
    }

    fn utimens(
        &self,
        _req: RequestInfo,
        path: &Path,
        fh: Option<u64>,
        atime: Option<time::Timespec>,
        mtime: Option<time::Timespec>,
    ) -> ResultEmpty {
        result_empty(match fh {
            Some(fh) => stat::futimens(fh as RawFd, &utime(atime), &utime(mtime)),
            None => stat::utimensat(
                Some(self.root),
                relative_path(path),
                &utime(atime),
                &utime(mtime),
                stat::UtimensatFlags::FollowSymlink,
            ),
        })
    }

    fn readlink(&self, _req: RequestInfo, path: &Path) -> ResultData {
        result_data(fcntl::readlinkat(self.root, relative_path(path)))
    }

    fn mknod(
        &self,
        req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        rdev: u32,
    ) -> ResultEntry {
        let path = &relative_path(parent).join(name);
        unsafe {
            if libc::mknodat(
                self.root as libc::c_int,
                CString::from_vec_unchecked(path.as_os_str().as_bytes().to_vec()).as_ptr(),
                mode as libc::mode_t,
                rdev as libc::dev_t,
            ) == -1
            {
                return Err(io::Error::last_os_error().raw_os_error().unwrap());
            };
        }
        result_entry(
            self.mapping(&req, path),
            stat::fstatat(self.root, path, fcntl::AtFlags::empty()),
        )
    }

    fn mkdir(&self, req: RequestInfo, parent: &Path, name: &OsStr, mode: u32) -> ResultEntry {
        let path = &relative_path(parent).join(name);
        result_empty(stat::mkdirat(
            self.root as RawFd,
            path,
            stat::Mode::from_bits_truncate(mode as stat::mode_t),
        ))?;
        result_entry(
            self.mapping(&req, path),
            stat::fstatat(self.root, path, fcntl::AtFlags::empty()),
        )
    }

    fn unlink(&self, _req: RequestInfo, parent: &Path, name: &OsStr) -> ResultEmpty {
        result_empty(unistd::unlinkat(
            Some(self.root),
            &relative_path(parent).join(name),
            unistd::UnlinkatFlags::NoRemoveDir,
        ))
    }

    fn rmdir(&self, _req: RequestInfo, parent: &Path, name: &OsStr) -> ResultEmpty {
        result_empty(unistd::unlinkat(
            Some(self.root),
            &relative_path(parent).join(name),
            unistd::UnlinkatFlags::RemoveDir,
        ))
    }

    fn symlink(&self, req: RequestInfo, parent: &Path, name: &OsStr, target: &Path) -> ResultEntry {
        let path = &relative_path(parent).join(name);
        result_empty(unistd::symlinkat(target, Some(self.root), path))?;
        result_entry(
            self.mapping(&req, path),
            stat::fstatat(self.root, path, fcntl::AtFlags::AT_SYMLINK_NOFOLLOW),
        )
    }

    fn rename(
        &self,
        _req: RequestInfo,
        old_parent: &Path,
        old_name: &OsStr,
        new_parent: &Path,
        new_name: &OsStr,
    ) -> ResultEmpty {
        let old = &relative_path(old_parent).join(old_name);
        let new = &relative_path(new_parent).join(new_name);
        result_empty(fcntl::renameat(Some(self.root), old, Some(self.root), new))
    }

    fn link(
        &self,
        req: RequestInfo,
        path: &Path,
        new_parent: &Path,
        new_name: &OsStr,
    ) -> ResultEntry {
        let old = relative_path(path);
        let new = &relative_path(new_parent).join(new_name);
        result_empty(unistd::linkat(
            Some(self.root),
            old,
            Some(self.root),
            new,
            unistd::LinkatFlags::NoSymlinkFollow,
        ))?;
        result_entry(
            self.mapping(&req, new),
            stat::fstatat(self.root, new, fcntl::AtFlags::empty()),
        )
    }

    fn open(&self, _req: RequestInfo, path: &Path, flags: u32) -> ResultOpen {
        result_open(
            flags,
            fcntl::openat(
                self.root,
                relative_path(path),
                fcntl::OFlag::from_bits_truncate(flags as libc::c_int),
                stat::Mode::empty(),
            ),
        )
    }

    fn read(
        &self,
        _req: RequestInfo,
        _path: &Path,
        fh: u64,
        offset: u64,
        size: u32,
        callback: impl FnOnce(ResultSlice<'_>) -> CallbackResult,
    ) -> CallbackResult {
        if let Err(e) = unistd::lseek64(
            fh as RawFd,
            offset as libc::off64_t,
            unistd::Whence::SeekSet,
        ) {
            return callback(Err(e as libc::c_int));
        };
        let mut data = Vec::<u8>::with_capacity(size as usize);
        unsafe {
            data.set_len(size as usize);
        }
        match unistd::read(fh as RawFd, &mut data) {
            Ok(bytes) => {
                data.truncate(bytes);
                callback(Ok(&data))
            }
            Err(e) => callback(Err(e as libc::c_int)),
        }
    }

    fn write(
        &self,
        _req: RequestInfo,
        _path: &Path,
        fh: u64,
        offset: u64,
        data: Vec<u8>,
        _flags: u32,
    ) -> ResultWrite {
        if let Err(e) = unistd::lseek64(
            fh as RawFd,
            offset as libc::off64_t,
            unistd::Whence::SeekSet,
        ) {
            return Err(e as libc::c_int);
        };
        result_write(unistd::write(fh as RawFd, &data))
    }

    fn flush(&self, _req: RequestInfo, _path: &Path, _fh: u64, _lock_owner: u64) -> ResultEmpty {
        unistd::sync();
        Ok(())
    }

    fn release(
        &self,
        _req: RequestInfo,
        _path: &Path,
        fh: u64,
        _flags: u32,
        _lock_owner: u64,
        flush: bool,
    ) -> ResultEmpty {
        if flush {
            unistd::sync();
        };
        result_empty(unistd::close(fh as RawFd))
    }

    fn fsync(&self, _req: RequestInfo, _path: &Path, fh: u64, datasync: bool) -> ResultEmpty {
        result_empty(match datasync {
            true => unistd::fdatasync(fh as RawFd),
            false => unistd::fsync(fh as RawFd),
        })
    }

    fn opendir(&self, _req: RequestInfo, path: &Path, flags: u32) -> ResultOpen {
        result_open(
            flags,
            fcntl::openat(
                self.root,
                relative_path(path),
                fcntl::OFlag::from_bits_truncate(flags as libc::c_int),
                stat::Mode::empty(),
            ),
        )
    }

    fn readdir(&self, _req: RequestInfo, _path: &Path, fh: u64) -> ResultReaddir {
        let dir = match Dir::from_fd(fh as RawFd) {
            Ok(d) => d,
            Err(e) => return Err(e as libc::c_int),
        };
        let mut entries = Vec::<DirectoryEntry>::new();
        for entry in dir {
            match entry {
                Ok(entry) => {
                    entries.push(DirectoryEntry {
                        name: OsString::from(OsStr::from_bytes(entry.file_name().to_bytes())),
                        kind: match entry.file_type() {
                            Some(kind) => match kind {
                                Type::Fifo => FileType::NamedPipe,
                                Type::CharacterDevice => FileType::CharDevice,
                                Type::Directory => FileType::Directory,
                                Type::BlockDevice => FileType::BlockDevice,
                                Type::Symlink => FileType::Symlink,
                                Type::Socket => FileType::Socket,
                                _ => FileType::RegularFile,
                            },
                            None => FileType::RegularFile,
                        },
                    });
                }
                Err(_e) => continue,
            }
        }
        Ok(entries)
    }

    fn releasedir(&self, _req: RequestInfo, _path: &Path, fh: u64, _flags: u32) -> ResultEmpty {
        result_empty(unistd::close(fh as RawFd))
    }

    fn fsyncdir(&self, _req: RequestInfo, _path: &Path, fh: u64, datasync: bool) -> ResultEmpty {
        result_empty(match datasync {
            true => unistd::fdatasync(fh as RawFd),
            false => unistd::fsync(fh as RawFd),
        })
    }

    fn statfs(&self, _req: RequestInfo, _path: &Path) -> ResultStatfs {
        result_statfs(statfs::fstatfs(&self.root))
    }

    fn create(
        &self,
        req: RequestInfo,
        parent: &Path,
        name: &OsStr,
        mode: u32,
        flags: u32,
    ) -> ResultCreate {
        let path = &relative_path(parent).join(name);
        let flags = fcntl::OFlag::from_bits_truncate(flags as libc::c_int)
            | fcntl::OFlag::O_CREAT
            | fcntl::OFlag::O_EXCL;
        let fd = match fcntl::openat(
            self.root,
            path,
            flags,
            stat::Mode::from_bits_truncate(mode as stat::mode_t),
        ) {
            Ok(fd) => fd as RawFd,
            Err(e) => return Err(e as libc::c_int),
        };
        match result_entry(
            self.mapping(&req, path),
            stat::fstatat(self.root, path, fcntl::AtFlags::empty()),
        ) {
            Ok(entry) => Ok(CreatedEntry {
                ttl: entry.0,
                attr: entry.1,
                fh: fd as u64,
                flags: flags.bits() as u32,
            }),
            Err(e) => Err(e),
        }
    }
}

fn background() -> std::result::Result<(), DaemonizeError> {
    // FIXME: if we don't have this, we don't see any errors if the process dies after forking
    //        so this needs to be replaced with proper logging, but is useful in the meantime.
    let stdout = File::create("/tmp/progitoor.out").unwrap();
    let stderr = File::create("/tmp/progitoor.err").unwrap();

    let daemonize = Daemonize::new()
        .pid_file("/tmp/progitoor.pid") // TODO: how can we delete this on exit?
        .stdout(stdout)
        .stderr(stderr)
        .chown_pid_file(true);

    // This runs in the parent process, so isn't useful for unmount
    //.exit_action(|| println!("Executed before master process exits"));

    daemonize.start()
}

arg_enum! {
    #[derive(Debug, PartialEq)]
    pub enum LogLevel {
        Debug,
        Info,
        Warning,
        Error,
    }
}

fn main() -> Result<()> {
    let arg = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .arg(
            Arg::with_name("FOREGROUND")
                .short("f")
                .long("foreground")
                .help("Don't fork - remain in foreground")
                .required(false),
        )
        .arg(
            Arg::with_name("LOGLEVEL")
                .short("l")
                .long("loglevel")
                .help("Specifies the log level")
                .required(false)
                .takes_value(true)
                .default_value("Info"),
        )
        .arg(Arg::with_name("DIR").index(1).required(true))
        .get_matches();

    let mut base_log_config = fern::Dispatch::new();
    base_log_config = match value_t!(arg, "LOGLEVEL", LogLevel).context("Could not get loglevel")? {
        LogLevel::Debug => base_log_config.level(log::LevelFilter::Debug),
        LogLevel::Info => base_log_config.level(log::LevelFilter::Info),
        LogLevel::Warning => base_log_config.level(log::LevelFilter::Warn),
        LogLevel::Error => base_log_config.level(log::LevelFilter::Error),
    };

    let dir = arg
        .value_of("DIR")
        .context("Could not get base/mount point directory")?;

    let mount_path = Path::new(dir);
    if !mount_path.exists() {
        return Err(anyhow!("Root/mount point path {} does not exist", dir));
    }
    if !mount_path.is_dir() {
        return Err(anyhow!("Root/mount point path {} is not a directory", dir));
    }
    let absolute_mount_path = fs::canonicalize(mount_path)
        .context(format!("Failed to canonicalize mount path of {}", dir))?;

    info!("Absolute mount/root dir: {:?}", absolute_mount_path);

    let mount_fd = fcntl::open(
        &absolute_mount_path,
        fcntl::OFlag::O_PATH | fcntl::OFlag::O_DIRECTORY,
        stat::Mode::empty(),
    )
    .context(format!("Failed to open directory {}", dir))?;

    let fuse = FS {
        root: mount_fd,
        owner: MountOwner {
            uid: unistd::getuid(),
            gid: unistd::getgid(),
        },
        metadata: progitoor::metadata::Store::new(mount_fd).unwrap(),
    };

    if arg.is_present("FOREGROUND") {
        base_log_config
            .chain(std::io::stdout())
            .apply()
            .context("failed to set up logger")?;
    } else {
        base_log_config
            .chain(syslog::unix(syslog::Facility::LOG_USER)?)
            .apply()
            .context("failed to set up logger")?;

        background().context("failed to daemonize")?;
    }

    match fuse_mt::mount(
        fuse_mt::FuseMT::new(fuse, 1),
        &absolute_mount_path,
        &[
            &OsString::from("-o"),
            &OsString::from("nonempty"),
            &OsString::from("-o"),
            &OsString::from("allow_root"),
            &OsString::from("-o"),
            &OsString::from("auto_unmount"),
            &OsString::from("-o"),
            &OsString::from("suid"),
            &OsString::from("-o"),
            &OsString::from("exec"),
        ],
    )
    .context("Mount failed")
    {
        Ok(..) => {
            info!("progitoor exiting normally");
            Ok(())
        }
        Err(err) => {
            error!("progitoor exiting abnormally: {}", err);
            Err(err)
        }
    }
}
