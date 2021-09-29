// Copyright 2021 Edwin Peer and Simeon Miteff

extern crate daemonize;
extern crate fuse_mt;
extern crate libc;
extern crate nix;
extern crate time;

use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use clap::{
    arg_enum, crate_authors, crate_description, crate_name, crate_version, value_t, App, Arg,
};
use daemonize::{Daemonize, DaemonizeError};
use nix::fcntl;
use nix::sys::stat;
use nix::unistd;
use log::{error, info};

use progitoor::filesystem::{MountOwner, FS};

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
