// Copyright 2021 Edwin Peer and Simeon Miteff

extern crate daemonize;
extern crate fuse_mt;
extern crate libc;
extern crate nix;
extern crate time;

use std::ffi::OsString;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use clap::{
    arg_enum, crate_authors, crate_description, crate_name, crate_version, value_t, App, Arg,
};
use daemonize::{Daemonize, DaemonizeError};
use nix::fcntl;
use nix::sys::stat;
use log::{error, info};

use progitoor::filesystem::FS;

fn background() -> std::result::Result<(), DaemonizeError> {
    let daemonize = Daemonize::new().exit_action(|| println!("Foreground process exiting."));

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

    let mount_fd = fcntl::open(
        &absolute_mount_path,
        fcntl::OFlag::O_PATH | fcntl::OFlag::O_DIRECTORY,
        stat::Mode::empty(),
    )
    .context(format!("Failed to open directory {}", dir))?;

    let mut base_log_config = fern::Dispatch::new();
    base_log_config = match value_t!(arg, "LOGLEVEL", LogLevel).context("Could not get loglevel")? {
        LogLevel::Debug => base_log_config.level(log::LevelFilter::Debug),
        LogLevel::Info => base_log_config.level(log::LevelFilter::Info),
        LogLevel::Warning => base_log_config.level(log::LevelFilter::Warn),
        LogLevel::Error => base_log_config.level(log::LevelFilter::Error),
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

    info!("Absolute mount/root dir: {:?}", absolute_mount_path);

    let fuse = FS::new(mount_fd);

    // Add a panic handler that causes the process to exit, otherwise
    // the periodic flusher thread may panic and we'll just continue running.
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        log::error!("progitoor thread panic: {}", panic_info);
        orig_hook(panic_info);
        std::process::exit(1);
    }));

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
