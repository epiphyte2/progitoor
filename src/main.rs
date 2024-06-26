// Copyright 2021 Edwin Peer and Simeon Miteff

extern crate daemonize;
extern crate fuse_mt;
extern crate libc;
extern crate nix;
extern crate time;

use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::exit;

use anyhow::{anyhow, Context, Result};
use clap::{
    arg_enum, crate_authors, crate_description, crate_name, crate_version, value_t, App, Arg,
};
use daemonize::{Daemonize, Outcome};
use interprocess::unnamed_pipe::{pipe, UnnamedPipeReader};
use nix::fcntl;
use nix::sys::stat;
use log::{error, info};

use progitoor::filesystem::FS;

fn background(mut ready: UnnamedPipeReader) -> std::result::Result<(), daemonize::Error> {
    match Daemonize::new().execute() {
        Outcome::Parent(Ok(_)) => {
            println!("Foreground process waiting for mount...");
            let mut buffer = [0; 0];
            ready
                .read_exact(&mut buffer[..])
                .expect("Receiving on ready channel failed");
            println!("Foreground process waiting for 2s...");
            std::thread::sleep(std::time::Duration::from_secs(2));
            println!("Foreground process exiting.");
            exit(0);
        },
        Outcome::Parent(Err(e)) => Err(e),
        Outcome::Child(Ok(_)) => Ok(()),
        Outcome::Child(Err(e)) => Err(e),
    }
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
        .arg(
            Arg::with_name("MOUNT_OPT")
                .short("o")
                .number_of_values(1)
                .multiple(true)
                .help("Specifies the mount options")
                .required(false)
                .takes_value(true),
        )
        .arg(Arg::with_name("SOURCE").index(1).required(true))
        .arg(Arg::with_name("TARGET").index(2).required(true))
        .get_matches();

    let source_dir = arg.value_of("SOURCE").context("No source directory")?;

    let target_dir = arg.value_of("TARGET").context("No mount point")?;

    let mount_path = Path::new(target_dir);
    if !mount_path.exists() {
        return Err(anyhow!("Mount point {} does not exist", target_dir));
    }
    if !mount_path.is_dir() {
        return Err(anyhow!("Mount point {} is not a directory", target_dir));
    }
    let source_dir = fs::canonicalize(source_dir).context(format!(
        "Failed to canonicalize source dir of {}",
        source_dir
    ))?;

    let target_dir = fs::canonicalize(target_dir).context(format!(
        "Failed to canonicalize mount point of {}",
        target_dir
    ))?;

    let mount_fd = fcntl::open(
        &source_dir,
        fcntl::OFlag::O_PATH | fcntl::OFlag::O_DIRECTORY,
        stat::Mode::empty(),
    )
    .context(format!("Failed to open directory {:?}", source_dir))?;

    let mut base_log_config = fern::Dispatch::new();
    base_log_config = match value_t!(arg, "LOGLEVEL", LogLevel).context("Could not get loglevel")? {
        LogLevel::Debug => base_log_config.level(log::LevelFilter::Debug),
        LogLevel::Info => base_log_config.level(log::LevelFilter::Info),
        LogLevel::Warning => base_log_config.level(log::LevelFilter::Warn),
        LogLevel::Error => base_log_config.level(log::LevelFilter::Error),
    };

    let (mut ready_tx, ready_rx) = pipe().expect("Failed to create unnamed pipe for IPC");

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

        background(ready_rx).context("failed to daemonize")?;
    }

    let default_fuse_options = vec!["nonempty", "allow_root", "auto_unmount", "suid", "exec"];

    let mut fuse_options: Vec<_> = default_fuse_options
        .iter()
        .flat_map(|x| [OsStr::new("-o"), OsStr::new(x)])
        .collect();

    if arg.is_present("MOUNT_OPT") {
        let user_options = arg
            .value_of("MOUNT_OPT")
            .context("Problem getting mount options")?;
        if !user_options.is_empty() {
            fuse_options.extend(
                user_options
                    .split(',')
                    .filter(|x| !default_fuse_options.contains(x))
                    .flat_map(|x| [OsStr::new("-o"), OsStr::new(x)]),
            );
        }
    }

    info!("Source dir: {:?}", source_dir);
    info!("Mount point: {:?}", target_dir);
    info!("Using fuse mount options: {:?}", fuse_options);

    let fuse = FS::new(mount_fd);

    // Add a panic handler that causes the process to exit, otherwise
    // the periodic flusher thread may panic and we'll just continue running.
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        log::error!("progitoor thread panic: {}", panic_info);
        orig_hook(panic_info);
        std::process::exit(1);
    }));

    info!("Ready to mount...");
    ready_tx.write(&[0]).context("Signalling fork failed")?;

    match fuse_mt::mount(fuse_mt::FuseMT::new(fuse, 16), &target_dir, &fuse_options)
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
