# progitoor

## Introduction

`progitoor` is an overlay filesystem that stores ownership and other file metadata in a text database and presents
that view to processes running as root, while the actual files are user-owned and can be versioned in git.

A typical use-case is building root filesystems. In this scenario:
- The backing store could be files in a user-owned git branch somewhere in `~/project/`
- `progitoor` would mount the backing store and present the overlay under a mount point (e.g., `~/mnt/`)
- Files are created or modified within a `sudo chroot ~/mnt` will have their ownership and mtime persisted in
  `~/project/.progitoor` (which is ideally also git versioned)

## Theory of operation

File I/O is passed through `progitoor` using the FUSE filesystem driver. A `BTreeMap` is used for lookups when
file metadata needs to be remapped. The map is persisted (flushed) to a text file (`.progitoor` in the underlay)
every 30 seconds, and also when `progitoor` exits (normally on un-mounting the filesystem).

Each change to the map is also written to a journal file for safety. The flush operation deletes
the journal. If the journal file exists at start-up (indicating a crash), it is replayed (merged into the database
and deleted). File deletions are journaled by writing a special (tombstone) entry with an all-zero file mode.

## Building and installing

To install the latest version of `progitoor`, ensure you have a [Rust toolchain installed](https://rustup.rs/), then run:

```console
cargo install progitoor
```

Or, to build from source (binary in `target/release/progitoor`):

```console
cargo build --release
```

## Usage

Unless the optional `--foreground` flag is used, `progitoor` will mount the filesystem and then fork into the background and
exit, with logging to syslog. In foreground mode logging is sent to stdout.

The usage is compatible with normal `mount -o options <device> <mount point>`, specifically:
```console
USAGE:
    progitoor [FLAGS] [OPTIONS] <SOURCE> <TARGET>

FLAGS:
    -f, --foreground    Don't fork - remain in foreground
    -h, --help          Prints help information
    -V, --version       Prints version information

OPTIONS:
    -l, --loglevel <LOGLEVEL>    Specifies the log level [default: Info]
    -o <MOUNT_OPT>...            Specifies the mount options

ARGS:
    <SOURCE>
    <TARGET>
```

Valid log levels for `--loglevel` are `Debug`, `Info`, `Warn` and `Error`.

## Example

Running progitoor (foreground mode):
```console
$ mkdir project
$ mkdir mnt
$ progitoor ./project/ ./mnt/ --foreground
Source dir: "/home/simeon/project"
Mount point: "/home/simeon/mnt"
Using fuse mount options: ["-o", "nonempty", "-o", "allow_root", "-o", "auto_unmount", "-o", "suid", "-o", "exec"]
Periodic flusher thread starting
Ready to mount...
Mounting /home/simeon/mnt
Periodic flusher thread running
```

In another terminal, create some files, look at them (as user):
```console
$ cd mnt
mnt$ mkdir etc
mnt$ echo "fake data" > etc/passwd
mnt$ ls -ld etc/
drwxrwxr-x 2 simeon simeon 4096 Oct  3 09:27 etc/
mnt$ ls -l etc/
total 4
-rw-rw-r-- 1 simeon simeon 10 Oct  3 09:28 passwd
```

As root, adjust ownership:
```shell
mnt$ sudo chown -R root: etc/
```

The user's view is unchanged:
```console
mnt$ ls -ld etc/
drwxrwxr-x 2 simeon simeon 4096 Oct  3 09:27 etc/
mnt$ ls -l etc/
total 4
-rw-rw-r-- 1 simeon simeon 10 Oct  3 09:28 passwd
```

Root sees the remapped ownership:
```console
mnt$ sudo ls -ld etc/
drwxrwxr-x 2 root root 4096 Oct  3 09:27 etc/
mnt$ sudo ls -l etc/
total 4
-rw-rw-r-- 1 root root 10 Oct  3 09:28 passwd
```

## License

`progitoor` is licensed under the General Public License 3.0. Please see `LICENSE` for details.
