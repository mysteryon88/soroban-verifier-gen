use rustix::{
    fs::{self, AtFlags, Mode, OFlags, RenameFlags},
    process::geteuid,
};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::unix::ffi::OsStringExt,
    path::{Component, Path},
};
pub(crate) struct Dir(File);
impl Dir {
    pub(crate) fn walk(path: &Path, create: bool) -> io::Result<Self> {
        let mut dir = Self(File::from(fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?));
        for component in path.components() {
            match component {
                Component::RootDir => (),
                Component::Normal(name) => {
                    dir.check_trusted_parent()?;
                    dir = match dir.open_dir(name) {
                        Ok(d) => d,
                        Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                            match dir.create_dir(name) {
                                Ok(d) => d,
                                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                                    dir.open_dir(name)?
                                }
                                Err(e) => return Err(e),
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
                _ => return Err(io::Error::other("unsafe output path component")),
            }
        }
        Ok(dir)
    }
    pub(crate) fn same_object(&self, other: &Dir) -> io::Result<bool> {
        let a = fs::fstat(&self.0)?;
        let b = fs::fstat(&other.0)?;
        Ok(a.st_dev == b.st_dev && a.st_ino == b.st_ino)
    }
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }
    pub(crate) fn open_dir(&self, name: &OsStr) -> io::Result<Self> {
        Ok(Self(File::from(fs::openat(
            &self.0,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?)))
    }
    pub(crate) fn create_private_dir(&self, name: &OsStr) -> io::Result<Self> {
        self.create_dir(name)
    }
    pub(crate) fn entry_exists(&self, name: &OsStr) -> io::Result<bool> {
        match fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    pub(crate) fn open_owned_dir(&self, name: &OsStr) -> io::Result<Self> {
        self.open_dir(name)
    }
    fn check_trusted_parent(&self) -> io::Result<()> {
        let stat = fs::fstat(&self.0)?;
        let uid = geteuid().as_raw();
        // Sticky protects our entries only when the parent owner is also trusted.
        if (stat.st_uid != uid && stat.st_uid != 0)
            || (stat.st_mode & 0o022 != 0 && stat.st_mode & 0o1000 == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsafe output parent: require effective-UID/root owner and no group/other write unless sticky",
            ));
        }
        Ok(())
    }
    pub(crate) fn create_dir(&self, name: &OsStr) -> io::Result<Self> {
        self.check_trusted_parent()?;
        fs::mkdirat(&self.0, name, Mode::RWXU)?;
        let child = self.open_dir(name)?;
        let stat = fs::fstat(&child.0)?;
        if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "new output directory is not effective-UID-owned/private; preserving object",
            ));
        }
        Ok(child)
    }
    pub(crate) fn open_file(&self, name: &OsStr) -> io::Result<File> {
        Ok(File::from(fs::openat(
            &self.0,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?))
    }
    pub(crate) fn create_file(&self, name: &OsStr) -> io::Result<File> {
        Ok(File::from(fs::openat(
            &self.0,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?))
    }
    pub(crate) fn entries(&self) -> io::Result<Vec<OsString>> {
        let mut result = Vec::new();
        for entry in fs::Dir::read_from(&self.0)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                result.push(OsString::from_vec(name.to_vec()));
            }
        }
        Ok(result)
    }
    pub(crate) fn rename(&self, old: &OsStr, destination: &Dir, new: &OsStr) -> io::Result<()> {
        match fs::renameat_with(&self.0, old, &destination.0, new, RenameFlags::NOREPLACE) {
            Ok(()) => Ok(()),
            Err(
                rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS | rustix::io::Errno::NOTSUP,
            ) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "filesystem lacks atomic no-replace rename; no output moved or replaced",
            )),
            Err(e) => Err(e.into()),
        }
    }
    pub(crate) fn rename_directory(
        &self,
        old: &OsStr,
        held: &Dir,
        destination: &Dir,
        new: &OsStr,
    ) -> io::Result<()> {
        if !self.open_dir(old)?.same_object(held)? {
            return Err(io::Error::other("source directory identity changed"));
        }
        self.rename(old, destination, new)?;
        if !destination.open_dir(new)?.same_object(held)? {
            return Err(io::Error::other(
                "renamed directory identity changed; preserving recovery data",
            ));
        }
        Ok(())
    }
    pub(crate) fn remove_tree(&self, name: &OsStr) -> io::Result<()> {
        let stat = fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if fs::FileType::from_raw_mode(stat.st_mode) == fs::FileType::Directory {
            let dir = self.open_dir(name)?;
            for child in dir.entries()? {
                dir.remove_tree(&child)?;
            }
            self.remove_empty_dir(name, &dir)
        } else if fs::FileType::from_raw_mode(stat.st_mode) == fs::FileType::RegularFile {
            Ok(fs::unlinkat(&self.0, name, AtFlags::empty())?)
        } else {
            Err(io::Error::other(
                "unexpected symlink/special file in output; preserving recovery directory",
            ))
        }
    }
    pub(crate) fn remove_empty_dir(&self, name: &OsStr, dir: &Dir) -> io::Result<()> {
        let expected = fs::fstat(&dir.0)?;
        let actual = fs::statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
            return Err(io::Error::other(
                "output directory identity changed; preserving recovery directory",
            ));
        }
        Ok(fs::unlinkat(&self.0, name, AtFlags::REMOVEDIR)?)
    }
}
