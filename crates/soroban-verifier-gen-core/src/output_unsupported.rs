use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::Path,
};
pub(crate) struct Dir;
fn unsupported<T>() -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "safe output publication is supported only on native Windows and Linux filesystems",
    ))
}
impl Dir {
    pub(crate) fn walk(_: &Path, _: bool) -> io::Result<Self> {
        unsupported()
    }
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        unsupported()
    }
    pub(crate) fn open_dir(&self, _: &OsStr) -> io::Result<Self> {
        unsupported()
    }
    pub(crate) fn open_owned_dir(&self, _: &OsStr) -> io::Result<Self> {
        unsupported()
    }
    pub(crate) fn create_dir(&self, _: &OsStr) -> io::Result<Self> {
        unsupported()
    }
    pub(crate) fn create_private_dir(&self, _: &OsStr) -> io::Result<Self> {
        unsupported()
    }
    pub(crate) fn entry_exists(&self, _: &OsStr) -> io::Result<bool> {
        unsupported()
    }
    pub(crate) fn open_file(&self, _: &OsStr) -> io::Result<File> {
        unsupported()
    }
    pub(crate) fn create_file(&self, _: &OsStr) -> io::Result<File> {
        unsupported()
    }
    pub(crate) fn entries(&self) -> io::Result<Vec<OsString>> {
        unsupported()
    }
    pub(crate) fn same_object(&self, _: &Dir) -> io::Result<bool> {
        unsupported()
    }
    pub(crate) fn rename(&self, _: &OsStr, _: &Dir, _: &OsStr) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn rename_directory(
        &self,
        _: &OsStr,
        _: &Dir,
        _: &Dir,
        _: &OsStr,
    ) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn remove_tree(&self, _: &OsStr) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn remove_empty_dir(&self, _: &OsStr, _: &Dir) -> io::Result<()> {
        unsupported()
    }
}
