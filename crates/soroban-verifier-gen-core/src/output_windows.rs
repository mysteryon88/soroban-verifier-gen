use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io,
    mem::{offset_of, size_of},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, Prefix},
    ptr,
};
use windows_sys::{
    Wdk::{Foundation::OBJECT_ATTRIBUTES, Storage::FileSystem::*},
    Win32::{
        Foundation::{
            HANDLE, LocalFree, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError,
            STATUS_NO_MORE_FILES, UNICODE_STRING,
        },
        Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        },
        Storage::FileSystem::{
            DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FileIdInfo, GetFileInformationByHandleEx, GetVolumeInformationByHandleW,
        },
        System::{IO::IO_STATUS_BLOCK, SystemServices::FILE_PERSISTENT_ACLS},
    },
};

pub(crate) struct Dir(File);

fn status(value: i32) -> io::Result<()> {
    if value >= 0 {
        Ok(())
    } else {
        // SAFETY: pure NTSTATUS-to-Win32 error translation.
        Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(value) } as i32,
        ))
    }
}

fn name(value: &OsStr) -> io::Result<Vec<u16>> {
    let value: Vec<u16> = value.encode_wide().collect();
    if value.is_empty()
        || value.len() > 32760
        || value
            .iter()
            .any(|c| [0, b'/' as u16, b'\\' as u16, b':' as u16].contains(c))
        || value == [46]
        || value == [46, 46]
        || matches!(value.last(), Some(32 | 46))
    {
        return Err(io::Error::other("unsafe native output component"));
    }
    Ok(value)
}

impl Dir {
    pub(crate) fn walk(path: &Path, create: bool) -> io::Result<Self> {
        let mut parts = path.components();
        let Some(Component::Prefix(prefix)) = parts.next() else {
            return Err(io::Error::other("expected absolute local drive path"));
        };
        let drive = match prefix.kind() {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => d,
            _ => {
                return Err(io::Error::other(
                    "safe output does not support UNC/device paths",
                ));
            }
        };
        if !matches!(parts.next(), Some(Component::RootDir)) {
            return Err(io::Error::other("expected drive root"));
        }
        // This is the volume root only. Every mutable component below it uses NtCreateFile RootDirectory.
        let root = format!("{}:\\", drive as char);
        let mut current = Self(
            OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(root)?,
        );
        current.check_dir()?;
        for part in parts {
            let Component::Normal(part) = part else {
                return Err(io::Error::other("unsafe directory component"));
            };
            current = match current.open_dir(part) {
                Ok(d) => d,
                Err(e) if create && e.kind() == io::ErrorKind::NotFound => match current
                    .create_dir(part)
                {
                    Ok(d) => d,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => current.open_dir(part)?,
                    Err(e) => return Err(e),
                },
                Err(e) => return Err(e),
            };
        }
        let mut flags = 0;
        // SAFETY: live volume-directory handle and writable flags; optional string outputs omitted.
        if unsafe {
            GetVolumeInformationByHandleW(
                current.0.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut flags,
                ptr::null_mut(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if flags & FILE_PERSISTENT_ACLS == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "safe private staging requires persistent Windows ACLs",
            ));
        }
        Ok(current)
    }

    fn open(&self, part: &OsStr, options: u32, disposition: u32, access: u32) -> io::Result<File> {
        self.open_with_security(part, options, disposition, access, ptr::null_mut())
    }

    fn open_with_security(
        &self,
        part: &OsStr,
        options: u32,
        disposition: u32,
        access: u32,
        security: *mut std::ffi::c_void,
    ) -> io::Result<File> {
        let mut wide = name(part)?;
        let mut text = UNICODE_STRING {
            Length: (wide.len() * 2) as u16,
            MaximumLength: (wide.len() * 2) as u16,
            Buffer: wide.as_mut_ptr(),
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: self.0.as_raw_handle() as HANDLE,
            ObjectName: &mut text,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            SecurityDescriptor: security.cast(),
            SecurityQualityOfService: ptr::null_mut(),
        };
        let mut handle = ptr::null_mut();
        let mut ios = IO_STATUS_BLOCK::default();
        // SAFETY: strings, attributes and output buffers live through this synchronous call;
        // the single relative component cannot escape RootDirectory; reparses are rejected.
        status(unsafe {
            NtCreateFile(
                &mut handle,
                access,
                &attrs,
                &mut ios,
                ptr::null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                disposition,
                options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        })?;
        // SAFETY: successful NtCreateFile returned one newly owned handle.
        let file = unsafe { File::from_raw_handle(handle) };
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::other("reparse output component refused"));
        }
        Ok(file)
    }

    pub(crate) fn same_object(&self, other: &Dir) -> io::Result<bool> {
        fn id(file: &File) -> io::Result<(u64, [u8; 16])> {
            let mut info = FILE_ID_INFO::default();
            // SAFETY: live handle and correctly sized, initialized writable FILE_ID_INFO buffer.
            if unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle(),
                    FileIdInfo,
                    (&mut info as *mut FILE_ID_INFO).cast(),
                    size_of::<FILE_ID_INFO>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if info.FileId.Identifier == [0; 16] {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "filesystem does not expose stable directory identity",
                ));
            }
            Ok((info.VolumeSerialNumber, info.FileId.Identifier))
        }
        Ok(id(&self.0)? == id(&other.0)?)
    }
    fn check_dir(&self) -> io::Result<()> {
        let attrs = self.0.metadata()?.file_attributes();
        if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 || attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::other("unsafe output directory"));
        }
        Ok(())
    }
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }
    pub(crate) fn open_dir(&self, part: &OsStr) -> io::Result<Self> {
        Ok(Self(self.open(
            part,
            FILE_DIRECTORY_FILE,
            FILE_OPEN,
            FILE_GENERIC_READ,
        )?))
    }
    pub(crate) fn create_private_dir(&self, part: &OsStr) -> io::Result<Self> {
        // Protected DACL is applied atomically at creation; only owner and SYSTEM inherit access.
        let sddl: Vec<u16> = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)\0"
            .encode_utf16()
            .collect();
        let mut security = ptr::null_mut();
        // SAFETY: terminated SDDL and writable descriptor output; LocalFree releases the allocation below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut security,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let created = self
            .open_with_security(
                part,
                FILE_DIRECTORY_FILE,
                FILE_CREATE,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
                security,
            )
            .map(Self);
        // SAFETY: descriptor was allocated by the successful conversion above and is no longer in use.
        unsafe {
            LocalFree(security);
        }
        created
    }
    pub(crate) fn entry_exists(&self, part: &OsStr) -> io::Result<bool> {
        match self.open(part, 0, FILE_OPEN, FILE_GENERIC_READ) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
    pub(crate) fn open_owned_dir(&self, part: &OsStr) -> io::Result<Self> {
        Ok(Self(self.open(
            part,
            FILE_DIRECTORY_FILE,
            FILE_OPEN,
            FILE_GENERIC_READ | DELETE,
        )?))
    }
    pub(crate) fn create_dir(&self, part: &OsStr) -> io::Result<Self> {
        Ok(Self(self.open(
            part,
            FILE_DIRECTORY_FILE,
            FILE_CREATE,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
        )?))
    }
    pub(crate) fn open_file(&self, part: &OsStr) -> io::Result<File> {
        self.open(part, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_GENERIC_READ)
    }
    pub(crate) fn create_file(&self, part: &OsStr) -> io::Result<File> {
        self.open(
            part,
            FILE_NON_DIRECTORY_FILE,
            FILE_CREATE,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        )
    }

    pub(crate) fn entries(&self) -> io::Result<Vec<OsString>> {
        let mut result = Vec::new();
        let mut restart = true;
        loop {
            // u64 storage guarantees alignment of FILE_DIRECTORY_INFORMATION and its UTF-16 tail.
            let mut storage = vec![0u64; 8192];
            let mut ios = IO_STATUS_BLOCK::default();
            // SAFETY: aligned writable allocation, synchronous directory handle, no APC.
            let code = unsafe {
                NtQueryDirectoryFile(
                    self.0.as_raw_handle() as HANDLE,
                    ptr::null_mut(),
                    None,
                    ptr::null(),
                    &mut ios,
                    storage.as_mut_ptr().cast(),
                    (storage.len() * 8) as u32,
                    FileDirectoryInformation,
                    true,
                    ptr::null(),
                    restart,
                )
            };
            if code == STATUS_NO_MORE_FILES {
                break;
            }
            status(code)?;
            restart = false;
            // SAFETY: successful single-entry query initializes the fixed header and the returned tail.
            let info = unsafe { &*storage.as_ptr().cast::<FILE_DIRECTORY_INFORMATION>() };
            let offset = offset_of!(FILE_DIRECTORY_INFORMATION, FileName);
            if info.FileNameLength % 2 != 0
                || offset + info.FileNameLength as usize > ios.Information
            {
                return Err(io::Error::other("invalid native directory record"));
            }
            // SAFETY: length and allocation bounds checked above; tail is u16 aligned.
            let wide = unsafe {
                std::slice::from_raw_parts(
                    storage.as_ptr().cast::<u8>().add(offset).cast::<u16>(),
                    info.FileNameLength as usize / 2,
                )
            };
            let entry = OsString::from_wide(wide);
            if entry != "." && entry != ".." {
                result.push(entry);
            }
        }
        Ok(result)
    }

    pub(crate) fn rename(&self, old: &OsStr, destination: &Dir, new: &OsStr) -> io::Result<()> {
        let file = self.open(old, 0, FILE_OPEN, FILE_GENERIC_READ | DELETE)?;
        Self::rename_handle(&file, destination, new)
    }
    pub(crate) fn rename_directory(
        &self,
        _old: &OsStr,
        held: &Dir,
        destination: &Dir,
        new: &OsStr,
    ) -> io::Result<()> {
        Self::rename_handle(&held.0, destination, new)
    }
    fn rename_handle(file: &File, destination: &Dir, new: &OsStr) -> io::Result<()> {
        let wide = name(new)?;
        let offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
        let length = size_of::<FILE_RENAME_INFORMATION>() + wide.len() * 2;
        let mut storage = vec![
            0u64;
            length
                .div_ceil(8)
                .max(size_of::<FILE_RENAME_INFORMATION>().div_ceil(8))
        ];
        // SAFETY: aligned allocation large enough for struct and complete variable UTF-16 tail.
        unsafe {
            let info = &mut *storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
            info.Anonymous.ReplaceIfExists = false;
            info.RootDirectory = destination.0.as_raw_handle() as HANDLE;
            info.FileNameLength = (wide.len() * 2) as u32;
            ptr::copy_nonoverlapping(
                wide.as_ptr(),
                storage.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
                wide.len(),
            );
            let mut ios = IO_STATUS_BLOCK::default();
            status(NtSetInformationFile(
                file.as_raw_handle() as HANDLE,
                &mut ios,
                storage.as_ptr().cast(),
                length as u32,
                FileRenameInformation,
            ))
        }
    }

    fn delete(file: &File) -> io::Result<()> {
        let info = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
        let mut ios = IO_STATUS_BLOCK::default();
        // SAFETY: fixed initialized buffer; deletion refers to the opened object itself.
        status(unsafe {
            NtSetInformationFile(
                file.as_raw_handle() as HANDLE,
                &mut ios,
                (&info as *const FILE_DISPOSITION_INFORMATION).cast(),
                size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                FileDispositionInformation,
            )
        })
    }
    pub(crate) fn remove_tree(&self, part: &OsStr) -> io::Result<()> {
        let file = self.open(part, 0, FILE_OPEN, FILE_GENERIC_READ | DELETE)?;
        if file.metadata()?.is_dir() {
            let dir = Self(file);
            for child in dir.entries()? {
                dir.remove_tree(&child)?;
            }
            Self::delete(&dir.0)
        } else {
            Self::delete(&file)
        }
    }
    pub(crate) fn remove_empty_dir(&self, _part: &OsStr, dir: &Dir) -> io::Result<()> {
        Self::delete(&dir.0)
    }
}
