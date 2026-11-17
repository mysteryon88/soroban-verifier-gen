use super::*;
use std::fs;

#[cfg(unix)]
pub(crate) fn link(target: &Path, path: &Path) {
    std::os::unix::fs::symlink(target, path).unwrap();
}
#[cfg(windows)]
pub(crate) fn link(target: &Path, path: &Path) {
    fs::create_dir(path).unwrap();
    junction_in_place(target, path);
}

#[cfg(windows)]
fn junction_in_place(target: &Path, path: &Path) {
    use std::{
        mem::{offset_of, size_of},
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        ptr,
    };
    use windows_sys::{
        Wdk::Storage::FileSystem::{REPARSE_DATA_BUFFER, REPARSE_DATA_BUFFER_0_1},
        Win32::{
            Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT},
            System::{
                IO::DeviceIoControl, Ioctl::FSCTL_SET_REPARSE_POINT,
                SystemServices::IO_REPARSE_TAG_MOUNT_POINT,
            },
        },
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap();
    let substitute: Vec<u16> = OsString::from(format!("\\??\\{}", target.display()))
        .encode_wide()
        .collect();
    let print: Vec<u16> = target.as_os_str().encode_wide().collect();
    let offset = offset_of!(REPARSE_DATA_BUFFER, Anonymous)
        + offset_of!(REPARSE_DATA_BUFFER_0_1, PathBuffer);
    let length = offset + (substitute.len() + print.len() + 2) * 2;
    let mut storage = vec![0u64; length.max(size_of::<REPARSE_DATA_BUFFER>()).div_ceil(8)];
    // SAFETY: aligned allocation covers the fixed native record and both terminated UTF-16 tails.
    unsafe {
        let info = &mut *storage.as_mut_ptr().cast::<REPARSE_DATA_BUFFER>();
        info.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
        info.ReparseDataLength = (length - offset_of!(REPARSE_DATA_BUFFER, Anonymous)) as u16;
        let mount = &mut info.Anonymous.MountPointReparseBuffer;
        mount.SubstituteNameLength = (substitute.len() * 2) as u16;
        mount.PrintNameOffset = ((substitute.len() + 1) * 2) as u16;
        mount.PrintNameLength = (print.len() * 2) as u16;
        let buffer = storage.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>();
        ptr::copy_nonoverlapping(substitute.as_ptr(), buffer, substitute.len());
        ptr::copy_nonoverlapping(
            print.as_ptr(),
            buffer.add(substitute.len() + 1),
            print.len(),
        );
        let mut returned = 0;
        assert_ne!(
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_SET_REPARSE_POINT,
                storage.as_ptr().cast(),
                length as u32,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut()
            ),
            0,
            "{}",
            io::Error::last_os_error()
        );
    }
}

#[test]
fn raced_empty_directory_and_file_are_never_replaced() {
    let p = tempfile::tempdir().unwrap();
    for file in [false, true] {
        let out = p.path().join(if file { "file" } else { "directory" });
        let output = Output::new(&out).unwrap();
        output.write("new", b"generated").unwrap();
        if file {
            fs::write(&out, "racer").unwrap();
        } else {
            fs::create_dir(&out).unwrap();
        }
        assert!(output.publish(false, |_| Ok(())).is_err());
        if file {
            assert_eq!(fs::read(&out).unwrap(), b"racer");
        } else {
            assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
        }
    }
}

#[test]
fn two_publishers_have_exactly_one_winner() {
    let p = tempfile::tempdir().unwrap();
    let out = p.path().join("out");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|i| {
            let out = out.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let output = Output::new(&out).unwrap();
                output.write("winner", &[i]).unwrap();
                barrier.wait();
                output.publish(false, |_| Ok(())).is_ok()
            })
        })
        .collect();
    let winners = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .filter(|won| *won)
        .count();
    assert_eq!(winners, 1);
    assert_eq!(fs::read(out.join("winner")).unwrap().len(), 1);
}

#[test]
fn traversal_is_rejected_before_missing_ancestors_are_created() {
    let p = tempfile::tempdir().unwrap();
    assert!(Output::new(&p.path().join("missing/../out")).is_err());
    assert!(!p.path().join("missing").exists());
    assert_eq!(fs::read_dir(p.path()).unwrap().count(), 0);
    assert!(Output::new(Path::new(".")).is_err());
}

#[test]
fn missing_output_and_ordinary_force_work() {
    let p = tempfile::tempdir().unwrap();
    let out = p.path().join("nested/out");
    let output = Output::new(&out).unwrap();
    output.write("sources/new", b"first").unwrap();
    assert!(output.write("sources/new", b"overwrite").is_err());
    output.publish(false, |d| d.validate_tree()).unwrap();
    let output = Output::new(&out).unwrap();
    output.write("new", b"second").unwrap();
    output.publish(true, |d| d.validate_tree()).unwrap();
    assert_eq!(fs::read(out.join("new")).unwrap(), b"second");
    assert!(!out.join("sources").exists());
}

#[test]
fn raced_symlink_never_changes_external_data() {
    let p = tempfile::tempdir().unwrap();
    let external = p.path().join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("sentinel"), "keep").unwrap();
    let out = p.path().join("out");
    let output = Output::new(&out).unwrap();
    output.write("sentinel", b"new").unwrap();
    link(&external, &out);
    assert!(output.publish(false, |_| Ok(())).is_err());
    assert_eq!(fs::read(external.join("sentinel")).unwrap(), b"keep");
    assert!(fs::symlink_metadata(out).unwrap().file_type().is_symlink());
}

#[test]
fn ancestor_and_staging_swaps_cannot_redirect_io_or_cleanup() {
    let p = tempfile::tempdir().unwrap();
    let external = p.path().join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("sentinel"), "keep").unwrap();
    for staging in [false, true] {
        let ancestor = p
            .path()
            .join(if staging { "stage-parent" } else { "ancestor" });
        fs::create_dir(&ancestor).unwrap();
        let out = ancestor.join("out");
        let output = Output::new(&out).unwrap();
        let replaced = if staging {
            output.recovery.clone()
        } else {
            ancestor.clone()
        };
        let moved = p.path().join(if staging {
            "moved-stage"
        } else {
            "moved-parent"
        });
        let swapped = match fs::rename(&replaced, &moved) {
            Ok(()) => {
                link(&external, &replaced);
                true
            }
            // Windows can deny ancestor renames while descendant handles remain open.
            #[cfg(windows)]
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => false,
            Err(e) => panic!("ancestor swap failed unexpectedly: {e}"),
        };
        output.write("sentinel", b"generated").unwrap();
        let _ = output.publish(false, |_| Ok(()));
        assert_eq!(fs::read(external.join("sentinel")).unwrap(), b"keep");
        assert_eq!(fs::read_dir(&external).unwrap().count(), 1);
        if swapped {
            assert!(
                fs::symlink_metadata(&replaced)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
    }
}

#[test]
fn staging_child_symlink_is_not_followed() {
    let p = tempfile::tempdir().unwrap();
    let external = p.path().join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("sentinel"), "keep").unwrap();
    let output = Output::new(&p.path().join("out")).unwrap();
    link(&external, &output.recovery.join("output/sources"));
    assert!(output.write("sources/sentinel", b"destroyed").is_err());
    assert_eq!(fs::read(external.join("sentinel")).unwrap(), b"keep");
}

#[cfg(windows)]
#[test]
fn in_place_reparse_mutation_cannot_redirect_pinned_directory_io() {
    let p = tempfile::tempdir().unwrap();
    let external = p.path().join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("sentinel"), "keep").unwrap();
    let output = Output::new(&p.path().join("out")).unwrap();
    junction_in_place(&external, &output.recovery.join("output"));
    let _ = output.write("sentinel", b"destroyed");
    assert_eq!(fs::read(external.join("sentinel")).unwrap(), b"keep");
    assert_eq!(fs::read_dir(&external).unwrap().count(), 1);
}

#[test]
fn failed_commit_restores_old_output_and_rollback_collision_preserves_both() {
    let p = tempfile::tempdir().unwrap();
    for collision in [false, true] {
        let out = p
            .path()
            .join(if collision { "collision" } else { "restore" });
        fs::create_dir(&out).unwrap();
        fs::write(out.join("old"), "keep").unwrap();
        let output = Output::new(&out).unwrap();
        let backup = output.backup(true, |d| d.validate_tree()).unwrap();
        if collision {
            fs::create_dir(&out).unwrap();
        }
        let error = if collision {
            output.commit(backup).unwrap_err()
        } else {
            output
                .rollback(
                    io::Error::other("simulated commit failure"),
                    backup.as_ref(),
                )
                .unwrap_err()
        };
        if collision {
            assert!(error.to_string().contains("previous output preserved"));
            assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
            assert_eq!(
                fs::read(output.recovery.join("previous-output/old")).unwrap(),
                b"keep"
            );
        } else {
            assert_eq!(fs::read(out.join("old")).unwrap(), b"keep");
        }
    }
}

#[test]
fn replaced_regular_staging_directory_cannot_choose_published_data() {
    let p = tempfile::tempdir().unwrap();
    let out = p.path().join("out");
    let output = Output::new(&out).unwrap();
    let generated_path = output.recovery.join("output");
    fs::rename(&generated_path, output.recovery.join("original")).unwrap();
    fs::create_dir(&generated_path).unwrap();
    fs::write(generated_path.join("sentinel"), "unrelated").unwrap();
    output.write("expected", b"generated").unwrap();
    let _ = output.commit(None);
    assert!(!out.join("sentinel").exists());
    assert_eq!(
        fs::read(generated_path.join("sentinel")).unwrap(),
        b"unrelated"
    );
    if out.exists() {
        assert_eq!(fs::read(out.join("expected")).unwrap(), b"generated");
    } else {
        assert_eq!(
            fs::read(output.recovery.join("original/expected")).unwrap(),
            b"generated"
        );
    }
}

#[test]
fn force_validates_the_actual_target_moved_to_backup() {
    let p = tempfile::tempdir().unwrap();
    let out = p.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("sentinel"), "old").unwrap();
    let output = Output::new(&out).unwrap();
    output.write("new", b"generated").unwrap();
    let original = p.path().join("original");
    fs::rename(&out, &original).unwrap();
    fs::create_dir(&out).unwrap();
    fs::write(out.join("sentinel"), "concurrent").unwrap();
    assert!(
        output
            .publish(true, |dir| {
                if dir.open_file(OsStr::new("sentinel"))?.metadata()?.len() != 3 {
                    return Err(io::Error::other("unvalidated raced target"));
                }
                Ok(())
            })
            .is_err()
    );
    assert_eq!(fs::read(original.join("sentinel")).unwrap(), b"old");
    assert_eq!(fs::read(out.join("sentinel")).unwrap(), b"concurrent");
    assert!(!out.join("new").exists());
}

#[test]
fn preflight_existing_destination_has_no_filesystem_mutations() {
    let p = tempfile::tempdir().unwrap();
    let out = p.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("sentinel"), "keep").unwrap();
    assert!(Output::check_existing(&out, false, |_| Ok(())).is_err());
    assert_eq!(fs::read_dir(p.path()).unwrap().count(), 1);
    assert_eq!(fs::read(out.join("sentinel")).unwrap(), b"keep");
}

#[cfg(windows)]
#[test]
fn private_staging_does_not_inherit_parent_access() {
    use std::{
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, SE_DACL_PROTECTED,
        },
        Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS,
    };
    let p = tempfile::tempdir().unwrap();
    let output = Output::new(&p.path().join("out")).unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&output.recovery)
        .unwrap();
    let mut descriptor = ptr::null_mut();
    let mut acl = ptr::null_mut();
    // SAFETY: valid directory handle, writable output pointers, descriptor freed below.
    unsafe {
        assert_eq!(
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor
            ),
            0
        );
        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            GetSecurityDescriptorControl(descriptor, &mut control, &mut revision),
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        assert!(!acl.is_null());
        assert_eq!((*acl).AceCount, 2);
        LocalFree(descriptor);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn unsupported_filesystem_never_moves_or_deletes_existing_output() {
    let p = tempfile::tempdir().unwrap();
    let out = p.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("sentinel"), "keep").unwrap();
    let output = match Output::new(&out) {
        Ok(output) => output,
        Err(error) => {
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(fs::read(out.join("sentinel")).unwrap(), b"keep");
            assert!(!out.join("new").exists());
            return;
        }
    };
    output.write("new", b"generated").unwrap();
    match output.publish(true, |d| d.validate_tree()) {
        Ok(()) => assert_eq!(fs::read(out.join("new")).unwrap(), b"generated"),
        Err(e) => {
            assert_eq!(e.kind(), io::ErrorKind::Unsupported);
            assert_eq!(fs::read(out.join("sentinel")).unwrap(), b"keep");
            assert!(!out.join("new").exists());
        }
    }
}

#[test]
fn symlink_ancestor_is_rejected_before_creating_staging() {
    let p = tempfile::tempdir().unwrap();
    let external = p.path().join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("sentinel"), "keep").unwrap();
    let ancestor = p.path().join("ancestor");
    link(&external, &ancestor);
    assert!(Output::new(&ancestor.join("out")).is_err());
    assert_eq!(fs::read_dir(&external).unwrap().count(), 1);
    assert_eq!(fs::read(external.join("sentinel")).unwrap(), b"keep");
}

#[cfg(windows)]
#[test]
fn windows_aliases_and_unsafe_component_spellings_are_rejected_before_mutation() {
    let cwd = std::env::current_dir().unwrap();
    assert!(validate_path(&PathBuf::from(format!(r"\\?\{}", cwd.display()))).is_err());
    let p = tempfile::tempdir().unwrap();
    for spelling in ["bad.", "bad ", "bad:stream"] {
        assert!(Output::new(&p.path().join("missing").join(spelling).join("out")).is_err());
        assert!(!p.path().join("missing").exists());
    }
}

#[test]
fn protected_directory_identity_refuses_aliases_and_actual_backup() {
    let p = tempfile::tempdir().unwrap();
    let out = p.path().join("protected");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("sentinel"), "keep").unwrap();
    let protected = Dir::walk(&out, false).unwrap();
    #[cfg(windows)]
    let alias = PathBuf::from(format!(r"\\?\{}", out.display()));
    #[cfg(not(windows))]
    let alias = out.clone();
    let aliased = Dir::walk(&alias, false).unwrap();
    assert!(ensure_not_protected(&aliased, &[protected]).is_err());
    let mut output = Output::new(&out).unwrap();
    output.protected.push(Dir::walk(&out, false).unwrap());
    output.write("new", b"generated").unwrap();
    assert!(output.publish(true, |_| Ok(())).is_err());
    assert_eq!(fs::read(out.join("sentinel")).unwrap(), b"keep");
    assert!(!out.join("new").exists());
}

#[cfg(target_os = "linux")]
mod linux_creation_boundary {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn unsafe_nonsticky_parent_is_rejected_before_creating_missing_components() {
        let p = tempfile::tempdir().unwrap();
        let unsafe_parent = p.path().join("unsafe");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        let result = Output::new(&unsafe_parent.join("missing/out"));
        let Err(error) = result else {
            panic!("accepted writable nonsticky parent");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(fs::read_dir(&unsafe_parent).unwrap().count(), 0);
    }

    #[test]
    fn preexisting_nested_directory_cannot_hide_an_unsafe_ancestor() {
        let p = tempfile::tempdir().unwrap();
        let unsafe_parent = p.path().join("unsafe");
        let nested = unsafe_parent.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        let result = Output::new(&nested.join("out"));
        let Err(error) = result else {
            panic!("accepted nested path through writable nonsticky ancestor");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(fs::read_dir(&unsafe_parent).unwrap().count(), 1);
        assert_eq!(fs::read_dir(&nested).unwrap().count(), 0);
    }

    #[test]
    fn already_opened_unsafe_directory_cannot_create_children() {
        let p = tempfile::tempdir().unwrap();
        let unsafe_parent = p.path().join("unsafe");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        let parent = Dir::walk(&unsafe_parent, false).unwrap();
        assert!(parent.create_private_dir(OsStr::new("child")).is_err());
        assert_eq!(fs::read_dir(&unsafe_parent).unwrap().count(), 0);
    }

    #[test]
    fn trusted_private_and_sticky_parents_allow_private_creation() {
        let p = tempfile::tempdir().unwrap();
        let uid = fs::metadata(p.path()).unwrap().uid();
        for mode in [0o700, 0o1777] {
            let parent = p.path().join(format!("parent-{mode:o}"));
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
            let out = parent.join("missing/out");
            let output = Output::new(&out).unwrap();
            let stage = fs::metadata(&output.recovery).unwrap();
            assert_eq!(stage.uid(), uid);
            assert_eq!(stage.mode() & 0o777, 0o700);
            let created_parent = fs::metadata(parent.join("missing")).unwrap();
            assert_eq!(created_parent.uid(), uid);
            assert_eq!(created_parent.mode() & 0o777, 0o700);
            output.write("new", b"generated").unwrap();
            output.publish(false, |_| Ok(())).unwrap();
            assert_eq!(fs::read(out.join("new")).unwrap(), b"generated");
            assert_eq!(fs::metadata(out.join("new")).unwrap().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn different_uid_sticky_owner_is_rejected_when_provisioned() {
        let Some(path) = std::env::var_os("VERIFIER_OTHER_UID_FIXTURE") else {
            return;
        };
        let path = PathBuf::from(path);
        let metadata = fs::metadata(&path).unwrap();
        let current_uid = fs::metadata(tempfile::tempdir().unwrap().path())
            .unwrap()
            .uid();
        assert_ne!(metadata.uid(), current_uid);
        assert_ne!(metadata.uid(), 0);
        assert_eq!(metadata.mode() & 0o7777, 0o1777);
        let result = Output::new(&path.join("missing/out"));
        let Err(error) = result else {
            panic!("accepted sticky parent owned by another UID");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
    }
}
