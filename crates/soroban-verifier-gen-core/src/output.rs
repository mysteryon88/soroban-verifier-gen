//! Private handle-relative output transaction; no replacing-rename fallback.
use std::{
    ffi::{OsStr, OsString},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
#[cfg(target_os = "linux")]
#[path = "output_linux.rs"]
mod native;
#[cfg(windows)]
#[path = "output_windows.rs"]
mod native;
#[cfg(not(any(windows, target_os = "linux")))]
#[path = "output_unsupported.rs"]
mod native;
pub(crate) use native::Dir;
static SERIAL: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Output {
    parent: Dir,
    stage: Dir,
    generated: Dir,
    name: OsString,
    stage_name: OsString,
    recovery: PathBuf,
    protected: Vec<Dir>,
}

pub(crate) fn validate_path(path: &Path) -> io::Result<PathBuf> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(io::Error::other(
            "unsafe output directory: parent traversal is not allowed",
        ));
    }
    let cwd = std::env::current_dir()?;
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    };
    #[cfg(windows)]
    let absolute = {
        use std::path::Prefix;
        let mut components = absolute.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(io::Error::other("expected local drive path"));
        };
        let drive = match prefix.kind() {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => d,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "UNC/device output paths are unsupported",
                ));
            }
        };
        if !matches!(components.next(), Some(Component::RootDir)) {
            return Err(io::Error::other("drive-relative output paths are unsafe"));
        }
        let mut normalized = PathBuf::from(format!("{}:\\", drive as char));
        for component in components {
            match component {
                Component::CurDir => (),
                Component::Normal(name) => {
                    let text = name.to_string_lossy();
                    if text.ends_with(['.', ' ']) || text.contains(':') {
                        return Err(io::Error::other("unsafe Windows path component"));
                    }
                    normalized.push(name);
                }
                _ => return Err(io::Error::other("unsafe output component")),
            }
        }
        normalized
    };
    let absolute: PathBuf = absolute
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect();
    #[cfg(windows)]
    let ancestor = cwd
        .to_string_lossy()
        .to_lowercase()
        .starts_with(&(absolute.to_string_lossy().to_lowercase() + "\\"))
        || cwd
            .to_string_lossy()
            .eq_ignore_ascii_case(&absolute.to_string_lossy());
    #[cfg(not(windows))]
    let ancestor = cwd.starts_with(&absolute);
    if absolute.file_name().is_none() || ancestor {
        return Err(io::Error::other(
            "unsafe output directory: refusing root, cwd or cwd ancestor",
        ));
    }
    Ok(absolute)
}

fn protected_directories() -> io::Result<Vec<Dir>> {
    std::env::current_dir()?
        .ancestors()
        .map(|path| Dir::walk(path, false))
        .collect()
}

fn ensure_not_protected(target: &Dir, protected: &[Dir]) -> io::Result<()> {
    for directory in protected {
        if target.same_object(directory)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe output: directory is cwd or a cwd ancestor",
            ));
        }
    }
    Ok(())
}

impl Output {
    pub(crate) fn new(path: &Path) -> io::Result<Self> {
        let path = validate_path(path)?;
        let name = path.file_name().unwrap().to_owned();
        let protected = protected_directories()?;
        let parent = Dir::walk(path.parent().unwrap(), true)?;
        for _ in 0..32 {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let stage_name = OsString::from(format!(
                ".verifier-stage-{}-{nonce}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            match parent.create_private_dir(&stage_name) {
                Ok(stage) => {
                    let generated = stage.create_dir(OsStr::new("output"))?;
                    let recovery = path.parent().unwrap().join(&stage_name);
                    return Ok(Self {
                        parent,
                        stage,
                        generated,
                        name,
                        stage_name,
                        recovery,
                        protected,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other(
            "cannot allocate private output staging directory",
        ))
    }

    pub(crate) fn check_existing(
        path: &Path,
        force: bool,
        guard: impl FnOnce(&Dir) -> io::Result<()>,
    ) -> io::Result<()> {
        let path = validate_path(path)?;
        let parent = match Dir::walk(path.parent().unwrap(), false) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let name = path.file_name().unwrap();
        if !force {
            return if parent.entry_exists(name)? {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "output directory already exists; use --force to replace it",
                ))
            } else {
                Ok(())
            };
        }
        match parent.open_dir(name) {
            Ok(dir) => {
                ensure_not_protected(&dir, &protected_directories()?)?;
                guard(&dir)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn write(&self, path: &str, bytes: &[u8]) -> io::Result<()> {
        self.write_inner(path, bytes)
            .map_err(|e| self.with_recovery(e))
    }

    fn write_inner(&self, path: &str, bytes: &[u8]) -> io::Result<()> {
        let mut dir = self.generated.try_clone()?;
        let mut parts = Path::new(path).components().peekable();
        while let Some(component) = parts.next() {
            let Component::Normal(name) = component else {
                return Err(io::Error::other("invalid generated filename"));
            };
            if parts.peek().is_none() {
                let mut file = dir.create_file(name)?;
                file.write_all(bytes)?;
                file.sync_all()?;
            } else {
                dir = match dir.open_dir(name) {
                    Ok(d) => d,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => dir.create_dir(name)?,
                    Err(e) => return Err(e),
                };
            }
        }
        Ok(())
    }

    pub(crate) fn publish(
        self,
        force: bool,
        guard: impl FnOnce(&Dir) -> io::Result<()>,
    ) -> io::Result<()> {
        let result = self
            .backup(force, guard)
            .and_then(|backup| self.commit(backup));
        result.map_err(|e| self.with_recovery(e))
    }

    fn backup(
        &self,
        force: bool,
        guard: impl FnOnce(&Dir) -> io::Result<()>,
    ) -> io::Result<Option<Dir>> {
        if !force {
            return Ok(None);
        }
        match self
            .parent
            .rename(&self.name, &self.stage, OsStr::new("previous-output"))
        {
            Ok(()) => {
                // Inspect the object actually moved, not a previously checked pathname.
                match self.stage.open_owned_dir(OsStr::new("previous-output")) {
                    Ok(dir) => match ensure_not_protected(&dir, &self.protected)
                        .and_then(|()| guard(&dir))
                    {
                        Ok(()) => Ok(Some(dir)),
                        Err(e) => self.rollback(e, Some(&dir)).map(|()| None),
                    },
                    Err(e) => self.rollback(e, None).map(|()| None),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn commit(&self, backup: Option<Dir>) -> io::Result<()> {
        if let Err(e) = self.stage.rename_directory(
            OsStr::new("output"),
            &self.generated,
            &self.parent,
            &self.name,
        ) {
            return if backup.is_some() {
                self.rollback(e, backup.as_ref())
            } else {
                Err(e)
            };
        }
        let published = self.parent.open_dir(&self.name)?;
        if !published.same_object(&self.generated)? {
            return Err(io::Error::other(
                "staging identity changed; preserving recovery directory",
            ));
        }
        if let Some(backup) = backup {
            // Never reopen a mutable backup name to choose the tree being deleted.
            for name in backup.entries()? {
                backup.remove_tree(&name)?;
            }
            self.stage
                .remove_empty_dir(OsStr::new("previous-output"), &backup)?;
        }
        self.parent.remove_empty_dir(&self.stage_name, &self.stage)
    }

    fn with_recovery(&self, error: io::Error) -> io::Error {
        io::Error::new(
            error.kind(),
            format!(
                "{error}; inspect retained staging at last known path {}",
                self.recovery.display()
            ),
        )
    }

    fn rollback(&self, failure: io::Error, backup: Option<&Dir>) -> io::Result<()> {
        let restored = match backup {
            Some(dir) => self.stage.rename_directory(
                OsStr::new("previous-output"),
                dir,
                &self.parent,
                &self.name,
            ),
            None => self
                .stage
                .rename(OsStr::new("previous-output"), &self.parent, &self.name),
        };
        match restored {
            Ok(()) => Err(failure),
            Err(e) => Err(io::Error::other(format!(
                "{failure}; rollback refused ({e}); previous output preserved at {}",
                self.recovery.join("previous-output").display()
            ))),
        }
    }
}

impl Dir {
    pub(crate) fn validate_tree(&self) -> io::Result<()> {
        fn visit(dir: &Dir, depth: usize, remaining: &mut usize) -> io::Result<()> {
            if depth > 64 {
                return Err(io::Error::other("output tree too deep"));
            }
            for name in dir.entries()? {
                *remaining = remaining
                    .checked_sub(1)
                    .ok_or_else(|| io::Error::other("output tree too large"))?;
                match dir.open_dir(&name) {
                    Ok(child) => visit(&child, depth + 1, remaining)?,
                    Err(_) => {
                        let file = dir.open_file(&name)?;
                        if !file.metadata()?.is_file() {
                            return Err(io::Error::other("special output file refused"));
                        }
                    }
                }
            }
            Ok(())
        }
        visit(self, 0, &mut 100_000)
    }
}

#[cfg(all(test, any(windows, target_os = "linux")))]
#[path = "output_tests.rs"]
pub(crate) mod tests;
