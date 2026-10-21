use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

struct TemporaryFile(PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Replace a file atomically, creating its contents with private permissions.
pub fn write_private_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file path has no parent"))?;
    let (temporary, mut file) = loop {
        let temporary = parent.join(format!(".tunmux-{:032x}.tmp", rand::random::<u128>()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => break (TemporaryFile(temporary), file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary.0, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn test_atomic_replace_is_private_and_does_not_follow_symlinks() {
        let dir =
            std::env::temp_dir().join(format!("tunmux-write-{:032x}", rand::random::<u128>()));
        fs::create_dir(&dir).unwrap();
        let target = dir.join("target");
        let path = dir.join("profile.conf");
        fs::write(&target, "original").unwrap();
        symlink(&target, &path).unwrap();
        write_private_atomic(&path, b"secret").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
        assert_eq!(fs::read_to_string(&path).unwrap(), "secret");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        write_private_atomic(&path, b"replacement").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "replacement");
        // A failed rename must remove the temporary file and preserve the destination.
        let destination = dir.join("directory");
        fs::create_dir(&destination).unwrap();
        assert!(write_private_atomic(&destination, b"failure").is_err());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 3);
        fs::remove_dir_all(dir).unwrap();
    }
}
