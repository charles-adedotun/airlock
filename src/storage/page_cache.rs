use crate::error::StorageError;
use std::fs::File;
use std::io::Result as IoResult;
use tokio::fs::File as TokioFile;

/// Drops pages from the OS page cache for the specified byte range of a file.
/// Cross-platform: uses `posix_fadvise` with `POSIX_FADV_DONTNEED` on Linux,
/// and is a safe no-op on macOS and other platforms.
pub fn posix_fadvise_dontneed(file: &File, offset: i64, len: i64) -> IoResult<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::fcntl::{PosixFadviseAdvice, posix_fadvise};
        use std::os::unix::io::AsRawFd;
        posix_fadvise(
            file.as_raw_fd(),
            offset as libc::off_t,
            len as libc::off_t,
            PosixFadviseAdvice::POSIX_FADV_DONTNEED,
        )
        .map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, offset, len);
    }
    Ok(())
}

/// Preallocates contiguous disk space for an open `tokio::fs::File`.
/// On Linux, uses `fallocate` to reserve physical blocks and avoid extent fragmentation.
/// Falls back to `file.set_len(size)` if unsupported or on macOS/other platforms.
pub async fn preallocate_file(file: &TokioFile, size: u64) -> Result<(), StorageError> {
    preallocate_file_with_path(file, size, "unspecified").await
}

/// Preallocates contiguous disk space with path metadata for descriptive error reporting.
pub async fn preallocate_file_with_path(
    file: &TokioFile,
    size: u64,
    path: &str,
) -> Result<(), StorageError> {
    if size == 0 {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        use nix::fcntl::{FallocateFlags, fallocate};
        use std::os::unix::io::AsRawFd;
        if let Err(err) = fallocate(
            file.as_raw_fd(),
            FallocateFlags::empty(),
            0,
            size as libc::off_t,
        ) {
            let raw_err = err as i32;
            if raw_err != libc::EOPNOTSUPP && raw_err != libc::ENOSYS {
                return Err(StorageError::FallocateFailed {
                    path: path.to_string(),
                    source: std::io::Error::from_raw_os_error(raw_err),
                });
            }
        } else {
            return Ok(());
        }
    }

    file.set_len(size)
        .await
        .map_err(|err| StorageError::FallocateFailed {
            path: path.to_string(),
            source: err,
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn test_preallocate_file() {
        let temp_dir = std::env::temp_dir();
        let test_path = temp_dir.join(format!("airlock_prealloc_test_{}.tmp", std::process::id()));

        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&test_path)
            .await
            .expect("Failed to create test file");

        let target_size = 1024 * 1024; // 1 MB
        let result = preallocate_file(&file, target_size).await;
        assert!(result.is_ok(), "Preallocate failed: {result:?}");

        let metadata = file.metadata().await.expect("Failed to get metadata");
        assert_eq!(metadata.len(), target_size);

        drop(file);
        let _ = tokio::fs::remove_file(&test_path).await;
    }

    #[test]
    fn test_posix_fadvise_dontneed() {
        let temp_dir = std::env::temp_dir();
        let test_path = temp_dir.join(format!("airlock_fadvise_test_{}.tmp", std::process::id()));

        {
            let mut file = std::fs::File::create(&test_path).expect("Failed to create test file");
            file.write_all(&[0u8; 4096]).expect("Failed to write bytes");
            let result = posix_fadvise_dontneed(&file, 0, 4096);
            assert!(result.is_ok());
        }

        let _ = std::fs::remove_file(&test_path);
    }
}
