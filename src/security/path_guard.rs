use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PathGuardError {
    #[error("Path traversal detected: target path escapes base cache directory")]
    TraversalDetected,
    #[error("Invalid extension: contains path separators or invalid characters")]
    InvalidExtension,
    #[error("Base cache directory error: {0}")]
    DirectoryError(String),
}

/// Derives a deterministic hex-encoded SHA-256 digest from a stream ID or URL.
///
/// Because SHA-256 outputs a rigid 64-character lowercase hexadecimal string (`[0-9a-f]{64}`),
/// it is physically impossible for the returned string to contain path traversal characters
/// (`../`, `..\`, null bytes, slashes, or special control characters).
pub fn hash_stream_id(stream_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(stream_id.as_bytes());
    hex::encode(hasher.finalize())
}

/// Validates file extension to ensure it does not contain path separators or illegal characters.
fn sanitize_extension(ext: &str) -> Result<&str, PathGuardError> {
    let trimmed = ext.trim_start_matches('.');
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('\0')
    {
        return Err(PathGuardError::InvalidExtension);
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(PathGuardError::InvalidExtension);
    }
    Ok(trimmed)
}

/// Safe cache path manager that anchors all cached files inside a validated directory.
#[derive(Debug, Clone)]
pub struct SafePathGuard {
    base_dir: PathBuf,
}

impl SafePathGuard {
    /// Initializes a `SafePathGuard` anchored at the specified directory.
    /// Creates the directory if it does not exist and resolves its canonical path.
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self, PathGuardError> {
        let path = base_dir.as_ref();
        std::fs::create_dir_all(path).map_err(|e| PathGuardError::DirectoryError(e.to_string()))?;

        let canonical_base =
            dunce::canonicalize(path).map_err(|e| PathGuardError::DirectoryError(e.to_string()))?;

        Ok(Self {
            base_dir: canonical_base,
        })
    }

    /// Returns the canonical base directory path.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Computes the safe path for an in-flight `.mp4.part` download.
    pub fn part_path(&self, stream_id: &str) -> Result<PathBuf, PathGuardError> {
        self.part_path_with_ext(stream_id, "mp4")
    }

    /// Computes the safe path for a completed `.mp4` file.
    pub fn final_path(&self, stream_id: &str) -> Result<PathBuf, PathGuardError> {
        self.final_path_with_ext(stream_id, "mp4")
    }

    /// Computes the safe path for an in-flight `.part` download with a custom extension.
    pub fn part_path_with_ext(
        &self,
        stream_id: &str,
        ext: &str,
    ) -> Result<PathBuf, PathGuardError> {
        let clean_ext = sanitize_extension(ext)?;
        let safe_key = hash_stream_id(stream_id);
        let filename = format!("{safe_key}.{clean_ext}.part");
        let target = self.base_dir.join(filename);

        if !target.starts_with(&self.base_dir) {
            return Err(PathGuardError::TraversalDetected);
        }

        Ok(target)
    }

    /// Computes the safe path for a completed file with a custom extension.
    pub fn final_path_with_ext(
        &self,
        stream_id: &str,
        ext: &str,
    ) -> Result<PathBuf, PathGuardError> {
        let clean_ext = sanitize_extension(ext)?;
        let safe_key = hash_stream_id(stream_id);
        let filename = format!("{safe_key}.{clean_ext}");
        let target = self.base_dir.join(filename);

        if !target.starts_with(&self.base_dir) {
            return Err(PathGuardError::TraversalDetected);
        }

        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_test_dir(sub: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("airlock_test_cache_{}_{}", std::process::id(), sub));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_hash_stream_id_deterministic() {
        let id = "10492_sintel_trailer";
        let hash1 = hash_stream_id(id);
        let hash2 = hash_stream_id(id);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_prevents_directory_traversal() {
        let temp_dir = temp_test_dir("traversal");
        let guard = SafePathGuard::new(&temp_dir).unwrap();

        // Malicious stream IDs attempting relative and absolute traversals
        let attack_ids = vec![
            "../../../../etc/passwd",
            "../../.ssh/authorized_keys",
            "/root/.bashrc",
            "C:\\Windows\\System32\\calc.exe",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "stream\0evil",
            "../../../../../var/run/docker.sock",
        ];

        for attack_id in attack_ids {
            let part_path = guard.part_path(attack_id).unwrap();
            let final_path = guard.final_path(attack_id).unwrap();

            // Assert that the generated path is strictly inside base_dir
            assert!(part_path.starts_with(guard.base_dir()));
            assert!(final_path.starts_with(guard.base_dir()));

            // Assert the filename is hex-encoded and does not contain traversal dots
            let filename = part_path.file_name().unwrap().to_str().unwrap();
            assert!(!filename.contains(".."));
            assert!(!filename.contains("passwd"));
            assert!(!filename.contains("authorized_keys"));
            assert!(filename.ends_with(".mp4.part"));
        }

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_custom_extensions() {
        let temp_dir = temp_test_dir("extensions");
        let guard = SafePathGuard::new(&temp_dir).unwrap();

        let ts_part = guard.part_path_with_ext("stream_123", "ts").unwrap();
        assert!(ts_part.to_str().unwrap().ends_with(".ts.part"));

        let ts_final = guard.final_path_with_ext("stream_123", "ts").unwrap();
        assert!(ts_final.to_str().unwrap().ends_with(".ts"));

        // Reject dangerous extensions
        assert!(guard.part_path_with_ext("stream_123", "../exe").is_err());
        assert!(guard.part_path_with_ext("stream_123", "mp4/evil").is_err());
        assert!(guard.part_path_with_ext("stream_123", "mp4\0evil").is_err());

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
