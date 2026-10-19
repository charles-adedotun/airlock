use crate::error::StorageError;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;

/// Segment identifier for cached chunks or files.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct SegmentId(pub String);

impl From<String> for SegmentId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SegmentId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::fmt::Display for SegmentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for SegmentId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl SegmentId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for SegmentId {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Metadata describing a cached media segment.
#[derive(Debug, Clone)]
pub struct SegmentMeta {
    pub id: SegmentId,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub created_at: SystemTime,
    pub last_accessed_at: SystemTime,
}

/// Configuration for the rolling storage window and disk protection.
#[derive(Debug, Clone)]
pub struct QuotaConfig {
    /// Minimum rolling storage threshold (default: 50 GB). Eviction prunes down towards this target.
    pub min_cache_bytes: u64,
    /// Maximum rolling storage ceiling (default: 200 GB). Eviction triggers when exceeded.
    pub max_cache_bytes: u64,
    /// Emergency minimum free disk floor (default: 10 GB). If the filesystem drops below this, writes halt.
    pub emergency_disk_floor_bytes: u64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            min_cache_bytes: 50 * 1024 * 1024 * 1024,            // 50 GB
            max_cache_bytes: 200 * 1024 * 1024 * 1024,           // 200 GB
            emergency_disk_floor_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
        }
    }
}

/// Eviction ordering strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionPolicy {
    /// Evict least recently accessed segments first (LRU).
    Lru,
    /// Evict oldest created segments first (FIFO).
    Fifo,
}

/// Snapshot of disk and cache usage metrics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiskUsageInfo {
    pub available_disk_bytes: u64,
    pub cache_used_bytes: u64,
    pub pinned_bytes: u64,
    pub pinned_count: usize,
    pub total_segments_count: usize,
}

/// Core Quota Manager tracking segments, enforcing rolling cache limits, and protecting pinned items.
pub struct QuotaManager {
    config: QuotaConfig,
    segments: HashMap<SegmentId, SegmentMeta>,
    pinned_segments: HashSet<SegmentId>,
    total_cache_bytes: u64,
}

impl QuotaManager {
    /// Creates a new QuotaManager with the provided configuration.
    pub fn new(config: QuotaConfig) -> Self {
        Self {
            config,
            segments: HashMap::new(),
            pinned_segments: HashSet::new(),
            total_cache_bytes: 0,
        }
    }

    /// Accessor for configuration.
    pub fn config(&self) -> &QuotaConfig {
        &self.config
    }

    /// Total cache bytes actively tracked.
    pub fn total_cache_bytes(&self) -> u64 {
        self.total_cache_bytes
    }

    /// Pins a segment by its ID, guaranteeing it will never be removed by eviction.
    pub fn pin_segment(&mut self, id: SegmentId) {
        self.pinned_segments.insert(id);
    }

    /// Unpins a segment by its ID, allowing future eviction if storage quota is exceeded.
    pub fn unpin_segment(&mut self, id: &SegmentId) -> bool {
        self.pinned_segments.remove(id)
    }

    /// Checks if a segment is currently pinned.
    pub fn is_pinned(&self, id: &SegmentId) -> bool {
        self.pinned_segments.contains(id)
    }

    /// Returns the number of currently pinned segments.
    pub fn pinned_count(&self) -> usize {
        self.pinned_segments.len()
    }

    /// Returns the total byte size of all currently pinned segments.
    pub fn pinned_bytes(&self) -> u64 {
        self.pinned_segments
            .iter()
            .filter_map(|id| self.segments.get(id))
            .map(|meta| meta.size_bytes)
            .sum()
    }

    /// Updates the `last_accessed_at` timestamp for a segment (for LRU tracking).
    pub fn touch_segment(&mut self, id: &SegmentId) {
        if let Some(meta) = self.segments.get_mut(id) {
            meta.last_accessed_at = SystemTime::now();
        }
    }

    /// Registers a new segment into tracking.
    /// If the new addition causes the cache to exceed `max_cache_bytes`,
    /// unpinned segments will be evicted down to `min_cache_bytes`.
    /// Returns the list of evicted segments that should be removed from disk.
    pub fn register_segment(
        &mut self,
        meta: SegmentMeta,
        policy: EvictionPolicy,
    ) -> Result<Vec<SegmentMeta>, StorageError> {
        let incoming_size = meta.size_bytes;
        let mut evicted = Vec::new();

        // Check if adding this segment would exceed max cache quota
        if self.total_cache_bytes.saturating_add(incoming_size) > self.config.max_cache_bytes {
            let target = self.config.min_cache_bytes.saturating_sub(incoming_size);
            evicted = self.evict_to_target(target, policy);

            // If even after evicting unpinned items we still exceed max limit
            if self.total_cache_bytes.saturating_add(incoming_size) > self.config.max_cache_bytes {
                return Err(StorageError::QuotaExceeded {
                    used_bytes: self.total_cache_bytes.saturating_add(incoming_size),
                    limit_bytes: self.config.max_cache_bytes,
                });
            }
        }

        // If replacing an existing segment, adjust total_cache_bytes
        if let Some(old) = self.segments.insert(meta.id.clone(), meta) {
            self.total_cache_bytes = self
                .total_cache_bytes
                .saturating_sub(old.size_bytes)
                .saturating_add(incoming_size);
        } else {
            self.total_cache_bytes = self.total_cache_bytes.saturating_add(incoming_size);
        }

        Ok(evicted)
    }

    /// Removes a segment from tracking and returns its metadata.
    pub fn remove_segment(&mut self, id: &SegmentId) -> Option<SegmentMeta> {
        self.pinned_segments.remove(id);
        if let Some(meta) = self.segments.remove(id) {
            self.total_cache_bytes = self.total_cache_bytes.saturating_sub(meta.size_bytes);
            Some(meta)
        } else {
            None
        }
    }

    /// Evicts unpinned segments according to the specified policy until total cache bytes <= target_bytes.
    /// Pinned segments are NEVER evicted.
    pub fn evict_to_target(
        &mut self,
        target_bytes: u64,
        policy: EvictionPolicy,
    ) -> Vec<SegmentMeta> {
        if self.total_cache_bytes <= target_bytes {
            return Vec::new();
        }

        // Gather all unpinned candidates
        let mut candidates: Vec<SegmentId> = self
            .segments
            .iter()
            .filter(|(id, _)| !self.pinned_segments.contains(*id))
            .map(|(id, _)| id.clone())
            .collect();

        // Sort according to policy
        match policy {
            EvictionPolicy::Lru => {
                candidates.sort_by_key(|id| {
                    self.segments
                        .get(id)
                        .map(|m| m.last_accessed_at)
                        .unwrap_or(SystemTime::UNIX_EPOCH)
                });
            }
            EvictionPolicy::Fifo => {
                candidates.sort_by_key(|id| {
                    self.segments
                        .get(id)
                        .map(|m| m.created_at)
                        .unwrap_or(SystemTime::UNIX_EPOCH)
                });
            }
        }

        let mut evicted = Vec::new();
        for id in candidates {
            if self.total_cache_bytes <= target_bytes {
                break;
            }
            if let Some(meta) = self.remove_segment(&id) {
                evicted.push(meta);
            }
        }

        evicted
    }

    /// Queries the available free disk space on the filesystem hosting `path`.
    pub fn get_available_disk_space(path: &Path) -> Result<u64, StorageError> {
        use nix::sys::statvfs::statvfs;
        let stat = statvfs(path)
            .map_err(|e| StorageError::Io(std::io::Error::from_raw_os_error(e as i32)))?;
        let free_bytes =
            (stat.blocks_available() as u64).saturating_mul(stat.fragment_size() as u64);
        Ok(free_bytes)
    }

    /// Validates the 10 GB emergency free disk floor on `cache_dir`.
    /// If available space is below `emergency_disk_floor_bytes`, triggers eviction of unpinned segments.
    /// If free space remains below the emergency floor after evicting all unpinned items,
    /// returns `Err(StorageError::QuotaExceeded)`.
    pub fn enforce_emergency_disk_floor(
        &mut self,
        cache_dir: &Path,
        policy: EvictionPolicy,
    ) -> Result<Vec<SegmentMeta>, StorageError> {
        let available = Self::get_available_disk_space(cache_dir)?;
        if available >= self.config.emergency_disk_floor_bytes {
            return Ok(Vec::new());
        }

        let deficit = self.config.emergency_disk_floor_bytes - available;
        let target_cache = self.total_cache_bytes.saturating_sub(deficit);
        let evicted = self.evict_to_target(target_cache, policy);

        // Re-check after eviction
        let recheck_available = Self::get_available_disk_space(cache_dir)?;
        if recheck_available < self.config.emergency_disk_floor_bytes {
            return Err(StorageError::QuotaExceeded {
                used_bytes: self.total_cache_bytes,
                limit_bytes: self.config.max_cache_bytes,
            });
        }

        Ok(evicted)
    }
}

/// Thread-safe shared QuotaManager for async server tasks.
#[derive(Clone)]
pub struct SharedQuotaManager {
    inner: Arc<RwLock<QuotaManager>>,
}

impl SharedQuotaManager {
    pub fn new(config: QuotaConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(QuotaManager::new(config))),
        }
    }

    pub async fn pin_segment(&self, id: SegmentId) {
        let mut lock = self.inner.write().await;
        lock.pin_segment(id);
    }

    pub async fn unpin_segment(&self, id: &SegmentId) -> bool {
        let mut lock = self.inner.write().await;
        lock.unpin_segment(id)
    }

    pub async fn is_pinned(&self, id: &SegmentId) -> bool {
        let lock = self.inner.read().await;
        lock.is_pinned(id)
    }

    pub async fn touch_segment(&self, id: &SegmentId) {
        let mut lock = self.inner.write().await;
        lock.touch_segment(id);
    }

    pub async fn register_segment(
        &self,
        meta: SegmentMeta,
        policy: EvictionPolicy,
    ) -> Result<Vec<SegmentMeta>, StorageError> {
        let mut lock = self.inner.write().await;
        lock.register_segment(meta, policy)
    }

    pub async fn remove_segment(&self, id: &SegmentId) -> Option<SegmentMeta> {
        let mut lock = self.inner.write().await;
        lock.remove_segment(id)
    }

    pub async fn usage_info(&self, cache_dir: &Path) -> Result<DiskUsageInfo, StorageError> {
        let available_disk = QuotaManager::get_available_disk_space(cache_dir)?;
        let lock = self.inner.read().await;
        Ok(DiskUsageInfo {
            available_disk_bytes: available_disk,
            cache_used_bytes: lock.total_cache_bytes(),
            pinned_bytes: lock.pinned_bytes(),
            pinned_count: lock.pinned_count(),
            total_segments_count: lock.segments.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_segment(id: &str, size_bytes: u64, age_secs: u64) -> SegmentMeta {
        let now = SystemTime::now();
        let timestamp = now - Duration::from_secs(age_secs);
        SegmentMeta {
            id: SegmentId::from(id),
            path: PathBuf::from(format!("/tmp/{id}.ts")),
            size_bytes,
            created_at: timestamp,
            last_accessed_at: timestamp,
        }
    }

    #[test]
    fn test_quota_pinning_prevents_eviction() {
        let config = QuotaConfig {
            min_cache_bytes: 100,
            max_cache_bytes: 200,
            emergency_disk_floor_bytes: 10,
        };
        let mut manager = QuotaManager::new(config);

        let seg_a = make_segment("seg_a_pinned", 150, 100);
        let seg_b = make_segment("seg_b_unpinned", 40, 50);

        manager.pin_segment(SegmentId::from("seg_a_pinned"));
        assert!(manager.is_pinned(&SegmentId::from("seg_a_pinned")));

        manager
            .register_segment(seg_a, EvictionPolicy::Lru)
            .unwrap();
        manager
            .register_segment(seg_b, EvictionPolicy::Lru)
            .unwrap();
        assert_eq!(manager.total_cache_bytes(), 190);

        // Now register seg_c (50 bytes). Total = 240 > max 200.
        // It must evict seg_b, but NOT seg_a!
        let seg_c = make_segment("seg_c", 50, 10);
        let evicted = manager
            .register_segment(seg_c, EvictionPolicy::Lru)
            .unwrap();

        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].id.as_str(), "seg_b_unpinned");
        assert!(manager.is_pinned(&SegmentId::from("seg_a_pinned")));
        assert!(
            manager
                .segments
                .contains_key(&SegmentId::from("seg_a_pinned"))
        );
    }

    #[test]
    fn test_quota_lru_eviction_order() {
        let config = QuotaConfig {
            min_cache_bytes: 100,
            max_cache_bytes: 200,
            emergency_disk_floor_bytes: 10,
        };
        let mut manager = QuotaManager::new(config);

        let seg_old = make_segment("old_seg", 80, 300);
        let seg_mid = make_segment("mid_seg", 80, 200);
        let seg_new = make_segment("new_seg", 30, 100);

        manager
            .register_segment(seg_old, EvictionPolicy::Lru)
            .unwrap();
        manager
            .register_segment(seg_mid, EvictionPolicy::Lru)
            .unwrap();
        manager
            .register_segment(seg_new, EvictionPolicy::Lru)
            .unwrap();

        // Touch old_seg so it becomes the most recently accessed!
        manager.touch_segment(&SegmentId::from("old_seg"));

        // Register incoming seg_burst (60 bytes). Total = 80+80+30+60 = 250 > 200.
        // Needs eviction down to target (100 - 60 = 40).
        // LRU order: mid_seg (accessed 200s ago) < new_seg (100s ago) < old_seg (just touched).
        // So mid_seg must be evicted first!
        let seg_burst = make_segment("burst", 60, 5);
        let evicted = manager
            .register_segment(seg_burst, EvictionPolicy::Lru)
            .unwrap();

        assert!(!evicted.is_empty());
        assert_eq!(evicted[0].id.as_str(), "mid_seg");
    }

    #[test]
    fn test_quota_fifo_eviction_order() {
        let config = QuotaConfig {
            min_cache_bytes: 50,
            max_cache_bytes: 150,
            emergency_disk_floor_bytes: 10,
        };
        let mut manager = QuotaManager::new(config);

        let seg_1 = make_segment("seg_1", 60, 500); // oldest
        let seg_2 = make_segment("seg_2", 60, 200); // newer
        manager
            .register_segment(seg_1, EvictionPolicy::Fifo)
            .unwrap();
        manager
            .register_segment(seg_2, EvictionPolicy::Fifo)
            .unwrap();

        let seg_3 = make_segment("seg_3", 60, 10);
        let evicted = manager
            .register_segment(seg_3, EvictionPolicy::Fifo)
            .unwrap();

        assert_eq!(evicted[0].id.as_str(), "seg_1");
    }

    #[test]
    fn test_quota_exceeded_error_when_all_pinned() {
        let config = QuotaConfig {
            min_cache_bytes: 50,
            max_cache_bytes: 100,
            emergency_disk_floor_bytes: 10,
        };
        let mut manager = QuotaManager::new(config);

        let seg_pinned = make_segment("pinned_heavy", 90, 100);
        manager.pin_segment(SegmentId::from("pinned_heavy"));
        manager
            .register_segment(seg_pinned, EvictionPolicy::Lru)
            .unwrap();

        // Adding 30 bytes exceeds 100 max, and pinned cannot be evicted
        let seg_incoming = make_segment("incoming", 30, 10);
        let result = manager.register_segment(seg_incoming, EvictionPolicy::Lru);
        assert!(matches!(result, Err(StorageError::QuotaExceeded { .. })));
    }

    #[test]
    fn test_get_available_disk_space() {
        let temp_dir = std::env::temp_dir();
        let space = QuotaManager::get_available_disk_space(&temp_dir);
        assert!(space.is_ok(), "Failed to get disk space: {space:?}");
        let free_bytes = space.unwrap();
        assert!(free_bytes > 0, "Free disk space should be > 0");
    }
}
