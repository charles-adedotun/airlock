use std::io::{Error, ErrorKind, Result as IoResult};

/// Minimum required host free/available RAM headroom (1.5 GiB = 1,610,612,736 bytes).
pub const MIN_MEMORY_HEADROOM_BYTES: u64 = 1536 * 1024 * 1024;

/// Snapshot of host memory statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostMemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub free_bytes: u64,
}

/// Parses the contents of Linux `/proc/meminfo` to extract memory metrics.
pub fn parse_meminfo(content: &str) -> IoResult<HostMemoryInfo> {
    let mut total_bytes: Option<u64> = None;
    let mut free_bytes: Option<u64> = None;
    let mut available_bytes: Option<u64> = None;
    let mut buffers_bytes: u64 = 0;
    let mut cached_bytes: u64 = 0;

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let key = match parts.next() {
            Some(k) => k,
            None => continue,
        };
        let val_kb = match parts.next().and_then(|v| v.parse::<u64>().ok()) {
            Some(v) => v,
            None => continue,
        };
        let val_bytes = val_kb.saturating_mul(1024);

        match key {
            "MemTotal:" => total_bytes = Some(val_bytes),
            "MemFree:" => free_bytes = Some(val_bytes),
            "MemAvailable:" => available_bytes = Some(val_bytes),
            "Buffers:" => buffers_bytes = val_bytes,
            "Cached:" => cached_bytes = val_bytes,
            _ => {}
        }
    }

    let total = total_bytes
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "MemTotal missing in /proc/meminfo"))?;
    let free = free_bytes.unwrap_or(0);
    // If MemAvailable kernel field is absent (older Linux kernels < 3.14), estimate it:
    let available = available_bytes.unwrap_or_else(|| {
        free.saturating_add(buffers_bytes)
            .saturating_add(cached_bytes)
    });

    Ok(HostMemoryInfo {
        total_bytes: total,
        available_bytes: available,
        free_bytes: free,
    })
}

/// Parses macOS `vm_stat` output text into `HostMemoryInfo`.
pub fn parse_vm_stat(content: &str, total_bytes: u64) -> IoResult<HostMemoryInfo> {
    let mut page_size = 16384u64; // Default on Apple Silicon
    let mut free_pages = 0u64;
    let mut speculative_pages = 0u64;
    let mut purgeable_pages = 0u64;
    let mut inactive_pages = 0u64;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("Mach Virtual Memory Statistics:") {
            if let Some(start) = line.find("page size of ") {
                let rest = &line[start + "page size of ".len()..];
                if let Some(end) = rest.find(" bytes")
                    && let Ok(ps) = rest[..end].trim().parse::<u64>()
                {
                    page_size = ps;
                }
            }
            continue;
        }

        if let Some((key, val_str)) = line.split_once(':') {
            let key = key.trim();
            let val = val_str
                .trim()
                .trim_end_matches('.')
                .parse::<u64>()
                .unwrap_or(0);

            match key {
                "Pages free" => free_pages = val,
                "Pages speculative" => speculative_pages = val,
                "Pages purgeable" => purgeable_pages = val,
                "Pages inactive" => inactive_pages = val,
                _ => {}
            }
        }
    }

    let free_bytes = free_pages.saturating_mul(page_size);
    // On Darwin, available memory is free + speculative + purgeable + inactive
    let available_pages = free_pages
        .saturating_add(speculative_pages)
        .saturating_add(purgeable_pages)
        .saturating_add(inactive_pages);
    let available_bytes = available_pages.saturating_mul(page_size);

    Ok(HostMemoryInfo {
        total_bytes,
        available_bytes,
        free_bytes,
    })
}

/// Retrieves host memory metrics cross-platform without any unsafe code.
/// - Linux: Reads and parses `/proc/meminfo`.
/// - macOS: Queries kernel vm statistics via `sysctl` and `vm_stat`.
pub fn get_host_memory_info() -> IoResult<HostMemoryInfo> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/meminfo")?;
        parse_meminfo(&content)
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        use std::sync::OnceLock;

        static TOTAL_RAM: OnceLock<u64> = OnceLock::new();
        let total_bytes = *TOTAL_RAM.get_or_init(|| {
            let output = Command::new("sysctl").args(["-n", "hw.memsize"]).output();
            if let Ok(out) = output {
                let s = String::from_utf8_lossy(&out.stdout);
                s.trim().parse::<u64>().unwrap_or(16 * 1024 * 1024 * 1024)
            } else {
                16 * 1024 * 1024 * 1024
            }
        });

        let vm_output = Command::new("vm_stat")
            .output()
            .map_err(|e| Error::other(format!("Failed to execute vm_stat: {e}")))?;
        let vm_text = String::from_utf8_lossy(&vm_output.stdout);
        parse_vm_stat(&vm_text, total_bytes)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Safe fallback for unsupported operating systems
        Ok(HostMemoryInfo {
            total_bytes: 8 * 1024 * 1024 * 1024,
            available_bytes: 4 * 1024 * 1024 * 1024,
            free_bytes: 4 * 1024 * 1024 * 1024,
        })
    }
}

/// Helper returning the currently available memory in bytes.
pub fn get_host_available_memory_bytes() -> IoResult<u64> {
    get_host_memory_info().map(|info| info.available_bytes)
}

/// Checks whether the host has at least `threshold_bytes` of available RAM.
pub fn check_host_memory_headroom_with_threshold(threshold_bytes: u64) -> bool {
    match get_host_memory_info() {
        Ok(info) => info.available_bytes >= threshold_bytes,
        Err(err) => {
            tracing::warn!("Failed to query host memory info: {err}. Permitting operation.");
            true
        }
    }
}

/// Checks whether the host has at least the minimum 1.5 GiB of available RAM headroom.
pub fn check_host_memory_headroom() -> bool {
    check_host_memory_headroom_with_threshold(MIN_MEMORY_HEADROOM_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_meminfo_standard_linux() {
        let sample = r#"
MemTotal:       32658824 kB
MemFree:         4123512 kB
MemAvailable:   21568904 kB
Buffers:          345120 kB
Cached:          8901234 kB
SwapTotal:       4194300 kB
SwapFree:        4194300 kB
"#;
        let info = parse_meminfo(sample).expect("Failed to parse meminfo");
        assert_eq!(info.total_bytes, 32658824 * 1024);
        assert_eq!(info.free_bytes, 4123512 * 1024);
        assert_eq!(info.available_bytes, 21568904 * 1024);
    }

    #[test]
    fn test_parse_meminfo_legacy_kernel_without_memavailable() {
        let sample = r#"
MemTotal:       16384000 kB
MemFree:         2000000 kB
Buffers:          500000 kB
Cached:          3000000 kB
"#;
        let info = parse_meminfo(sample).expect("Failed to parse legacy meminfo");
        assert_eq!(info.total_bytes, 16384000 * 1024);
        assert_eq!(info.free_bytes, 2000000 * 1024);
        // Estimated available = free (2,000,000) + buffers (500,000) + cached (3,000,000) = 5,500,000 kB
        assert_eq!(info.available_bytes, 5500000 * 1024);
    }

    #[test]
    fn test_parse_meminfo_invalid() {
        let empty = "RandomText: 1234";
        assert!(parse_meminfo(empty).is_err());
    }

    #[test]
    fn test_parse_vm_stat_macos() {
        let sample = r#"
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                                     5674.
Pages active:                                 211643.
Pages inactive:                               203108.
Pages speculative:                              4342.
Pages throttled:                                   0.
Pages purgeable:                                 190.
"#;
        let total_bytes = 17179869184u64;
        let info = parse_vm_stat(sample, total_bytes).expect("Failed to parse vm_stat");
        assert_eq!(info.total_bytes, total_bytes);
        assert_eq!(info.free_bytes, 5674 * 16384);
        // available = (5674 + 4342 + 190 + 203108) * 16384 = 213314 * 16384 = 3494985728
        assert_eq!(info.available_bytes, 213314 * 16384);
    }

    #[test]
    fn test_live_host_memory_query() {
        let info = get_host_memory_info();
        assert!(info.is_ok(), "Failed to get host memory info: {info:?}");
        let info = info.expect("Expected memory info");
        assert!(info.total_bytes > 0, "Total bytes should be > 0");
        assert!(check_host_memory_headroom_with_threshold(1));
        assert!(!check_host_memory_headroom_with_threshold(u64::MAX));
    }
}
