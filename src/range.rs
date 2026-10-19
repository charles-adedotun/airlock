use crate::error::ProtocolError;

/// Representation of an RFC 9110 HTTP Range header specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpRange {
    /// Explicit range with start and optional end: `bytes=start-end` or `bytes=start-`
    Single { start: u64, end: Option<u64> },
    /// Suffix range specifying the last N bytes of the file: `bytes=-suffix_len`
    Suffix { length: u64 },
    /// Multiple ranges separated by commas: `bytes=0-10,20-30`
    Multi(Vec<HttpRange>),
}

/// A resolved, validated byte range bounded within a known resource size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedByteRange {
    /// 0-indexed inclusive start offset.
    pub start: u64,
    /// 0-indexed inclusive end offset.
    pub end: u64,
    /// Total size of the underlying resource in bytes.
    pub total_size: u64,
}

impl ResolvedByteRange {
    /// Create a new resolved byte range, verifying invariants.
    pub fn new(start: u64, end: u64, total_size: u64) -> Result<Self, ProtocolError> {
        if total_size == 0 || start >= total_size || start > end {
            return Err(ProtocolError::RangeNotSatisfiable {
                start,
                end: Some(end),
                total: total_size,
            });
        }

        let clamped_end = end.min(total_size.saturating_sub(1));
        Ok(Self {
            start,
            end: clamped_end,
            total_size,
        })
    }

    /// Number of bytes in this range (inclusive bounds: end - start + 1).
    /// Uses checked arithmetic to prevent overflow.
    pub fn length(&self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    /// Format standard RFC 9110 `Content-Range` header value (e.g. `bytes 0-1024/10000`).
    pub fn content_range_value(&self) -> String {
        format!("bytes {}-{}/{}", self.start, self.end, self.total_size)
    }

    /// Check if a byte offset falls within this range.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.start && offset <= self.end
    }
}

/// Parse an RFC 9110 HTTP Range header string (e.g. `bytes=0-1024`, `bytes=1024-`, `bytes=-2048`).
pub fn parse_range_header(header_val: &str) -> Result<HttpRange, ProtocolError> {
    let trimmed = header_val.trim();
    if !trimmed.starts_with("bytes=") {
        return Err(ProtocolError::InvalidRange(format!(
            "Missing 'bytes=' prefix in range header: '{trimmed}'"
        )));
    }

    let spec_part = &trimmed["bytes=".len()..].trim();
    if spec_part.is_empty() {
        return Err(ProtocolError::InvalidRange(
            "Empty range specification".to_string(),
        ));
    }

    // Handle comma-separated multiple ranges: `bytes=0-10,20-30`
    if spec_part.contains(',') {
        let mut ranges = Vec::new();
        for item in spec_part.split(',') {
            let item_trimmed = item.trim();
            if !item_trimmed.is_empty() {
                ranges.push(parse_single_range(item_trimmed)?);
            }
        }
        if ranges.is_empty() {
            return Err(ProtocolError::InvalidRange(
                "Empty multi-range list".to_string(),
            ));
        }
        return Ok(HttpRange::Multi(ranges));
    }

    parse_single_range(spec_part)
}

fn parse_single_range(range_str: &str) -> Result<HttpRange, ProtocolError> {
    let parts: Vec<&str> = range_str.split('-').collect();
    if parts.len() != 2 {
        return Err(ProtocolError::InvalidRange(format!(
            "Invalid range component syntax: '{range_str}'"
        )));
    }

    let start_str = parts[0].trim();
    let end_str = parts[1].trim();

    if start_str.is_empty() {
        // Suffix range: `bytes=-N` (last N bytes)
        if end_str.is_empty() {
            return Err(ProtocolError::InvalidRange(
                "Range contains only '-' with no offsets".to_string(),
            ));
        }
        let suffix_len = end_str.parse::<u64>().map_err(|_| {
            ProtocolError::InvalidRange(format!("Invalid suffix range number: '{end_str}'"))
        })?;
        if suffix_len == 0 {
            return Err(ProtocolError::InvalidRange(
                "Suffix range length cannot be zero".to_string(),
            ));
        }
        Ok(HttpRange::Suffix { length: suffix_len })
    } else {
        // Start offset specified
        let start = start_str.parse::<u64>().map_err(|_| {
            ProtocolError::InvalidRange(format!("Invalid start range offset: '{start_str}'"))
        })?;

        if end_str.is_empty() {
            // Open-ended range: `bytes=start-`
            Ok(HttpRange::Single { start, end: None })
        } else {
            // Closed range: `bytes=start-end`
            // Handle possible overflow gracefully
            let end = end_str.parse::<u64>().map_err(|_| {
                // If it overflows u64, treat as u64::MAX for safety clamp
                if end_str.chars().all(|c| c.is_ascii_digit()) {
                    return ProtocolError::InvalidRange(
                        "Range end offset overflows u64".to_string(),
                    );
                }
                ProtocolError::InvalidRange(format!("Invalid end range offset: '{end_str}'"))
            })?;

            if start > end {
                return Err(ProtocolError::InvalidRange(format!(
                    "Range start ({start}) cannot be greater than end ({end})"
                )));
            }

            Ok(HttpRange::Single {
                start,
                end: Some(end),
            })
        }
    }
}

/// Resolve an `HttpRange` against a known resource length.
/// RFC 9110 §14.2: For multi-range requests, implementations may coalesce or serve
/// the first satisfiable range.
pub fn resolve_range(
    range: &HttpRange,
    total_size: u64,
) -> Result<ResolvedByteRange, ProtocolError> {
    if total_size == 0 {
        return Err(ProtocolError::RangeNotSatisfiable {
            start: 0,
            end: None,
            total: 0,
        });
    }

    match range {
        HttpRange::Single { start, end } => {
            let s = *start;
            if s >= total_size {
                return Err(ProtocolError::RangeNotSatisfiable {
                    start: s,
                    end: *end,
                    total: total_size,
                });
            }
            let max_idx = total_size - 1;
            let e = end.map(|val| val.min(max_idx)).unwrap_or(max_idx);
            ResolvedByteRange::new(s, e, total_size)
        }
        HttpRange::Suffix { length } => {
            let len = *length;
            if len == 0 {
                return Err(ProtocolError::RangeNotSatisfiable {
                    start: total_size,
                    end: None,
                    total: total_size,
                });
            }
            let s = total_size.saturating_sub(len);
            let e = total_size - 1;
            ResolvedByteRange::new(s, e, total_size)
        }
        HttpRange::Multi(ranges) => {
            // RFC 9110 §14.2: Select the first satisfiable range in order
            for r in ranges {
                if let Ok(resolved) = resolve_range(r, total_size) {
                    return Ok(resolved);
                }
            }
            Err(ProtocolError::RangeNotSatisfiable {
                start: 0,
                end: None,
                total: total_size,
            })
        }
    }
}
