use std::net::IpAddr;
use thiserror::Error;

/// Ingestion-related errors when fetching media from upstream providers.
#[derive(Debug, Error)]
pub enum IngestError {
    #[error("Network I/O failed during ingest: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Ingest timed out after {0:?}")]
    Timeout(std::time::Duration),

    #[error("Ingest stream aborted: {0}")]
    Aborted(String),

    #[error("Unexpected HTTP status from upstream: {0}")]
    BadStatus(reqwest::StatusCode),

    #[error("Premature EOF encountered: expected {expected} bytes, received {received} bytes")]
    PrematureEof { expected: u64, received: u64 },

    #[error("Ingest channel closed unexpectedly")]
    ChannelClosed,
}

/// Storage errors handling NVMe disk caches, sparse allocations, and RAM buffers.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Storage I/O failure: {0}")]
    Io(#[from] std::io::Error),

    #[error("Storage quota exceeded: used {used_bytes} bytes, limit {limit_bytes} bytes")]
    QuotaExceeded { used_bytes: u64, limit_bytes: u64 },

    #[error("Preallocation failed for path {path}: {source}")]
    FallocateFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Target cache file not found: {0}")]
    FileNotFound(String),

    #[error("Corrupted file cache header or index at {0}")]
    CorruptIndex(String),

    #[error(
        "Ring buffer capacity underflow: requested sequence {requested} is older than oldest available {oldest}"
    )]
    RingUnderflow { requested: u64, oldest: u64 },
}

/// Protocol errors parsing MPEG-TS packets, MP4 boxes, and HTTP Range headers.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Invalid HTTP Range header: {0}")]
    InvalidRange(String),

    #[error("Requested Range not satisfiable: start={start}, end={end:?}, total={total}")]
    RangeNotSatisfiable {
        start: u64,
        end: Option<u64>,
        total: u64,
    },

    #[error("MPEG-TS packet sync lost: byte offset {offset} does not match sync byte 0x47")]
    MpegTsSyncLoss { offset: usize },

    #[error("MP4 moov atom missing in faststart header window ({scanned_bytes} bytes scanned)")]
    MissingMoovAtom { scanned_bytes: usize },

    #[error("Unsupported container format: {0}")]
    UnsupportedContainer(String),
}

/// Security validation errors defending against SSRF, unauthorized hosts, and directory traversal.
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error(
        "SSRF attempt blocked: destination address {0} is forbidden (loopback/private/link-local)"
    )]
    SsrfBlocked(IpAddr),

    #[error("Target upstream host '{0}' is not in the configured whitelist")]
    UnauthorizedHost(String),

    #[error("Invalid upstream URL: {0}")]
    InvalidUrl(String),

    #[error("Path traversal attempt detected in cache path: {0}")]
    PathTraversal(String),

    #[error("Authentication failed: invalid or expired stream token")]
    Unauthorized,
}

impl From<crate::security::NetworkSecurityError> for SecurityError {
    fn from(err: crate::security::NetworkSecurityError) -> Self {
        match err {
            crate::security::NetworkSecurityError::RestrictedIpAddress(ip) => {
                SecurityError::SsrfBlocked(ip)
            }
            crate::security::NetworkSecurityError::DnsResolutionFailed => {
                SecurityError::InvalidUrl(
                    "DNS resolution failed or returned no valid public IP addresses".to_string(),
                )
            }
            crate::security::NetworkSecurityError::LookupIoError(msg) => {
                SecurityError::InvalidUrl(msg)
            }
        }
    }
}

impl From<crate::security::PathGuardError> for SecurityError {
    fn from(err: crate::security::PathGuardError) -> Self {
        SecurityError::PathTraversal(err.to_string())
    }
}

/// Upstream coordination errors enforcing the strict single-socket invariant.
#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("Upstream single-connection limit reached: stream '{stream_id}' already active")]
    ConnectionLimitExceeded { stream_id: String },

    #[error("Upstream connection is in cooldown until {cooldown_until:?}")]
    CooldownActive { cooldown_until: std::time::Instant },

    #[error("Upstream provider authentication rejected (HTTP 401/403)")]
    AuthenticationFailed,

    #[error("Upstream session preempted by higher priority channel switch")]
    Preempted,

    #[error("Upstream provider unreachable")]
    ProviderUnreachable,
}

/// Top-level unified domain error for the airlock streaming daemon.
#[derive(Debug, Error)]
pub enum AirlockError {
    #[error("Ingest error: {0}")]
    Ingest(#[from] IngestError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Security error: {0}")]
    Security(#[from] SecurityError),

    #[error("Upstream error: {0}")]
    Upstream(#[from] UpstreamError),

    #[error("Internal service error: {0}")]
    Internal(String),
}

impl axum::response::IntoResponse for AirlockError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let (status, message) = match &self {
            AirlockError::Protocol(ProtocolError::RangeNotSatisfiable { .. }) => {
                (StatusCode::RANGE_NOT_SATISFIABLE, self.to_string())
            }
            AirlockError::Protocol(ProtocolError::InvalidRange(_)) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            AirlockError::Security(SecurityError::Unauthorized) => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            AirlockError::Security(SecurityError::SsrfBlocked(_))
            | AirlockError::Security(SecurityError::UnauthorizedHost(_))
            | AirlockError::Security(SecurityError::PathTraversal(_)) => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            AirlockError::Storage(StorageError::FileNotFound(_)) => {
                (StatusCode::NOT_FOUND, self.to_string())
            }
            AirlockError::Upstream(UpstreamError::ConnectionLimitExceeded { .. }) => {
                (StatusCode::TOO_MANY_REQUESTS, self.to_string())
            }
            AirlockError::Ingest(IngestError::BadStatus(code)) => (
                StatusCode::BAD_GATEWAY,
                format!("Upstream returned bad status: {code}"),
            ),
            AirlockError::Ingest(_) | AirlockError::Upstream(_) => {
                (StatusCode::BAD_GATEWAY, self.to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = serde_json::json!({
            "error": message,
            "status_code": status.as_u16(),
        });

        (status, axum::Json(body)).into_response()
    }
}
