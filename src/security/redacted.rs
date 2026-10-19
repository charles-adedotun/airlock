use regex::Regex;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::LazyLock;
use url::Url;

// Matches standard Xtream Codes IPTV streaming paths:
// /(live|movie|series)/{username}/{password}/...
static XTREAM_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/(live|movie|series)/([^/]+)/([^/]+)/").expect("valid static Xtream regex")
});

/// A security wrapper around `url::Url` that guarantees credentials in
/// HTTP Basic Auth or Xtream Codes IPTV paths (`/(live|movie|series)/{user}/{pass}/`)
/// are automatically redacted as `[REDACTED]` in `Display`, `Debug`, and `tracing` logs.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedUrl {
    inner: Url,
}

impl RedactedUrl {
    /// Creates a new `RedactedUrl` from a parsed `Url`.
    pub fn new(url: Url) -> Self {
        Self { inner: url }
    }

    /// Parses a URL string into a `RedactedUrl`.
    pub fn parse(input: &str) -> Result<Self, url::ParseError> {
        let url = Url::parse(input)?;
        Ok(Self { inner: url })
    }

    /// Accesses the underlying raw `Url`.
    /// Note: Use caution when handling the raw URL to avoid leaking credentials.
    pub fn inner(&self) -> &Url {
        &self.inner
    }

    /// Consumes the wrapper and returns the raw `Url`.
    pub fn into_inner(self) -> Url {
        self.inner
    }

    /// Returns the sanitized string representation with credentials masked.
    pub fn sanitized_string(&self) -> String {
        let mut cloned = self.inner.clone();

        // 1. Redact standard HTTP Basic Auth if present (http://user:pass@host/...)
        let has_user = !cloned.username().is_empty();
        let has_pass = cloned.password().is_some();
        if has_user {
            let _ = cloned.set_username("USER_PLACEHOLDER");
        }
        if has_pass {
            let _ = cloned.set_password(Some("PASS_PLACEHOLDER"));
        }

        let mut url_str = cloned.to_string();
        if has_user && has_pass {
            url_str = url_str.replace(
                "USER_PLACEHOLDER:PASS_PLACEHOLDER@",
                "[REDACTED]:[REDACTED]@",
            );
        } else if has_user {
            url_str = url_str.replace("USER_PLACEHOLDER@", "[REDACTED]@");
        }

        // 2. Redact Xtream Codes URL path credentials:
        //    /(live|movie|series)/{user}/{pass}/ -> /(live|movie|series)/[REDACTED]/[REDACTED]/
        if XTREAM_PATTERN.is_match(&url_str) {
            url_str = XTREAM_PATTERN
                .replace(&url_str, "/$1/[REDACTED]/[REDACTED]/")
                .to_string();
        }

        url_str
    }

    /// Returns only the safe trailing stream identifier (e.g., "10492.ts" or "sintel.mp4")
    /// suitable for Prometheus metrics labels and telemetry counters.
    pub fn safe_stream_label(&self) -> String {
        let path = self.inner.path();
        path.rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown")
            .to_string()
    }
}

impl Deref for RedactedUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<Url> for RedactedUrl {
    fn from(url: Url) -> Self {
        Self::new(url)
    }
}

impl FromStr for RedactedUrl {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<Url> for RedactedUrl {
    fn as_ref(&self) -> &Url {
        &self.inner
    }
}

impl fmt::Display for RedactedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sanitized_string())
    }
}

impl fmt::Debug for RedactedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedactedUrl(\"{}\")", self.sanitized_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redacts_live_stream_credentials() {
        let url_str = "http://line.ottcst.org/live/alice_user/secret_pass_123/45678.ts";
        let redacted = RedactedUrl::parse(url_str).unwrap();

        let display_str = format!("{redacted}");
        let debug_str = format!("{redacted:?}");

        assert!(!display_str.contains("alice_user"));
        assert!(!display_str.contains("secret_pass_123"));
        assert!(display_str.contains("/live/[REDACTED]/[REDACTED]/45678.ts"));

        assert!(!debug_str.contains("alice_user"));
        assert!(!debug_str.contains("secret_pass_123"));
        assert!(debug_str.contains("/live/[REDACTED]/[REDACTED]/45678.ts"));

        // Verify underlying URL remains intact for genuine HTTP calls
        assert_eq!(redacted.inner().as_str(), url_str);
    }

    #[test]
    fn test_redacts_movie_vod_credentials() {
        let url_str = "http://line.ottcst.org/movie/myuser/mypass/9999.mp4";
        let redacted = RedactedUrl::parse(url_str).unwrap();

        let display_str = format!("{redacted}");
        assert_eq!(
            display_str,
            "http://line.ottcst.org/movie/[REDACTED]/[REDACTED]/9999.mp4"
        );
    }

    #[test]
    fn test_redacts_series_credentials() {
        let url_str = "https://tv.example.com:8443/series/john_doe/top_secret/1234.mkv";
        let redacted = RedactedUrl::parse(url_str).unwrap();

        let display_str = format!("{redacted}");
        assert_eq!(
            display_str,
            "https://tv.example.com:8443/series/[REDACTED]/[REDACTED]/1234.mkv"
        );
    }

    #[test]
    fn test_redacts_http_basic_auth() {
        let url_str = "http://admin:supersecret@line.ottcst.org/stream/123.ts";
        let redacted = RedactedUrl::parse(url_str).unwrap();

        let display_str = format!("{redacted}");
        assert!(!display_str.contains("admin"));
        assert!(!display_str.contains("supersecret"));
        assert!(display_str.contains("[REDACTED]:[REDACTED]@line.ottcst.org"));
    }

    #[test]
    fn test_safe_stream_label() {
        let redacted = RedactedUrl::parse("http://line.ottcst.org/live/u/p/10492.ts").unwrap();
        assert_eq!(redacted.safe_stream_label(), "10492.ts");

        let vod = RedactedUrl::parse("http://line.ottcst.org/movie/u/p/sintel.mp4").unwrap();
        assert_eq!(vod.safe_stream_label(), "sintel.mp4");
    }
}
