use regex::Regex;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::LazyLock;
use url::Url;

// Matches standard Xtream Codes IPTV streaming paths:
// /(live|movie|series)/{username}/{password}/...
static XTREAM_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/(live|movie|series)/([^/]+)/([^/\s\?#]+)(/|$)")
        .expect("valid static Xtream regex")
});

static BASIC_AUTH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"://([^:\s/@]+):([^@\s/]+)@").expect("valid static basic auth regex")
});

static BASIC_AUTH_USER_ONLY_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"://([^:\s/@]+)@").expect("valid static basic auth user-only regex")
});

static QUERY_PARAM_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(username|user|password|pass|token|secret)=[^&#\s]+")
        .expect("valid static query param regex")
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
        let url_str = XTREAM_PATTERN
            .replace_all(&url_str, "/$1/[REDACTED]/[REDACTED]$4")
            .to_string();

        // 3. Redact query parameter credentials:
        //    ?username=...&password=... -> ?username=[REDACTED]&password=[REDACTED]
        QUERY_PARAM_PATTERN
            .replace_all(&url_str, "$1=[REDACTED]")
            .to_string()
    }

    /// Sanitizes arbitrary text (such as upstream error messages, exception strings, or URLs)
    /// by replacing any credentials found in Xtream paths (`/(live|movie|series)/{user}/{pass}/`),
    /// HTTP Basic Auth (`http://user:pass@...`), and query parameters (`?user=...&pass=...`) with `[REDACTED]`.
    pub fn sanitize_str(input: &str) -> String {
        let s = XTREAM_PATTERN.replace_all(input, "/$1/[REDACTED]/[REDACTED]$4");
        let s = BASIC_AUTH_PATTERN.replace_all(&s, "://[REDACTED]:[REDACTED]@");
        let s = BASIC_AUTH_USER_ONLY_PATTERN.replace_all(&s, "://[REDACTED]@");
        QUERY_PARAM_PATTERN
            .replace_all(&s, "$1=[REDACTED]")
            .to_string()
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

/// A secure string wrapper that redacts sensitive credentials (passwords, tokens)
/// in `Debug`, `Display`, and `tracing` logs.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct RedactedString(String);

impl RedactedString {
    /// Wrap a string as a redacted secret.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Explicitly access the secret string value.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper, returning the underlying String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for RedactedString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for RedactedString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl fmt::Display for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl FromStr for RedactedString {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl From<String> for RedactedString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for RedactedString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl serde::Serialize for RedactedString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for RedactedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(RedactedString(s))
    }
}

/// Helper function to sanitize arbitrary strings or error messages by redacting Xtream credentials and HTTP Basic Auth.
pub fn redacted_string(input: &str) -> String {
    RedactedUrl::sanitize_str(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redacts_live_stream_credentials() {
        let url_str = "http://stream.example.com/live/alice_user/secret_pass_123/45678.ts";
        let redacted = RedactedUrl::parse(url_str).expect("valid url");

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
        let url_str = "http://stream.example.com/movie/myuser/mypass/9999.mp4";
        let redacted = RedactedUrl::parse(url_str).expect("valid url");

        let display_str = format!("{redacted}");
        assert_eq!(
            display_str,
            "http://stream.example.com/movie/[REDACTED]/[REDACTED]/9999.mp4"
        );
    }

    #[test]
    fn test_redacts_series_credentials() {
        let url_str = "https://tv.example.com:8443/series/john_doe/top_secret/1234.mkv";
        let redacted = RedactedUrl::parse(url_str).expect("valid url");

        let display_str = format!("{redacted}");
        assert_eq!(
            display_str,
            "https://tv.example.com:8443/series/[REDACTED]/[REDACTED]/1234.mkv"
        );
    }

    #[test]
    fn test_redacts_http_basic_auth() {
        let url_str = "http://admin:supersecret@stream.example.com/stream/123.ts";
        let redacted = RedactedUrl::parse(url_str).expect("valid url");

        let display_str = format!("{redacted}");
        assert!(!display_str.contains("admin"));
        assert!(!display_str.contains("supersecret"));
        assert!(display_str.contains("[REDACTED]:[REDACTED]@stream.example.com"));
    }

    #[test]
    fn test_redacts_query_parameter_credentials() {
        let url_str = "http://stream.example.com/get.php?username=alice&password=secret123";
        let redacted = RedactedUrl::parse(url_str).expect("valid url");

        let display_str = format!("{redacted}");
        assert!(!display_str.contains("alice"));
        assert!(!display_str.contains("secret123"));
        assert_eq!(
            display_str,
            "http://stream.example.com/get.php?username=[REDACTED]&password=[REDACTED]"
        );

        // Sanitize string with query parameters in arbitrary text
        let raw_text = "fetch error from http://stream.example.com/player_api.php?user=charlie&pass=superpass&token=xyz789";
        let sanitized = RedactedUrl::sanitize_str(raw_text);
        assert!(!sanitized.contains("charlie"));
        assert!(!sanitized.contains("superpass"));
        assert!(!sanitized.contains("xyz789"));
        assert_eq!(
            sanitized,
            "fetch error from http://stream.example.com/player_api.php?user=[REDACTED]&pass=[REDACTED]&token=[REDACTED]"
        );
    }

    #[test]
    fn test_safe_stream_label() {
        let redacted =
            RedactedUrl::parse("http://stream.example.com/live/u/p/10492.ts").expect("valid url");
        assert_eq!(redacted.safe_stream_label(), "10492.ts");

        let vod = RedactedUrl::parse("http://stream.example.com/movie/u/p/sintel.mp4")
            .expect("valid url");
        assert_eq!(vod.safe_stream_label(), "sintel.mp4");
    }

    #[test]
    fn test_redacted_string_redaction() {
        let secret = RedactedString::new("super_secret_password_123");
        assert_eq!(format!("{secret}"), "[REDACTED]");
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert_eq!(secret.expose_secret(), "super_secret_password_123");
        assert_eq!(&*secret, "super_secret_password_123");
    }

    #[test]
    fn test_sanitize_str_in_error_messages() {
        let err_str = "error sending request for url (http://stream.example.com/live/demo_user_123/secret_pass_123/4906.ts): connection reset by peer";
        let sanitized = RedactedUrl::sanitize_str(err_str);
        assert!(!sanitized.contains("demo_user_123"));
        assert!(!sanitized.contains("secret_pass_123"));
        assert_eq!(
            sanitized,
            "error sending request for url (http://stream.example.com/live/[REDACTED]/[REDACTED]/4906.ts): connection reset by peer"
        );

        let vod_err = "failed to proxy: error sending request for url (http://stream.example.com/movie/my_user/my_secret/100.mp4): timed out";
        assert_eq!(
            redacted_string(vod_err),
            "failed to proxy: error sending request for url (http://stream.example.com/movie/[REDACTED]/[REDACTED]/100.mp4): timed out"
        );

        let series_err = "failed to proxy: error sending request for url (http://stream.example.com/series/my_user/my_secret/200.mkv): refused";
        assert_eq!(
            redacted_string(series_err),
            "failed to proxy: error sending request for url (http://stream.example.com/series/[REDACTED]/[REDACTED]/200.mkv): refused"
        );

        let basic_err = "upstream error: failed request to http://admin:supersecret@stream.example.com:8080/path";
        assert_eq!(
            RedactedUrl::sanitize_str(basic_err),
            "upstream error: failed request to http://[REDACTED]:[REDACTED]@stream.example.com:8080/path"
        );

        let clean_err = "standard io error: Connection reset by peer (os error 104)";
        assert_eq!(RedactedUrl::sanitize_str(clean_err), clean_err);
    }
}
