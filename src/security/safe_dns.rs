use reqwest::dns::{Name, Resolve, Resolving};
use reqwest::{Client, redirect};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum NetworkSecurityError {
    #[error("Target IP address {0} is restricted (private/loopback/metadata/CGNAT)")]
    RestrictedIpAddress(IpAddr),
    #[error("DNS resolution failed or returned no valid public IP addresses")]
    DnsResolutionFailed,
    #[error("I/O error during DNS lookup: {0}")]
    LookupIoError(String),
}

/// Evaluates whether an IP address belongs to internal, loopback, link-local,
/// cloud metadata, multicast, or Tailscale CGNAT subnets.
pub fn is_ip_restricted(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_ipv4_restricted(ipv4),
        IpAddr::V6(ipv6) => is_ipv6_restricted(ipv6),
    }
}

/// Checks an IPv4 address against restricted subnets.
fn is_ipv4_restricted(ipv4: Ipv4Addr) -> bool {
    let octets = ipv4.octets();

    // 1. Loopback: 127.0.0.0/8
    if ipv4.is_loopback() {
        return true;
    }

    // 2. RFC 1918 Private LAN:
    //    10.0.0.0/8
    //    172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    //    192.168.0.0/16
    if ipv4.is_private() {
        return true;
    }

    // 3. Link-Local / Cloud Metadata (AWS/GCP/Azure/OpenStack):
    //    169.254.0.0/16 (e.g. 169.254.169.254)
    if ipv4.is_link_local() {
        return true;
    }

    // 4. Tailscale Carrier-Grade NAT (CGNAT) / RFC 6598 Shared Address Space:
    //    100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
    //    Binary check: first octet is 100, second octet top 2 bits are 01 (0b01xxxxxx = 64..127)
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
        return true;
    }

    // 5. Broadcast (255.255.255.255) and Unspecified (0.0.0.0/8)
    if ipv4.is_broadcast() || ipv4.is_unspecified() || octets[0] == 0 {
        return true;
    }

    // 6. Multicast: 224.0.0.0/4 (224.0.0.0 - 239.255.255.255)
    if ipv4.is_multicast() {
        return true;
    }

    // 7. Documentation (RFC 5737):
    //    192.0.2.0/24 (TEST-NET-1)
    //    198.51.100.0/24 (TEST-NET-2)
    //    203.0.113.0/24 (TEST-NET-3)
    if ipv4.is_documentation() {
        return true;
    }

    // 8. Reserved for future use (RFC 1112): 240.0.0.0/4
    if octets[0] >= 240 {
        return true;
    }

    false
}

/// Checks an IPv6 address against restricted subnets.
fn is_ipv6_restricted(ipv6: Ipv6Addr) -> bool {
    // 1. Loopback (::1) and Unspecified (::)
    if ipv6.is_loopback() || ipv6.is_unspecified() {
        return true;
    }

    // 2. Multicast (ff00::/8)
    if ipv6.is_multicast() {
        return true;
    }

    // 3. IPv4-Mapped IPv6 (::ffff:x.x.x.x)
    if let Some(mapped_v4) = ipv6.to_ipv4_mapped() {
        return is_ipv4_restricted(mapped_v4);
    }

    let segments = ipv6.segments();

    // 4. Unique Local Addresses (ULA) fc00::/7 (RFC 4193, private IPv6)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // 5. Link-Local Unicast fe80::/10 (RFC 4291)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    // 6. Documentation (RFC 3849): 2001:db8::/32
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }

    // 7. Discard prefix (RFC 6666): 100::/64
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return true;
    }

    false
}

/// Safe DNS Resolver plugin for `reqwest::Client`.
///
/// Resolves domain names to IP addresses and rejects any resolutions pointing to
/// internal networks, link-local, loopback, cloud metadata, or Tailscale CGNAT subnets.
/// This prevents DNS rebinding and SSRF network pivoting.
#[derive(Debug, Default, Clone)]
pub struct SafeDnsResolver;

impl SafeDnsResolver {
    pub fn new() -> Self {
        Self
    }
}

impl Resolve for SafeDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host_str = name.as_str();

            // Perform DNS lookup asynchronously via Tokio's threadpool resolver
            let addrs = tokio::net::lookup_host((host_str, 80)).await.map_err(|e| {
                Box::new(NetworkSecurityError::LookupIoError(e.to_string()))
                    as Box<dyn std::error::Error + Send + Sync>
            })?;

            let mut safe_addrs = Vec::new();
            for addr in addrs {
                let ip = addr.ip();
                if is_ip_restricted(ip) {
                    tracing::warn!(
                        target: "security::ssrf",
                        host = host_str,
                        ip = %ip,
                        "Blocked outbound connection attempt to restricted IP address"
                    );
                    return Err(Box::new(NetworkSecurityError::RestrictedIpAddress(ip))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
                safe_addrs.push(addr);
            }

            if safe_addrs.is_empty() {
                return Err(Box::new(NetworkSecurityError::DnsResolutionFailed)
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            let iter: Box<dyn Iterator<Item = SocketAddr> + Send> =
                Box::new(safe_addrs.into_iter());
            Ok(iter)
        })
    }
}

/// Creates a security-hardened `reqwest::Client` configured with:
/// - `SafeDnsResolver` blocking private, link-local, loopback, and Tailscale subnets.
/// - Redirects disabled (`redirect::Policy::none()`) to prevent redirect-based SSRF.
/// - Strict connection and read timeouts.
/// - Rustls TLS backend.
pub fn create_hardened_http_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .dns_resolver(Arc::new(SafeDnsResolver::new()))
        .redirect(redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .tcp_nodelay(true)
        .use_rustls_tls()
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_loopback_blocked() {
        assert!(is_ip_restricted(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(is_ip_restricted(IpAddr::from_str("127.0.1.100").unwrap()));
        assert!(is_ip_restricted(IpAddr::from_str("::1").unwrap()));
    }

    #[test]
    fn test_rfc1918_private_lan_blocked() {
        // 10.0.0.0/8
        assert!(is_ip_restricted(IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(is_ip_restricted(IpAddr::from_str("10.254.1.5").unwrap()));

        // 172.16.0.0/12
        assert!(is_ip_restricted(IpAddr::from_str("172.16.0.1").unwrap()));
        assert!(is_ip_restricted(
            IpAddr::from_str("172.31.255.254").unwrap()
        ));
        // 172.32.0.1 is public
        assert!(!is_ip_restricted(IpAddr::from_str("172.32.0.1").unwrap()));

        // 192.168.0.0/16
        assert!(is_ip_restricted(IpAddr::from_str("192.168.1.1").unwrap()));
        assert!(is_ip_restricted(IpAddr::from_str("192.168.0.254").unwrap()));
    }

    #[test]
    fn test_cloud_metadata_link_local_blocked() {
        // 169.254.169.254 (AWS, GCP, Azure metadata service)
        assert!(is_ip_restricted(
            IpAddr::from_str("169.254.169.254").unwrap()
        ));
        assert!(is_ip_restricted(IpAddr::from_str("169.254.1.1").unwrap()));
        // IPv6 Link-Local
        assert!(is_ip_restricted(IpAddr::from_str("fe80::1").unwrap()));
    }

    #[test]
    fn test_tailscale_cgnat_blocked() {
        // Tailscale CGNAT subnet is 100.64.0.0/10 (100.64.0.0 to 100.127.255.255)
        assert!(is_ip_restricted(IpAddr::from_str("100.64.0.1").unwrap()));
        assert!(is_ip_restricted(IpAddr::from_str("100.85.12.34").unwrap()));
        assert!(is_ip_restricted(
            IpAddr::from_str("100.100.100.100").unwrap()
        ));
        assert!(is_ip_restricted(
            IpAddr::from_str("100.127.255.254").unwrap()
        ));

        // Outside Tailscale CGNAT:
        // 100.63.255.255 is public
        assert!(!is_ip_restricted(
            IpAddr::from_str("100.63.255.255").unwrap()
        ));
        // 100.128.0.1 is public
        assert!(!is_ip_restricted(IpAddr::from_str("100.128.0.1").unwrap()));
    }

    #[test]
    fn test_unspecified_broadcast_multicast_blocked() {
        assert!(is_ip_restricted(IpAddr::from_str("0.0.0.0").unwrap()));
        assert!(is_ip_restricted(
            IpAddr::from_str("255.255.255.255").unwrap()
        ));
        assert!(is_ip_restricted(IpAddr::from_str("224.0.0.1").unwrap()));
        assert!(is_ip_restricted(IpAddr::from_str("::").unwrap()));
        assert!(is_ip_restricted(IpAddr::from_str("ff02::1").unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_blocked() {
        // ::ffff:127.0.0.1
        assert!(is_ip_restricted(
            IpAddr::from_str("::ffff:127.0.0.1").unwrap()
        ));
        // ::ffff:192.168.1.1
        assert!(is_ip_restricted(
            IpAddr::from_str("::ffff:192.168.1.1").unwrap()
        ));
        // ::ffff:169.254.169.254
        assert!(is_ip_restricted(
            IpAddr::from_str("::ffff:169.254.169.254").unwrap()
        ));
        // ::ffff:100.64.0.1
        assert!(is_ip_restricted(
            IpAddr::from_str("::ffff:100.64.0.1").unwrap()
        ));
    }

    #[test]
    fn test_legitimate_public_ips_allowed() {
        // Cloudflare DNS: 1.1.1.1
        assert!(!is_ip_restricted(IpAddr::from_str("1.1.1.1").unwrap()));
        // Google DNS: 8.8.8.8, 2001:4860:4860::8888
        assert!(!is_ip_restricted(IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(!is_ip_restricted(
            IpAddr::from_str("2001:4860:4860::8888").unwrap()
        ));
        // Random public IP
        assert!(!is_ip_restricted(
            IpAddr::from_str("93.184.216.34").unwrap()
        ));
    }

    #[tokio::test]
    async fn test_safe_dns_resolver_rejects_localhost() {
        let resolver = SafeDnsResolver::new();
        let name = Name::from_str("localhost").unwrap();
        let res = resolver.resolve(name).await;
        assert!(res.is_err());
    }
}
