//! HTTP protocol analysis and filtering

use super::{AnalyzerStats, L7Protocol, PacketMeta, ProtocolAnalyzer, Verdict};
use parking_lot::RwLock;
use pistonprotection_common::error::Result;
use tracing::debug;

/// HTTP methods
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Connect,
    Trace,
    Unknown,
}

impl HttpMethod {
    fn from_bytes(bytes: &[u8]) -> Self {
        match bytes {
            b"GET" => HttpMethod::Get,
            b"POST" => HttpMethod::Post,
            b"PUT" => HttpMethod::Put,
            b"DELETE" => HttpMethod::Delete,
            b"HEAD" => HttpMethod::Head,
            b"OPTIONS" => HttpMethod::Options,
            b"PATCH" => HttpMethod::Patch,
            b"CONNECT" => HttpMethod::Connect,
            b"TRACE" => HttpMethod::Trace,
            _ => HttpMethod::Unknown,
        }
    }
}

/// Check if payload is HTTP/1.x
pub fn is_http(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }

    // Check for HTTP request methods
    let methods = [
        b"GET ".as_slice(),
        b"POST".as_slice(),
        b"PUT ".as_slice(),
        b"HEAD".as_slice(),
        b"DELE".as_slice(), // DELETE
        b"OPTI".as_slice(), // OPTIONS
        b"PATC".as_slice(), // PATCH
        b"CONN".as_slice(), // CONNECT
        b"TRAC".as_slice(), // TRACE
    ];

    for method in &methods {
        if payload.starts_with(method) {
            return true;
        }
    }

    // Check for HTTP response
    if payload.starts_with(b"HTTP/") {
        return true;
    }

    false
}

/// Check if payload is HTTP/2
pub fn is_http2(payload: &[u8]) -> bool {
    // HTTP/2 connection preface
    const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    if payload.len() >= H2_PREFACE.len() {
        return payload.starts_with(H2_PREFACE);
    }

    // Could also be an HTTP/2 frame (after preface)
    // HTTP/2 frames start with a 9-byte header
    if payload.len() >= 9 {
        // Check for valid frame type (0-9 are defined, 10+ are extensions)
        let frame_type = payload[3];
        if frame_type <= 9 {
            // Could be HTTP/2, but not definitive
            return false;
        }
    }

    false
}

/// Parse HTTP/1.x request line
pub fn parse_request_line(payload: &[u8]) -> Option<(HttpMethod, &[u8], &[u8])> {
    // Find end of request line
    let line_end = payload.iter().position(|&b| b == b'\r' || b == b'\n')?;
    let line = &payload[..line_end];

    // Split by spaces: METHOD PATH VERSION
    let mut parts = line.splitn(3, |&b| b == b' ');

    let method_bytes = parts.next()?;
    let path = parts.next()?;
    let version = parts.next()?;

    let method = HttpMethod::from_bytes(method_bytes);

    Some((method, path, version))
}

/// Parse a header value from HTTP payload
pub fn get_header<'a>(payload: &'a [u8], header_name: &[u8]) -> Option<&'a [u8]> {
    // Find the header in the payload
    let header_name_lower: Vec<u8> = header_name.iter().map(|b| b.to_ascii_lowercase()).collect();

    let mut i = 0;
    while i < payload.len() {
        // Find next line
        let line_start = i;
        while i < payload.len() && payload[i] != b'\r' && payload[i] != b'\n' {
            i += 1;
        }

        let line = &payload[line_start..i];

        // Skip CRLF
        if i < payload.len() && payload[i] == b'\r' {
            i += 1;
        }
        if i < payload.len() && payload[i] == b'\n' {
            i += 1;
        }

        // Empty line means end of headers
        if line.is_empty() {
            break;
        }

        // Check if this line starts with our header
        if let Some(colon_pos) = line.iter().position(|&b| b == b':') {
            let name = &line[..colon_pos];
            let name_lower: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();

            if name_lower == header_name_lower {
                // Skip colon and optional whitespace
                let mut value_start = colon_pos + 1;
                while value_start < line.len() && (line[value_start] == b' ' || line[value_start] == b'\t') {
                    value_start += 1;
                }
                return Some(&line[value_start..]);
            }
        }
    }

    None
}

/// HTTP/1.x protocol analyzer
pub struct HttpAnalyzer {
    stats: RwLock<AnalyzerStats>,
    /// Maximum request size
    max_request_size: usize,
    /// Maximum header size
    max_header_size: usize,
    /// Blocked user agents
    blocked_user_agents: Vec<String>,
    /// Allowed methods
    allowed_methods: Vec<HttpMethod>,
}

impl HttpAnalyzer {
    pub fn new() -> Self {
        Self {
            stats: RwLock::new(AnalyzerStats::default()),
            max_request_size: 10 * 1024 * 1024, // 10MB
            max_header_size: 8192,
            blocked_user_agents: vec![
                "python-requests".to_string(),
                "curl".to_string(),
                "wget".to_string(),
            ],
            allowed_methods: vec![
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Put,
                HttpMethod::Delete,
                HttpMethod::Head,
                HttpMethod::Options,
                HttpMethod::Patch,
            ],
        }
    }

    /// Check if user agent is blocked
    fn is_user_agent_blocked(&self, user_agent: &[u8]) -> bool {
        let ua_lower = String::from_utf8_lossy(user_agent).to_lowercase();

        for blocked in &self.blocked_user_agents {
            if ua_lower.contains(&blocked.to_lowercase()) {
                return true;
            }
        }

        false
    }
}

impl ProtocolAnalyzer for HttpAnalyzer {
    fn protocol(&self) -> L7Protocol {
        L7Protocol::Http
    }

    fn can_handle(&self, meta: &PacketMeta, payload: &[u8]) -> bool {
        is_http(payload)
    }

    fn analyze(&self, meta: &PacketMeta, payload: &[u8]) -> Result<Verdict> {
        let mut stats = self.stats.write();
        stats.packets_analyzed += 1;
        stats.bytes_analyzed += payload.len() as u64;

        // Check request size
        if payload.len() > self.max_request_size {
            debug!(src = %meta.src_ip, size = payload.len(), "HTTP request too large");
            stats.packets_dropped += 1;
            return Ok(Verdict::Drop);
        }

        // Parse request line
        if let Some((method, path, version)) = parse_request_line(payload) {
            // Check if method is allowed
            if !self.allowed_methods.contains(&method) {
                debug!(src = %meta.src_ip, method = ?method, "HTTP method not allowed");
                stats.packets_dropped += 1;
                return Ok(Verdict::Drop);
            }

            // Check user agent
            if let Some(user_agent) = get_header(payload, b"User-Agent") {
                if self.is_user_agent_blocked(user_agent) {
                    debug!(
                        src = %meta.src_ip,
                        user_agent = %String::from_utf8_lossy(user_agent),
                        "Blocked user agent"
                    );
                    stats.packets_dropped += 1;
                    return Ok(Verdict::Drop);
                }
            }

            // Check for suspicious paths
            let path_str = String::from_utf8_lossy(path);
            if path_str.contains("..") || path_str.contains("//") {
                debug!(src = %meta.src_ip, path = %path_str, "Suspicious path");
                stats.packets_dropped += 1;
                return Ok(Verdict::Drop);
            }
        }

        stats.packets_passed += 1;
        Ok(Verdict::Pass)
    }

    fn stats(&self) -> AnalyzerStats {
        self.stats.read().clone()
    }
}

/// HTTP/2 protocol analyzer
pub struct Http2Analyzer {
    stats: RwLock<AnalyzerStats>,
}

impl Http2Analyzer {
    pub fn new() -> Self {
        Self {
            stats: RwLock::new(AnalyzerStats::default()),
        }
    }
}

impl ProtocolAnalyzer for Http2Analyzer {
    fn protocol(&self) -> L7Protocol {
        L7Protocol::Http2
    }

    fn can_handle(&self, _meta: &PacketMeta, payload: &[u8]) -> bool {
        is_http2(payload)
    }

    fn analyze(&self, meta: &PacketMeta, payload: &[u8]) -> Result<Verdict> {
        let mut stats = self.stats.write();
        stats.packets_analyzed += 1;
        stats.bytes_analyzed += payload.len() as u64;

        // HTTP/2 analysis would require stateful frame parsing
        // For now, just pass valid HTTP/2 traffic

        stats.packets_passed += 1;
        Ok(Verdict::Pass)
    }

    fn stats(&self) -> AnalyzerStats {
        self.stats.read().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http() {
        assert!(is_http(b"GET / HTTP/1.1\r\n"));
        assert!(is_http(b"POST /api HTTP/1.1\r\n"));
        assert!(is_http(b"HTTP/1.1 200 OK\r\n"));
        assert!(!is_http(b"not http"));
    }

    #[test]
    fn test_parse_request_line() {
        let request = b"GET /path/to/resource HTTP/1.1\r\nHost: example.com\r\n";
        let (method, path, version) = parse_request_line(request).unwrap();

        assert_eq!(method, HttpMethod::Get);
        assert_eq!(path, b"/path/to/resource");
        assert_eq!(version, b"HTTP/1.1");
    }

    #[test]
    fn test_get_header() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test/1.0\r\n\r\n";

        let host = get_header(request, b"Host").unwrap();
        assert_eq!(host, b"example.com");

        let ua = get_header(request, b"User-Agent").unwrap();
        assert_eq!(ua, b"test/1.0");

        assert!(get_header(request, b"X-Not-Found").is_none());
    }

    #[test]
    fn test_is_http2() {
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        assert!(is_http2(preface));
        assert!(!is_http2(b"GET / HTTP/1.1\r\n"));
    }
}
