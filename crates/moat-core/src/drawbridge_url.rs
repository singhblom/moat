//! Drawbridge URLs in the one form a device dials, signs and compares.

use std::fmt;

use crate::{Error, Result};

/// A Drawbridge URL in normal form: `ws://` or `wss://`, a lowercase host
/// without the scheme's default port, and a path. [`parse`](Self::parse) is
/// the only way to make one, so two values are equal exactly when they name
/// the same Drawbridge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DrawbridgeUrl(String);

impl DrawbridgeUrl {
    /// Read a URL as typed, scanned, configured or found in a record. A bare
    /// host is read as `wss://<host>/ws` and a URL with no path as `<url>/ws`.
    pub fn parse(input: &str) -> Result<Self> {
        let bad = |why: &str| Error::InvalidDrawbridgeUrl(format!("{input:?} {why}"));
        let input = input.trim();
        let (scheme, rest) = match input.split_once("://") {
            Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
            None => ("wss".to_string(), input),
        };
        let default_port = match scheme.as_str() {
            "wss" => ":443",
            "ws" => ":80",
            _ => return Err(bad("must start with ws:// or wss://")),
        };
        if rest.contains(['?', '#']) || rest.chars().any(char::is_whitespace) {
            return Err(bad("must be a host and a path only"));
        }
        let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let host = host.to_ascii_lowercase();
        let host = host.strip_suffix(default_port).unwrap_or(&host);
        if host.is_empty() || host.contains('@') {
            return Err(bad("has no usable host"));
        }
        let path = if path.is_empty() || path == "/" { "/ws" } else { path };
        Ok(Self(format!("{scheme}://{host}{path}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DrawbridgeUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_of_one_drawbridge_parse_equal() {
        for (typed, want) in [
            ("wss://drawbridge.example.com/ws", "wss://drawbridge.example.com/ws"),
            ("drawbridge.example.com", "wss://drawbridge.example.com/ws"),
            ("  drawbridge.example.com/ws  ", "wss://drawbridge.example.com/ws"),
            ("WSS://Drawbridge.Example.com", "wss://drawbridge.example.com/ws"),
            ("wss://drawbridge.example.com:443/ws", "wss://drawbridge.example.com/ws"),
            ("ws://127.0.0.1:80", "ws://127.0.0.1/ws"),
            ("ws://127.0.0.1:8080", "ws://127.0.0.1:8080/ws"),
            ("ws://127.0.0.1:8080/", "ws://127.0.0.1:8080/ws"),
            ("wss://drawbridge.example.com:4430/ws", "wss://drawbridge.example.com:4430/ws"),
            ("wss://drawbridge.example.com/custom", "wss://drawbridge.example.com/custom"),
        ] {
            assert_eq!(DrawbridgeUrl::parse(typed).unwrap().as_str(), want, "{typed:?}");
        }
    }

    #[test]
    fn what_is_not_a_drawbridge_does_not_parse() {
        for typed in [
            "",
            "   ",
            "https://drawbridge.example.com",
            "wss://",
            "ws:///ws",
            "a b",
            "wss://drawbridge.example.com/ws?x=1",
            "wss://drawbridge.example.com/ws#top",
            "wss://user@drawbridge.example.com/ws",
        ] {
            assert!(DrawbridgeUrl::parse(typed).is_err(), "{typed:?}");
        }
    }
}
