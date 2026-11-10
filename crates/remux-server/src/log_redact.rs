//! Masks credentials before a log line is written.
//!
//! Stremio-style addons put the debrid API key in the stream URL itself
//! (`/resolve/<service>/<key>/...`) or in the addon config (`realdebrid=<key>`), clients
//! pass `api_key=` in query strings and `Authorization` / `X-Emby-Token` headers, and URLs
//! can carry `user:password@`. Any log line that prints such a URL or header, or an error
//! that quotes one, would otherwise write the secret in plain text. [`Redacting`] wraps a
//! writer so every formatted line is scrubbed, whatever field carried it.
//!
//! Covered forms:
//! - URL userinfo: `scheme://user:pass@` and `scheme://user@`
//! - `/resolve/<service>/<key>` path segments
//! - `<debrid>=<key>` addon config pairs (plain or `%3D`); `%XX` escapes are part of the
//!   key, the encoded config delimiters `%7C` (`|`) and `%26` (`&`) end it
//! - credential names in queries, log fields and header dumps (`?`, `&`, `;`, space, quote
//!   or `%3F`/`%26` before the name; `=`, `%3D` or `:` after it), the name itself possibly
//!   percent-encoded: api_key, apikey, api-key, x-api-key, access_token, refresh_token,
//!   client_secret, password, token, x-plex-token, x-emby-token, x-mediabrowser-token
//! - `Authorization: Bearer|Basic <secret>` and the Jellyfin/Emby `Token="<secret>"` form
//!
//! The writer buffers to the end of a line, so a secret split across `write` calls is
//! still caught, and decodes lossily, so undecodable bytes never pass through unchanged.

use std::{borrow::Cow, io, sync::LazyLock};

use regex::Regex;
use tracing_subscriber::fmt::MakeWriter;

pub const MASK: &str = "<redacted>";

/// Credential names masked in queries, log fields and header dumps.
const NAMES: &[&str] = &[
    "x-mediabrowser-token",
    "x-emby-token",
    "x-plex-token",
    "x-api-key",
    "client_secret",
    "refresh_token",
    "access_token",
    "api_key",
    "api-key",
    "apikey",
    "password",
    "token",
];

/// A regex for `s` where every character may also be written as its `%XX` escape.
fn encodable(s: &str) -> String {
    s.chars()
        .map(|c| format!("(?:{}|%{:02X})", regex::escape(&c.to_string()), c as u32))
        .collect()
}

/// A `%XX` escape that is not one of `excluded` (two hex digits each, upper case).
fn escape_except(excluded: &[&str]) -> String {
    let mut alts = Vec::new();
    for hi in "0123456789ABCDEF".chars() {
        for lo in "0123456789ABCDEF".chars() {
            let hex = format!("{hi}{lo}");
            if !excluded.contains(&hex.as_str()) {
                alts.push(hex);
            }
        }
    }
    format!("%(?:{})", alts.join("|"))
}

static RULES: LazyLock<Vec<(Regex, String)>> = LazyLock::new(|| {
    let keep = format!("${{1}}{MASK}");
    let names = NAMES.iter().map(|n| encodable(n)).collect::<Vec<_>>().join("|");
    let eq = encodable("=");
    let query_value = format!(r##"(?:{}|[^&\s'"#%,;])+"##, escape_except(&["26"]));
    let debrid_value = format!(r#"(?:{}|[^|/&\s'"%,])+"#, escape_except(&["7C", "26"]));
    let rules = [
        // scheme://user:pass@ and scheme://user@
        (r#"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@'"?#]+@"#.to_string(), format!("${{1}}{MASK}@")),
        // /resolve/<service>/<key>/...  (the key is the segment after the service)
        (r#"(?i)(/resolve/[a-z0-9_-]+/)[^/\s'"?#]+"#.to_string(), keep.clone()),
        // <debrid>=<key> in an addon config, plain or URL-encoded '='
        (
            format!(
                "(?i)((?:realdebrid|alldebrid|premiumize|debridlink|torbox|offcloud|putio|easydebrid)(?:{eq})){debrid_value}"
            ),
            keep.clone(),
        ),
        // Authorization: Bearer <secret> / Basic <secret>
        (
            r#"(?i)\b((?:proxy-)?authorization["']?\s*[:=]\s*["']?(?:bearer|basic)\s+)[^\s'",;]+"#
                .to_string(),
            keep.clone(),
        ),
        // Jellyfin/Emby authorization header: ..., Token="<secret>"
        (r#"(?i)\b(token\s*=\s*")[^"]*"#.to_string(), keep.clone()),
        // credential names in queries, fields and header dumps
        (
            format!(
                r#"(?i)((?:^|[?&;\s,{{("']|%3F|%26)(?:{names})["']?\s*(?:{eq}|:)\s*["']?){query_value}"#
            ),
            keep,
        ),
    ];
    rules
        .into_iter()
        .map(|(r, with)| (Regex::new(&r).expect("valid redaction regex"), with))
        .collect()
});

/// The line with every credential replaced by [`MASK`]; borrowed when nothing matched.
pub fn redact(line: &str) -> Cow<'_, str> {
    let mut out = Cow::Borrowed(line);
    for (rule, with) in RULES.iter() {
        if rule.is_match(&out) {
            out = Cow::Owned(rule.replace_all(&out, with.as_str()).into_owned());
        }
    }
    out
}

/// A [`MakeWriter`] whose writers scrub each line with [`redact`].
pub struct Redacting<M>(pub M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for Redacting<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter::new(self.0.make_writer())
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        RedactingWriter::new(self.0.make_writer_for(meta))
    }
}

/// Buffers to the end of each line and writes it redacted; a remainder without a newline
/// is redacted and written on `flush` and on drop.
pub struct RedactingWriter<W: io::Write> {
    inner: W,
    pending: Vec<u8>,
}

impl<W: io::Write> RedactingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            pending: Vec::new(),
        }
    }

    fn emit(&mut self, bytes: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(bytes);
        self.inner.write_all(redact(&text).as_bytes())
    }
}

impl<W: io::Write> io::Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while let Some(i) = self.pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=i).collect();
            self.emit(&line)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let rest = std::mem::take(&mut self.pending);
            self.emit(&rest)?;
        }
        self.inner.flush()
    }
}

impl<W: io::Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        let _ = io::Write::flush(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    fn clean(line: &str, secret: &str) -> String {
        let out = redact(line).into_owned();
        assert!(!out.contains(secret), "{secret} leaked: {out}");
        out
    }

    #[test]
    fn masks_the_key_segment_of_a_resolve_url() {
        let out = clean(
            "WARN probe failed url=https://addon.example/resolve/realdebrid/ABCDEF123456/0f1e2d/null/0/Movie.mkv error=x",
            "ABCDEF123456",
        );
        assert!(
            out.contains("/resolve/realdebrid/<redacted>/0f1e2d/null/0/Movie.mkv"),
            "{out}"
        );
    }

    #[test]
    fn masks_debrid_config_pairs_plain_and_encoded() {
        let out = clean(
            "manifest https://addon.example/sort=qualitysize|realdebrid=KEY123|lang=en/manifest.json",
            "KEY123",
        );
        assert!(out.contains("realdebrid=<redacted>|lang=en"), "{out}");
        let out = clean("GET /sort%3Dsize%7Ctorbox%3DKEY456%7Cfoo/manifest.json", "KEY456");
        assert!(out.contains("%7Ctorbox%3D<redacted>%7Cfoo"), "{out}");
    }

    #[test]
    fn percent_escapes_are_part_of_a_debrid_key() {
        // review (3): an escape inside the key must not end the match
        let out = clean("GET /realdebrid=ABC%2FSECRET1|lang=en/manifest.json", "SECRET1");
        assert!(out.contains("realdebrid=<redacted>|lang=en"), "{out}");
        clean("GET /realdebrid=%41SECRET2/manifest.json", "SECRET2");
        // the encoded delimiters still end it
        let out = clean("GET /realdebrid%3DSECRET3%7Clang%3Den/x", "SECRET3");
        assert!(out.contains("%7Clang%3Den"), "{out}");
    }

    #[test]
    fn masks_url_userinfo() {
        // review (1)
        let out = clean("fetch https://alice:SECRET4@host.example/path", "SECRET4");
        assert!(out.contains("https://<redacted>@host.example/path"), "{out}");
        let out = clean("fetch ftp://TOKENUSER5@host.example/", "TOKENUSER5");
        assert!(out.contains("ftp://<redacted>@host.example/"), "{out}");
    }

    #[test]
    fn masks_query_credentials_and_keeps_other_params() {
        let out = redact("uri=/Videos/1/stream?static=true&api_key=SECRET1&MediaSourceId=2");
        assert_eq!(
            out,
            "uri=/Videos/1/stream?static=true&api_key=<redacted>&MediaSourceId=2"
        );
        clean("x?token=abc123&y=1", "abc123");
        clean("x?ApiKey=SECRET6", "SECRET6");
        clean("x?client_secret=SECRET7&a=1", "SECRET7");
        clean("x?X-Plex-Token=SECRET8", "SECRET8");
        clean("x?refresh_token=SECRET9", "SECRET9");
    }

    #[test]
    fn masks_percent_encoded_query_names() {
        // review (4)
        clean("GET /x?%61pi_key=SECRET10", "SECRET10");
        clean("next=%2Fweb%3Fapi_key%3DSECRET11%26x%3D1", "SECRET11");
        let out = clean("u=%3Fapi_key%3DSECRET12%26x%3D1", "SECRET12");
        assert!(out.contains("%26x%3D1"), "{out}");
    }

    #[test]
    fn masks_header_and_field_forms() {
        // review (2) and (5)
        clean("Authorization: Bearer SECRET13", "SECRET13");
        clean("authorization=\"Basic SECRET14\"", "SECRET14");
        clean(
            "X-Emby-Authorization: MediaBrowser Client=\"Kodi\", Device=\"box\", Token=\"SECRET15\"",
            "SECRET15",
        );
        clean("headers={\"x-emby-token\": \"SECRET16\", \"accept\": \"*/*\"}", "SECRET16");
        clean("X-Api-Key: SECRET17", "SECRET17");
        clean("x-mediabrowser-token=SECRET18", "SECRET18");
        let out = clean("WARN login api_key=\"SECRET19\" user=bob", "SECRET19");
        assert!(out.contains("user=bob"), "{out}");
        clean("password: SECRET20", "SECRET20");
    }

    #[test]
    fn lines_without_credentials_are_untouched() {
        let line = "INFO pick movie:tt1 -> Some Movie 2010 1080p (resolve later)";
        assert!(matches!(redact(line), Cow::Borrowed(_)));
        let line = "INFO GET /Items/abc?Fields=Overview&Limit=20 200";
        assert!(matches!(redact(line), Cow::Borrowed(_)));
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Sink {
        fn bytes(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
    }

    impl io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn invalid_utf8_is_decoded_lossily_and_still_redacted() {
        // review (6)
        let sink = Sink::default();
        {
            let mut w = RedactingWriter::new(sink.clone());
            w.write_all(b"GET /x?api_key=SECRET21\xff&y=1\n").unwrap();
            w.write_all(b"\xfe url=https://a.example/resolve/realdebrid/SECRET22/x\n")
                .unwrap();
        }
        let out = sink.bytes();
        assert!(!out.contains(&0xff) && !out.contains(&0xfe), "raw bytes passed through");
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("SECRET21") && !text.contains("SECRET22"), "{text}");
    }

    #[test]
    fn a_secret_split_across_writes_is_still_masked() {
        // review (7): every split point, inside names and inside values
        let line = "WARN probe url=https://h.example/resolve/realdebrid/SPLITKEY1/x?api_key=SPLITKEY2&a=1 auth=\"Authorization: Bearer SPLITKEY3\"\n";
        for i in 0..=line.len() {
            let sink = Sink::default();
            {
                let mut w = RedactingWriter::new(sink.clone());
                w.write_all(line[..i].as_bytes()).unwrap();
                w.write_all(line[i..].as_bytes()).unwrap();
            }
            let text = String::from_utf8(sink.bytes()).unwrap();
            for s in ["SPLITKEY1", "SPLITKEY2", "SPLITKEY3"] {
                assert!(!text.contains(s), "split at {i}: {s} leaked: {text}");
            }
            assert!(text.ends_with('\n'), "split at {i}: {text}");
        }
    }

    #[test]
    fn a_remainder_without_newline_is_redacted_on_flush_and_drop() {
        let sink = Sink::default();
        let mut w = RedactingWriter::new(sink.clone());
        w.write_all(b"x?api_").unwrap();
        w.write_all(b"key=SECRET23").unwrap();
        assert!(sink.bytes().is_empty(), "nothing is written before the line ends");
        w.flush().unwrap();
        let text = String::from_utf8(sink.bytes()).unwrap();
        assert_eq!(text, "x?api_key=<redacted>");
        let sink = Sink::default();
        {
            let mut w = RedactingWriter::new(sink.clone());
            w.write_all(b"x?token=SECRET24").unwrap();
        }
        assert_eq!(String::from_utf8(sink.bytes()).unwrap(), "x?token=<redacted>");
    }

    #[test]
    fn a_tracing_event_is_written_redacted() {
        use tracing_subscriber::prelude::*;

        let sink = Sink::default();
        let writer = sink.clone();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(Redacting(move || writer.clone())),
        );
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                url = %"https://addon.example/resolve/realdebrid/TOPSECRETKEY/abc/null/0/f.mkv",
                "stream is suspiciously short"
            );
        });
        let text = String::from_utf8(sink.bytes()).unwrap();
        assert!(text.contains("stream is suspiciously short"), "{text}");
        assert!(!text.contains("TOPSECRETKEY"), "{text}");
        assert!(text.contains("/resolve/realdebrid/<redacted>/abc"), "{text}");
    }
}
