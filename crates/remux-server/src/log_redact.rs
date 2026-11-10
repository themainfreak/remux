//! Masks credentials that addon and client URLs carry before a log line is written.
//!
//! Stremio-style addons put the debrid API key in the stream URL itself
//! (`/resolve/<service>/<key>/...`) or in the addon config (`realdebrid=<key>`), and
//! clients pass `api_key=` in query strings. Any log line that prints such a URL, or an
//! error that quotes one, would otherwise write the key in plain text. [`Redacting`]
//! wraps a writer so every formatted line is scrubbed, whatever field carried it.

use std::{borrow::Cow, io, sync::LazyLock};

use regex::Regex;
use tracing_subscriber::fmt::MakeWriter;

pub const MASK: &str = "<redacted>";

static RULES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // /resolve/<service>/<key>/...  (the key is the segment after the service)
        r"(?i)(/resolve/[a-z0-9_-]+/)[^/\s'\x22?#]+",
        // <debrid>=<key> in an addon config path, plain or URL-encoded '='
        r"(?i)((?:realdebrid|alldebrid|premiumize|debridlink|torbox|offcloud|putio|easydebrid)(?:=|%3D))[^|/&\s'\x22%,]+",
        // credentials in query strings
        r"(?i)([?&](?:api_?key|apikey|token|access_token|password)=)[^&\s'\x22#]+",
    ]
    .iter()
    .map(|r| Regex::new(r).expect("valid redaction regex"))
    .collect()
});

/// The line with every credential replaced by [`MASK`]; borrowed when nothing matched.
pub fn redact(line: &str) -> Cow<'_, str> {
    let mut out = Cow::Borrowed(line);
    for rule in RULES.iter() {
        if rule.is_match(&out) {
            out = Cow::Owned(rule.replace_all(&out, format!("${{1}}{MASK}")).into_owned());
        }
    }
    out
}

/// A [`MakeWriter`] whose writers scrub each write with [`redact`].
pub struct Redacting<M>(pub M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for Redacting<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter(self.0.make_writer())
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        RedactingWriter(self.0.make_writer_for(meta))
    }
}

/// Writes one formatted event at a time (the fmt layer hands over a whole line per
/// `write_all`), so a URL is never split across two calls.
pub struct RedactingWriter<W>(W);

impl<W: io::Write> io::Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match std::str::from_utf8(buf).map(redact) {
            Ok(Cow::Owned(clean)) => self.0.write_all(clean.as_bytes())?,
            _ => self.0.write_all(buf)?,
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn masks_the_key_segment_of_a_resolve_url() {
        let line = "WARN probe failed url=https://addon.example/resolve/realdebrid/ABCDEF123456/0f1e2d/null/0/Movie.mkv error=x";
        let out = redact(line);
        assert!(!out.contains("ABCDEF123456"), "{out}");
        assert!(out.contains("/resolve/realdebrid/<redacted>/0f1e2d/null/0/Movie.mkv"), "{out}");
    }

    #[test]
    fn masks_debrid_config_pairs_plain_and_encoded() {
        let out = redact("manifest https://addon.example/sort=qualitysize|realdebrid=KEY123|lang=en/manifest.json");
        assert!(out.contains("realdebrid=<redacted>|lang=en"), "{out}");
        let out = redact("GET /sort%3Dsize%7Ctorbox%3DKEY456%7Cfoo/manifest.json");
        assert!(out.contains("%7Ctorbox%3D<redacted>%7Cfoo"), "{out}");
    }

    #[test]
    fn masks_query_credentials_and_keeps_other_params() {
        let out = redact("uri=/Videos/1/stream?static=true&api_key=SECRET1&MediaSourceId=2");
        assert_eq!(out, "uri=/Videos/1/stream?static=true&api_key=<redacted>&MediaSourceId=2");
        assert!(!redact("x?token=abc&y=1").contains("abc"));
    }

    #[test]
    fn lines_without_credentials_are_untouched() {
        let line = "INFO pick movie:tt1 -> Some Movie 2010 1080p (resolve later)";
        assert!(matches!(redact(line), Cow::Borrowed(_)));
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

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
        let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("stream is suspiciously short"), "{text}");
        assert!(!text.contains("TOPSECRETKEY"), "{text}");
        assert!(text.contains("/resolve/realdebrid/<redacted>/abc"), "{text}");
    }
}
