//! Terminal-safe rendering of untrusted filename bytes.
//!
//! Unix filenames are arbitrary bytes and a terminal *executes* control
//! sequences. A file named with an `OSC 52` escape rewrites the clipboard when
//! listed; one containing a newline forges an extra row in the table. This is
//! the ONLY route from raw manifest bytes to stdout.
//!
//! Two traps this avoids:
//!   1. Bytes, not `String`. `path.to_str().unwrap()` panics on a non-UTF-8
//!      filename — a denial-of-service on your own listing. We take `&[u8]`.
//!   2. Display only, never storage. Sanitizing before writing the manifest
//!      would destroy the real filename and `-d` could never restore it. The
//!      manifest stores raw bytes; this is display-only.

/// Bidi override/isolate codepoints, UTF-8 encoded: U+202A..=U+202E, U+2066..=U+2069
const BIDI: [&[u8]; 9] = [
    b"\xe2\x80\xaa",
    b"\xe2\x80\xab",
    b"\xe2\x80\xac",
    b"\xe2\x80\xad",
    b"\xe2\x80\xae",
    b"\xe2\x81\xa6",
    b"\xe2\x81\xa7",
    b"\xe2\x81\xa8",
    b"\xe2\x81\xa9",
];

/// Render untrusted bytes safe for a terminal. Each removed byte becomes `?`,
/// so a tampered name is visibly tampered rather than silently cleaned.
pub fn safe(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        if b < 0x20 || b == 0x7f {
            // C0 controls + DEL — covers ESC, CR, LF, TAB, NUL
            out.push(b'?');
            i += 1;
        } else if b == 0xc2 && raw.get(i + 1).is_some_and(|&n| (0x80..=0x9f).contains(&n)) {
            // C1 controls, UTF-8 encoded as C2 80..9F
            out.push(b'?');
            i += 2;
        } else if b == 0xe2 && BIDI.contains(&&raw[i..(i + 3).min(raw.len())]) {
            out.push(b'?');
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    // Invalid UTF-8 becomes U+FFFD. Never panics on a weird filename.
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::safe;

    #[test]
    fn neutralises_terminal_escapes() {
        // OSC 52 clipboard hijack, OSC 8 link, OSC 0 title, CSI line overwrite
        assert!(!safe(b"\x1b]52;c;aGk=\x07x").contains('\x1b'));
        assert!(!safe(b"\x1b]8;;http://evil\x07link\x1b]8;;\x07").contains('\x1b'));
        assert!(!safe(b"\x1b]0;pwned\x07").contains('\x1b'));
        assert!(!safe(b"\x1b[2K\x1b[1Gfake").contains('\x1b'));
    }

    #[test]
    fn no_escape_byte_survives() {
        for b in 0u8..=0x1f {
            assert_eq!(safe(&[b, b'a']), "?a", "byte {b:#x} leaked");
        }
        assert_eq!(safe(b"\x7f"), "?");
        // C1 (0x80..0x9f) encoded as C2 80..9F
        assert_eq!(safe(b"\xc2\x9b" /* CSI */), "?");
    }

    #[test]
    fn does_not_panic_on_invalid_utf8() {
        let _ = safe(b"\xff\xfe\x00\x80");
        let _ = safe(&[0xc2]); // truncated multibyte
        let _ = safe(&[0xe2, 0x80]); // truncated bidi
    }

    #[test]
    fn preserves_legitimate_names() {
        let name = "rapport_été_🔐.pdf".as_bytes();
        assert_eq!(safe(name), "rapport_été_🔐.pdf");
    }

    #[test]
    fn empty_input_is_empty() {
        assert_eq!(safe(b""), "");
    }

    #[test]
    fn marks_removals_visibly() {
        // CR overprint and embedded newline (forged table row) both become ?
        assert_eq!(safe(b"a\rb"), "a?b");
        assert_eq!(safe(b"a\nb"), "a?b");
        // bidi spoof
        assert_eq!(safe("a\u{202e}b".as_bytes()), "a?b");
    }
}
