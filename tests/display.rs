//! The display sanitizer, exercised through the public API. Terminal escapes in
//! a filename must never reach stdout intact; legitimate names must survive.

use cloakit::util::display::safe;

#[test]
fn neutralises_terminal_escapes() {
    assert!(!safe(b"\x1b]52;c;aGk=\x07x").contains('\x1b'), "OSC 52");
    assert!(
        !safe(b"\x1b]8;;http://evil\x07x\x1b]8;;\x07").contains('\x1b'),
        "OSC 8"
    );
    assert!(!safe(b"\x1b[2K\x1b[1Gfake").contains('\x1b'), "CSI");
}

#[test]
fn preserves_legitimate_names() {
    assert_eq!(safe("rapport_été_🔐.pdf".as_bytes()), "rapport_été_🔐.pdf");
}

#[test]
fn does_not_panic_on_invalid_utf8() {
    let _ = safe(b"\xff\xfe\x00\x80");
    let _ = safe(&[0xc2]);
    let _ = safe(&[0xe2, 0x80]);
}

#[test]
fn marks_removals_visibly() {
    assert_eq!(safe(b"a\nb"), "a?b", "embedded newline (forged row)");
    assert_eq!(safe("a\u{202e}b".as_bytes()), "a?b", "bidi spoof");
}
