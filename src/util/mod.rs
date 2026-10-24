//! Small shared helpers: atomic writes, passphrase prompts, terminal-safe
//! display, hex encoding, and human-readable sizes.

pub mod atomic;
pub mod display;
pub mod prompt;

use anyhow::{Result, bail};

/// Lowercase hex encode.
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // writing to a String never fails
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode lowercase/uppercase hex. Errors on odd length or non-hex bytes.
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        bail!("hex string has odd length");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = hex_val(b[i])?;
        let lo = hex_val(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => bail!("invalid hex byte: {:#x}", c),
    }
}

/// Human-readable byte count, e.g. `1.2 MiB`.
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut val = n as f64;
    let mut unit = 0;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    format!("{val:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips() {
        let data = [0x00, 0x1f, 0xa0, 0xff, 0x42];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "001fa0ff42");
        assert_eq!(hex_decode(&encoded).unwrap(), data);
    }

    #[test]
    fn hex_rejects_garbage() {
        assert!(hex_decode("abc").is_err()); // odd
        assert!(hex_decode("zz").is_err()); // non-hex
    }

    #[test]
    fn sizes_format() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1_572_864), "1.5 MiB");
    }
}
