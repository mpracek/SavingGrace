//! GUID text parsing (adapter identifiers on Windows look like `{1CA18531-B5FA-4A92-837A-AE12298FFF7F}`).

/// Returns (data1, data2, data3, data4) or `None` if the text is not a well-formed GUID.
pub fn parse_guid(s: &str) -> Option<(u32, u16, u16, [u8; 8])> {
    let t = s.trim().trim_start_matches('{').trim_end_matches('}');
    let parts: Vec<&str> = t.split('-').collect();
    if parts.len() != 5
        || [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .any(|(n, p)| p.len() != *n)
    {
        return None;
    }
    let d1 = u32::from_str_radix(parts[0], 16).ok()?;
    let d2 = u16::from_str_radix(parts[1], 16).ok()?;
    let d3 = u16::from_str_radix(parts[2], 16).ok()?;
    let tail = format!("{}{}", parts[3], parts[4]);
    let mut d4 = [0u8; 8];
    for (i, b) in d4.iter_mut().enumerate() {
        *b = u8::from_str_radix(tail.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some((d1, d2, d3, d4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_braced_and_bare_guids() {
        let want = (
            0x1CA18531,
            0xB5FA,
            0x4A92,
            [0x83, 0x7A, 0xAE, 0x12, 0x29, 0x8F, 0xFF, 0x7F],
        );
        assert_eq!(
            parse_guid("{1CA18531-B5FA-4A92-837A-AE12298FFF7F}"),
            Some(want)
        );
        assert_eq!(
            parse_guid("1ca18531-b5fa-4a92-837a-ae12298fff7f"),
            Some(want)
        );
    }

    #[test]
    fn rejects_malformed_guids() {
        for bad in [
            "",
            "{}",
            "1234",
            "{1CA18531-B5FA-4A92-837A-AE12298FFF7}",
            "{1CA18531-B5FA-4A92-837A-AE12298FFF7G}",
            "{1CA18531B5FA4A92837AAE12298FFF7F}",
            "{1CA18531-B5FA-4A92-837A-AE12298FFF7F-00}",
        ] {
            assert_eq!(parse_guid(bad), None, "{bad}");
        }
    }
}
