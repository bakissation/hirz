//! Display helpers. Names shown here come from websites and other devices, so they are
//! cleaned before reaching the terminal.

/// Characters that change how surrounding text is displayed without being visible.
fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// Removes control and invisible characters, collapses whitespace and shortens the text to
/// at most `max_chars` characters.
pub fn clean(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_chars.saturating_mul(4)));
    let mut count = 0usize;
    let mut last_space = true;
    let mut truncated = false;
    for c in s.chars() {
        if invisible(c) {
            continue;
        }
        let c = if c.is_control() || c.is_whitespace() {
            ' '
        } else {
            c
        };
        if c == ' ' {
            if last_space {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        if count >= max_chars {
            truncated = true;
            break;
        }
        out.push(c);
        count = count.saturating_add(1);
    }
    if truncated {
        while out.ends_with(' ') {
            out.pop();
        }
        if max_chars > 3 {
            for _ in 0..3 {
                out.pop();
            }
            out.push_str("...");
        }
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

pub use hirz_proto::hex::encode as hex;

/// The start of an id as `hirz list`, `hirz devices` and `hirz devices approve` show it.
pub fn short_id(id: &[u8]) -> String {
    const SHOWN_HEX: usize = 12;
    let mut h = hex(id);
    h.truncate(SHOWN_HEX);
    h
}

/// Normalises a user-typed id prefix: lowercase hex digits, at least 4, at most a whole
/// credential id.
pub fn hex_prefix(input: &str) -> Option<String> {
    let p: String = input.trim().to_ascii_lowercase();
    let max = hirz_vault::MAX_CREDENTIAL_ID_LEN.saturating_mul(2);
    (p.len() >= 4 && p.len() <= max && p.bytes().all(|b| b.is_ascii_hexdigit())).then_some(p)
}

/// `YYYY-MM-DD` (UTC) for a unix time in seconds.
pub fn date(unix: u64) -> String {
    let days = unix / 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 to a proleptic Gregorian date (H. Hinnant's algorithm), for days
/// after the epoch.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days.saturating_add(719_468);
    let era = z / 146_097;
    let doe = z.saturating_sub(era.saturating_mul(146_097));
    let yoe = doe
        .saturating_sub(doe / 1460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096)
        / 365;
    let y = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = doy.saturating_mul(5).saturating_add(2) / 153;
    let d = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let y = if m <= 2 { y.saturating_add(1) } else { y };
    (y, m, d)
}

pub use hirz_proto::time::unix_now as now;

/// Renders rows as left-aligned columns separated by two spaces.
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row.iter()) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let mut line = |cells: &mut dyn Iterator<Item = &str>| {
        let mut l = String::new();
        for (i, (cell, w)) in cells.zip(widths.iter()).enumerate() {
            if i > 0 {
                l.push_str("  ");
            }
            l.push_str(cell);
            let pad = w.saturating_sub(cell.chars().count());
            l.extend(core::iter::repeat_n(' ', pad));
        }
        out.push_str(l.trim_end());
        out.push('\n');
    };
    line(&mut header.iter().copied());
    for row in rows {
        line(&mut row.iter().map(String::as_str));
    }
    out
}

/// Plural helper: `count(3, "passkey")` is "3 passkeys".
pub fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// A credential's RP id for people: OpenSSH keys read "SSH key (NAME)", see
/// [`hirz_uv::display::site_label_with`]. JSON output keeps the raw RP id.
pub fn site(rp_id: &str, max_chars: usize) -> String {
    hirz_uv::display::site_label_with(rp_id, |s| clean(s, max_chars))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn clean_removes_controls_and_bidi() {
        assert_eq!(clean("a\u{202e}b\nc\td", 40), "ab c d");
        assert_eq!(clean("  x   y  ", 40), "x y");
        assert_eq!(clean("\u{1b}[31mred", 40), "[31mred");
        assert_eq!(clean("abcdefghij", 6), "abc...");
        assert_eq!(clean("abc", 3), "abc");
    }

    #[test]
    fn ssh_sites() {
        assert_eq!(site("ssh:", 40), "SSH key");
        assert_eq!(site("ssh:git\u{202e}hub", 40), "SSH key (github)");
        assert_eq!(site("ssh:abcdefghij", 6), "SSH key (abc...)");
        assert_eq!(site("example.com", 40), "example.com");
    }

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_700_000_000), "2023-11-14");
        assert_eq!(date(4_102_444_800), "2100-01-01");
    }

    #[test]
    fn prefixes() {
        assert_eq!(hex_prefix(" ABcd12 ").unwrap(), "abcd12");
        assert!(hex_prefix("abc").is_none());
        assert!(hex_prefix("zzzz").is_none());
        assert!(hex_prefix(&"ab".repeat(1023)).is_some());
        assert!(hex_prefix(&"ab".repeat(1024)).is_none());
        assert_eq!(hex(&[0x0f, 0xa0]), "0fa0");
    }

    #[test]
    fn table_layout() {
        let t = table(&["A", "BB"], &[vec!["xyz".into(), "1".into()]]);
        assert_eq!(t, "A    BB\nxyz  1\n");
        assert_eq!(count(1, "passkey"), "1 passkey");
        assert_eq!(count(2, "passkey"), "2 passkeys");
    }
}
