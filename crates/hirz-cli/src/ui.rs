//! Display helpers. Names shown here come from websites and other devices, so they are
//! cleaned before reaching the terminal.

/// The same list the approval windows use (`hirz_uv::display::is_invisible`).
fn invisible(c: char) -> bool {
    hirz_uv::display::is_invisible(c)
}

pub fn clean(s: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_chars.saturating_mul(4)));
    let mut count = 0usize;
    let mut last_space = true;
    let mut truncated = false;
    let mut marks = hirz_uv::display::MAX_COMBINING_MARKS;
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
            marks = hirz_uv::display::MAX_COMBINING_MARKS;
        } else {
            last_space = false;
            if hirz_uv::display::is_combining(c) {
                if marks >= hirz_uv::display::MAX_COMBINING_MARKS {
                    continue;
                }
                marks = marks.saturating_add(1);
            } else {
                marks = 0;
            }
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

/// Writes DEL, the C1 controls and invisible or direction-changing characters of JSON text as
/// `\uXXXX`, so a terminal never acts on them. They occur only inside strings, and the JSON
/// means the same afterwards. A character beyond the first plane is written as the UTF-16 pair
/// JSON asks for (U+E0067 is `\udb40\udc67`), never as one five-digit escape.
pub fn escape_json_controls(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if ('\u{7f}'..='\u{9f}').contains(&c) || invisible(c) {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A path for a message: control and invisible characters in names the user did not type become `?`.
pub fn path_text(p: &std::path::Path) -> String {
    p.to_string_lossy()
        .chars()
        .map(|c| {
            if c.is_control() || invisible(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

pub use hirz_proto::hex::encode as hex;

pub const SHORT_ID_DIGITS: usize = 12;

pub fn short_id(id: &[u8]) -> String {
    id_prefix(id, SHORT_ID_DIGITS)
}

pub fn id_prefix(id: &[u8], digits: usize) -> String {
    let mut h = hex(id);
    h.truncate(digits);
    h
}

/// How many hex digits tell these ids apart, at least what `short_id` shows. Lists that ask the
/// user to type a longer prefix print this many, so the prefix can be read off the list.
pub fn distinct_digits(ids: &[&[u8]]) -> usize {
    let hexes: Vec<String> = ids.iter().map(|id| hex(id)).collect();
    let longest = hexes.iter().map(String::len).max().unwrap_or(0);
    (SHORT_ID_DIGITS..=longest.max(SHORT_ID_DIGITS))
        .find(|n| {
            let shown: std::collections::BTreeSet<&str> = hexes
                .iter()
                .map(|h| h.get(..*n).unwrap_or(h.as_str()))
                .collect();
            shown.len() == hexes.len()
        })
        .unwrap_or(longest)
}

/// Normalises a user-typed id prefix: lowercase hex digits, at least 4, at most a whole
/// credential id.
pub fn hex_prefix(input: &str) -> Option<String> {
    let p: String = input.trim().to_ascii_lowercase();
    let max = hirz_vault::MAX_CREDENTIAL_ID_LEN.saturating_mul(2);
    (p.len() >= 4 && p.len() <= max && p.bytes().all(|b| b.is_ascii_hexdigit())).then_some(p)
}

pub fn date(unix: u64) -> String {
    let days = unix / 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 to a proleptic Gregorian date (H. Hinnant's algorithm); after the epoch only.
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

pub fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// OpenSSH keys read "SSH key (NAME)" (see [`hirz_uv::display::site_label_with`]); JSON output keeps the raw RP id.
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
    fn names_cannot_hide_behind_blank_glyphs_or_stacked_marks() {
        assert_eq!(clean("a\u{2800}\u{2800}b", 40), "ab");
        assert_eq!(clean("a\u{3164}b\u{115f}c\u{206a}d\u{1bca0}e", 40), "abcde");
        assert_eq!(clean("x\u{e0041}\u{fe0f}y", 40), "xy");
        let stacked = format!("e{}", "\u{0301}".repeat(60));
        assert_eq!(clean(&stacked, 40), "e\u{0301}\u{0301}");
        assert_eq!(clean("\u{0301}\u{0301}abc", 40), "abc");
        assert_eq!(clean("a \u{0301}b", 40), "a b");
    }

    #[test]
    fn json_text_never_carries_raw_terminal_controls() {
        let raw = "{\"a\": \"x\u{9b}31m\u{7f}\u{202e}y\u{ad}\", \"b\": \"caf\u{e9}\"}";
        let fixed = escape_json_controls(raw);
        assert_eq!(
            fixed,
            "{\"a\": \"x\\u009b31m\\u007f\\u202ey\\u00ad\", \"b\": \"caf\u{e9}\"}"
        );
        let a: serde_json::Value = serde_json::from_str(raw).unwrap();
        let b: serde_json::Value = serde_json::from_str(&fixed).unwrap();
        assert_eq!(a, b);
        assert_eq!(escape_json_controls("plain"), "plain");
    }

    #[test]
    fn characters_beyond_the_first_plane_keep_their_meaning_in_json() {
        let names = [
            "tag\u{e0067}x",
            "\u{1bca0}\u{13430}\u{1d159}\u{e0100}",
            "mix \u{1f600} \u{202e}\u{e0041} end",
        ];
        for name in names {
            let value = serde_json::json!({ "name": name, "list": [name] });
            let pretty = serde_json::to_string_pretty(&value).unwrap();
            let fixed = escape_json_controls(&pretty);
            let back: serde_json::Value = serde_json::from_str(&fixed).unwrap();
            assert_eq!(back, value, "{name:?}");
            assert!(
                fixed
                    .chars()
                    .all(|c| !invisible(c) && !('\u{7f}'..='\u{9f}').contains(&c))
            );
        }
        assert_eq!(escape_json_controls("\"\u{e0067}\""), "\"\\udb40\\udc67\"");
    }

    #[test]
    fn paths_in_messages_carry_no_escape_sequences() {
        let p = std::path::Path::new("/tmp/x\u{1b}]0;title\u{7}\u{1b}[2J\u{9b}.passkey");
        assert_eq!(path_text(p), "/tmp/x?]0;title??[2J?.passkey");
        assert_eq!(path_text(std::path::Path::new("/a b/c")), "/a b/c");
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
    fn lists_print_enough_digits_to_tell_ids_apart() {
        let a = [0xab; 16];
        let mut b = a;
        b[7] = 0xcd;
        let mut c = a;
        c[15] = 0x01;
        assert_eq!(distinct_digits(&[&a]), 12);
        assert_eq!(distinct_digits(&[&a, &[0x01; 16]]), 12);
        assert_eq!(distinct_digits(&[&a, &b]), 15);
        assert_eq!(distinct_digits(&[&a, &b, &c]), 31);
        let whole: &[u8] = &a[..8];
        assert_eq!(distinct_digits(&[whole, &a]), 17);
        assert_eq!(id_prefix(&a, 5), "ababa");
        assert_eq!(distinct_digits(&[]), 12);
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
