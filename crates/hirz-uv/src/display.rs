//! What the prompts say, and the zenity argument vectors that show it. Pure functions. RP names,
//! user names and display names are hostile: they are passed with `--no-markup` and every untrusted
//! string also goes through [`sanitize`] (docs/approval.md).

use std::time::Duration;

use hirz_core::{
    ApprovalContext, CandidateAccount, Ceremony, ExportApprovalContext, PairingApprovalContext,
    RemovalApprovalContext, RepairApprovalContext, UserEntity,
};

use crate::config::UvMethod;

pub const MAX_RP_CHARS: usize = 100;
pub const MAX_ORIGIN_CHARS: usize = 120;
pub const MAX_FIELD_CHARS: usize = 64;
/// Combining marks kept after one base character; more is how text paints over its neighbours.
pub const MAX_COMBINING_MARKS: usize = 2;

/// Characters that draw nothing or hide their surroundings: the Unicode default-ignorable code
/// points plus glyphs that look blank although they are not white space. Shared with the CLI.
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFC}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D159}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Code points that draw on top of the character before them: every nonspacing and enclosing mark
/// (Unicode categories Mn and Me) and every character with a combining class, as of Unicode 16,
/// plus whole marks blocks, so a mark added to one later is still counted. Sorted and disjoint.
/// Spacing marks (Mc) take room of their own and stay out of the cap.
#[rustfmt::skip]
const COMBINING: &[(u32, u32)] = &[
    (0x0300, 0x036F), (0x0483, 0x0489), (0x0591, 0x05BD), (0x05BF, 0x05BF), (0x05C1, 0x05C2),
    (0x05C4, 0x05C5), (0x05C7, 0x05C7), (0x0610, 0x061A), (0x064B, 0x065F), (0x0670, 0x0670),
    (0x06D6, 0x06DC), (0x06DF, 0x06E4), (0x06E7, 0x06E8), (0x06EA, 0x06ED), (0x0711, 0x0711),
    (0x0730, 0x074A), (0x07A6, 0x07B0), (0x07EB, 0x07F3), (0x07FD, 0x07FD), (0x0816, 0x0819),
    (0x081B, 0x0823), (0x0825, 0x0827), (0x0829, 0x082D), (0x0859, 0x085B), (0x0897, 0x089F),
    (0x08CA, 0x08E1), (0x08E3, 0x0902), (0x093A, 0x093A), (0x093C, 0x093C), (0x0941, 0x0948),
    (0x094D, 0x094D), (0x0951, 0x0957), (0x0962, 0x0963), (0x0981, 0x0981), (0x09BC, 0x09BC),
    (0x09C1, 0x09C4), (0x09CD, 0x09CD), (0x09E2, 0x09E3), (0x09FE, 0x09FE), (0x0A01, 0x0A02),
    (0x0A3C, 0x0A3C), (0x0A41, 0x0A42), (0x0A47, 0x0A48), (0x0A4B, 0x0A4D), (0x0A51, 0x0A51),
    (0x0A70, 0x0A71), (0x0A75, 0x0A75), (0x0A81, 0x0A82), (0x0ABC, 0x0ABC), (0x0AC1, 0x0AC5),
    (0x0AC7, 0x0AC8), (0x0ACD, 0x0ACD), (0x0AE2, 0x0AE3), (0x0AFA, 0x0AFF), (0x0B01, 0x0B01),
    (0x0B3C, 0x0B3C), (0x0B3F, 0x0B3F), (0x0B41, 0x0B44), (0x0B4D, 0x0B4D), (0x0B55, 0x0B56),
    (0x0B62, 0x0B63), (0x0B82, 0x0B82), (0x0BC0, 0x0BC0), (0x0BCD, 0x0BCD), (0x0C00, 0x0C00),
    (0x0C04, 0x0C04), (0x0C3C, 0x0C3C), (0x0C3E, 0x0C40), (0x0C46, 0x0C48), (0x0C4A, 0x0C4D),
    (0x0C55, 0x0C56), (0x0C62, 0x0C63), (0x0C81, 0x0C81), (0x0CBC, 0x0CBC), (0x0CBF, 0x0CBF),
    (0x0CC6, 0x0CC6), (0x0CCC, 0x0CCD), (0x0CE2, 0x0CE3), (0x0D00, 0x0D01), (0x0D3B, 0x0D3C),
    (0x0D41, 0x0D44), (0x0D4D, 0x0D4D), (0x0D62, 0x0D63), (0x0D81, 0x0D81), (0x0DCA, 0x0DCA),
    (0x0DD2, 0x0DD4), (0x0DD6, 0x0DD6), (0x0E31, 0x0E31), (0x0E34, 0x0E3A), (0x0E47, 0x0E4E),
    (0x0EB1, 0x0EB1), (0x0EB4, 0x0EBC), (0x0EC8, 0x0ECE), (0x0F18, 0x0F19), (0x0F35, 0x0F35),
    (0x0F37, 0x0F37), (0x0F39, 0x0F39), (0x0F71, 0x0F7E), (0x0F80, 0x0F84), (0x0F86, 0x0F87),
    (0x0F8D, 0x0F97), (0x0F99, 0x0FBC), (0x0FC6, 0x0FC6), (0x102D, 0x1030), (0x1032, 0x1037),
    (0x1039, 0x103A), (0x103D, 0x103E), (0x1058, 0x1059), (0x105E, 0x1060), (0x1071, 0x1074),
    (0x1082, 0x1082), (0x1085, 0x1086), (0x108D, 0x108D), (0x109D, 0x109D), (0x135D, 0x135F),
    (0x1712, 0x1715), (0x1732, 0x1734), (0x1752, 0x1753), (0x1772, 0x1773), (0x17B4, 0x17B5),
    (0x17B7, 0x17BD), (0x17C6, 0x17C6), (0x17C9, 0x17D3), (0x17DD, 0x17DD), (0x180B, 0x180D),
    (0x180F, 0x180F), (0x1885, 0x1886), (0x18A9, 0x18A9), (0x1920, 0x1922), (0x1927, 0x1928),
    (0x1932, 0x1932), (0x1939, 0x193B), (0x1A17, 0x1A18), (0x1A1B, 0x1A1B), (0x1A56, 0x1A56),
    (0x1A58, 0x1A5E), (0x1A60, 0x1A60), (0x1A62, 0x1A62), (0x1A65, 0x1A6C), (0x1A73, 0x1A7C),
    (0x1A7F, 0x1A7F), (0x1AB0, 0x1B03), (0x1B34, 0x1B34), (0x1B36, 0x1B3A), (0x1B3C, 0x1B3C),
    (0x1B42, 0x1B42), (0x1B44, 0x1B44), (0x1B6B, 0x1B73), (0x1B80, 0x1B81), (0x1BA2, 0x1BA5),
    (0x1BA8, 0x1BAD), (0x1BE6, 0x1BE6), (0x1BE8, 0x1BE9), (0x1BED, 0x1BED), (0x1BEF, 0x1BF3),
    (0x1C2C, 0x1C33), (0x1C36, 0x1C37), (0x1CD0, 0x1CD2), (0x1CD4, 0x1CE0), (0x1CE2, 0x1CE8),
    (0x1CED, 0x1CED), (0x1CF4, 0x1CF4), (0x1CF8, 0x1CF9), (0x1DC0, 0x1DFF), (0x20D0, 0x20FF),
    (0x2CEF, 0x2CF1), (0x2D7F, 0x2D7F), (0x2DE0, 0x2DFF), (0x302A, 0x302F), (0x3099, 0x309A),
    (0xA66F, 0xA672), (0xA674, 0xA67D), (0xA69E, 0xA69F), (0xA6F0, 0xA6F1), (0xA802, 0xA802),
    (0xA806, 0xA806), (0xA80B, 0xA80B), (0xA825, 0xA826), (0xA82C, 0xA82C), (0xA8C4, 0xA8C5),
    (0xA8E0, 0xA8F1), (0xA8FF, 0xA8FF), (0xA926, 0xA92D), (0xA947, 0xA951), (0xA953, 0xA953),
    (0xA980, 0xA982), (0xA9B3, 0xA9B3), (0xA9B6, 0xA9B9), (0xA9BC, 0xA9BD), (0xA9C0, 0xA9C0),
    (0xA9E5, 0xA9E5), (0xAA29, 0xAA2E), (0xAA31, 0xAA32), (0xAA35, 0xAA36), (0xAA43, 0xAA43),
    (0xAA4C, 0xAA4C), (0xAA7C, 0xAA7C), (0xAAB0, 0xAAB0), (0xAAB2, 0xAAB4), (0xAAB7, 0xAAB8),
    (0xAABE, 0xAABF), (0xAAC1, 0xAAC1), (0xAAEC, 0xAAED), (0xAAF6, 0xAAF6), (0xABE5, 0xABE5),
    (0xABE8, 0xABE8), (0xABED, 0xABED), (0xFB1E, 0xFB1E), (0xFE00, 0xFE0F), (0xFE20, 0xFE2F),
    (0x101FD, 0x101FD), (0x102E0, 0x102E0), (0x10376, 0x1037A), (0x10A01, 0x10A03),
    (0x10A05, 0x10A06), (0x10A0C, 0x10A0F), (0x10A38, 0x10A3A), (0x10A3F, 0x10A3F),
    (0x10AE5, 0x10AE6), (0x10D24, 0x10D27), (0x10D69, 0x10D6D), (0x10EAB, 0x10EAC),
    (0x10EFC, 0x10EFF), (0x10F46, 0x10F50), (0x10F82, 0x10F85), (0x11001, 0x11001),
    (0x11038, 0x11046), (0x11070, 0x11070), (0x11073, 0x11074), (0x1107F, 0x11081),
    (0x110B3, 0x110B6), (0x110B9, 0x110BA), (0x110C2, 0x110C2), (0x11100, 0x11102),
    (0x11127, 0x1112B), (0x1112D, 0x11134), (0x11173, 0x11173), (0x11180, 0x11181),
    (0x111B6, 0x111BE), (0x111C0, 0x111C0), (0x111C9, 0x111CC), (0x111CF, 0x111CF),
    (0x1122F, 0x11231), (0x11234, 0x11237), (0x1123E, 0x1123E), (0x11241, 0x11241),
    (0x112DF, 0x112DF), (0x112E3, 0x112EA), (0x11300, 0x11301), (0x1133B, 0x1133C),
    (0x11340, 0x11340), (0x1134D, 0x1134D), (0x11366, 0x1136C), (0x11370, 0x11374),
    (0x113BB, 0x113C0), (0x113CE, 0x113D0), (0x113D2, 0x113D2), (0x113E1, 0x113E2),
    (0x11438, 0x1143F), (0x11442, 0x11444), (0x11446, 0x11446), (0x1145E, 0x1145E),
    (0x114B3, 0x114B8), (0x114BA, 0x114BA), (0x114BF, 0x114C0), (0x114C2, 0x114C3),
    (0x115B2, 0x115B5), (0x115BC, 0x115BD), (0x115BF, 0x115C0), (0x115DC, 0x115DD),
    (0x11633, 0x1163A), (0x1163D, 0x1163D), (0x1163F, 0x11640), (0x116AB, 0x116AB),
    (0x116AD, 0x116AD), (0x116B0, 0x116B7), (0x1171D, 0x1171D), (0x1171F, 0x1171F),
    (0x11722, 0x11725), (0x11727, 0x1172B), (0x1182F, 0x11837), (0x11839, 0x1183A),
    (0x1193B, 0x1193E), (0x11943, 0x11943), (0x119D4, 0x119D7), (0x119DA, 0x119DB),
    (0x119E0, 0x119E0), (0x11A01, 0x11A0A), (0x11A33, 0x11A38), (0x11A3B, 0x11A3E),
    (0x11A47, 0x11A47), (0x11A51, 0x11A56), (0x11A59, 0x11A5B), (0x11A8A, 0x11A96),
    (0x11A98, 0x11A99), (0x11C30, 0x11C36), (0x11C38, 0x11C3D), (0x11C3F, 0x11C3F),
    (0x11C92, 0x11CA7), (0x11CAA, 0x11CB0), (0x11CB2, 0x11CB3), (0x11CB5, 0x11CB6),
    (0x11D31, 0x11D36), (0x11D3A, 0x11D3A), (0x11D3C, 0x11D3D), (0x11D3F, 0x11D45),
    (0x11D47, 0x11D47), (0x11D90, 0x11D91), (0x11D95, 0x11D95), (0x11D97, 0x11D97),
    (0x11EF3, 0x11EF4), (0x11F00, 0x11F01), (0x11F36, 0x11F3A), (0x11F40, 0x11F42),
    (0x11F5A, 0x11F5A), (0x13440, 0x13440), (0x13447, 0x13455), (0x1611E, 0x16129),
    (0x1612D, 0x1612F), (0x16AF0, 0x16AF4), (0x16B30, 0x16B36), (0x16F4F, 0x16F4F),
    (0x16F8F, 0x16F92), (0x16FE4, 0x16FE4), (0x16FF0, 0x16FF1), (0x1BC9D, 0x1BC9E),
    (0x1CF00, 0x1CF2D), (0x1CF30, 0x1CF46), (0x1D165, 0x1D169), (0x1D16D, 0x1D172),
    (0x1D17B, 0x1D182), (0x1D185, 0x1D18B), (0x1D1AA, 0x1D1AD), (0x1D242, 0x1D244),
    (0x1DA00, 0x1DA36), (0x1DA3B, 0x1DA6C), (0x1DA75, 0x1DA75), (0x1DA84, 0x1DA84),
    (0x1DA9B, 0x1DA9F), (0x1DAA1, 0x1DAAF), (0x1E000, 0x1E006), (0x1E008, 0x1E018),
    (0x1E01B, 0x1E021), (0x1E023, 0x1E024), (0x1E026, 0x1E02A), (0x1E08F, 0x1E08F),
    (0x1E130, 0x1E136), (0x1E2AE, 0x1E2AE), (0x1E2EC, 0x1E2EF), (0x1E4EC, 0x1E4EF),
    (0x1E5EE, 0x1E5EF), (0x1E8D0, 0x1E8D6), (0x1E944, 0x1E94A), (0xE0100, 0xE01EF),
];

pub fn is_combining(c: char) -> bool {
    let c = u32::from(c);
    COMBINING
        .binary_search_by(|&(low, high)| {
            if high < c {
                core::cmp::Ordering::Less
            } else if low > c {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Makes an untrusted string safe and readable in a dialog: no control, invisible or bidirectional
/// characters, white space collapsed, at most [`MAX_COMBINING_MARKS`] marks per base character,
/// and `< > & \` replaced by look-alikes. Cuts at `max_chars` and ends with an ellipsis; returns
/// an empty string when nothing printable is left.
pub fn sanitize(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    let mut pending_space = false;
    let mut truncated = false;
    let mut marks = MAX_COMBINING_MARKS;
    for c in s.chars() {
        if c.is_whitespace() || c.is_control() {
            pending_space = !out.is_empty();
            marks = MAX_COMBINING_MARKS;
            continue;
        }
        if is_invisible(c) {
            continue;
        }
        if is_combining(c) {
            if marks >= MAX_COMBINING_MARKS {
                continue;
            }
            marks = marks.saturating_add(1);
        } else {
            marks = 0;
        }
        let mapped = match c {
            '<' => '\u{FF1C}',
            '>' => '\u{FF1E}',
            '&' => '\u{FF06}',
            '\\' => '\u{FF3C}',
            other => other,
        };
        let needed = if pending_space { 2 } else { 1 };
        if count.saturating_add(needed) > max_chars {
            truncated = true;
            break;
        }
        if pending_space {
            out.push(' ');
            count = count.saturating_add(1);
            pending_space = false;
        }
        out.push(mapped);
        count = count.saturating_add(1);
    }
    if truncated {
        out.push('\u{2026}');
    }
    out
}

/// Like [`sanitize`], but a value that is too long keeps its right end and loses the left: for
/// host names and origins the right end holds the registrable domain, the part that tells sites
/// apart, so it must never be the part that is cut.
pub fn sanitize_tail(s: &str, max_chars: usize) -> String {
    let full = sanitize(s, usize::MAX);
    let chars = full.chars().count();
    if chars <= max_chars {
        return full;
    }
    let keep = max_chars.saturating_sub(1);
    let tail: String = full.chars().skip(chars.saturating_sub(keep)).collect();
    let tail = tail.trim_start_matches(|c: char| c == ' ' || is_combining(c));
    format!("\u{2026}{tail}")
}

fn or_placeholder(s: String, placeholder: &str) -> String {
    if s.is_empty() {
        placeholder.to_owned()
    } else {
        s
    }
}

/// One table cell of the account list. Names are site-controlled: a leading "-" would be
/// read by zenity as an option, so it becomes U+2010 HYPHEN, which looks the same.
fn list_cell(value: Option<&str>) -> String {
    let s = or_placeholder(
        value
            .map(|v| sanitize(v, MAX_FIELD_CHARS))
            .unwrap_or_default(),
        "(none)",
    );
    match s.strip_prefix('-') {
        Some(rest) => format!("\u{2010}{rest}"),
        None => s,
    }
}

pub fn account_label(name: Option<&str>, display_name: Option<&str>) -> String {
    let n = name
        .map(|s| sanitize(s, MAX_FIELD_CHARS))
        .unwrap_or_default();
    let d = display_name
        .map(|s| sanitize(s, MAX_FIELD_CHARS))
        .unwrap_or_default();
    match (n.is_empty(), d.is_empty()) {
        (false, false) if n != d => format!("{d} ({n})"),
        (false, _) => n,
        (true, false) => d,
        (true, true) => "unnamed account".to_owned(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    ClickToAllow,
    Uv(UvMethod),
}

fn step_hint(step: Step) -> &'static str {
    match step {
        Step::ClickToAllow => "Allow only if you started this on the site above.",
        Step::Uv(UvMethod::Polkit) => "Next, your system will ask for your password.",
        Step::Uv(UvMethod::Fingerprint) => "After you continue, touch the fingerprint reader.",
        Step::Uv(UvMethod::Pin) => "Next, enter your hirz PIN.",
    }
}

/// Click-to-allow for an SSH key: there is no site to point at.
const SSH_ALLOW_HINT: &str = "Allow only if you just started this with ssh yourself.";
const PIN_ENTRY_HINT: &str = "Enter your hirz PIN to continue.";
pub const FINGER_HINT: &str = "Touch the fingerprint reader.";
/// Account list: the same for every method, since what follows depends on what is available.
pub const LIST_HINT: &str = "Choose an account, then confirm it is you.";

pub fn asked_ago(requested_at: u64, now: u64) -> String {
    match now.saturating_sub(requested_at) / 60 {
        0 => "less than a minute ago".to_owned(),
        1 => "1 minute ago".to_owned(),
        n => format!("{n} minutes ago"),
    }
}

pub fn fallback_label(next: UvMethod) -> &'static str {
    match next {
        UvMethod::Polkit => "Use password instead",
        UvMethod::Pin => "Use PIN instead",
        UvMethod::Fingerprint => "Use fingerprint instead",
    }
}

const SSH_PREFIX: &str = "ssh:";

/// OpenSSH security keys (`ssh-keygen -t ecdsa-sk` or `-t ed25519-sk`) use `ssh:` or
/// `ssh:NAME` as their RP id. Returns NAME, empty for plain `ssh:`.
pub fn ssh_key_name(rp_id: &str) -> Option<&str> {
    rp_id.strip_prefix(SSH_PREFIX)
}

/// The RP id as a person reads it: "SSH key" or "SSH key (NAME)" for OpenSSH keys, the RP id
/// itself otherwise. `clean` makes the untrusted part safe for the output it goes to. Logs
/// and machine-readable output keep the raw RP id.
pub fn site_label_with(rp_id: &str, clean: impl Fn(&str) -> String) -> String {
    match ssh_key_name(rp_id).map(&clean) {
        Some(name) if name.is_empty() => "SSH key".to_owned(),
        Some(name) => format!("SSH key ({name})"),
        None => clean(rp_id),
    }
}

pub fn site_label(rp_id: &str) -> String {
    or_placeholder(
        site_label_with(rp_id, |s| sanitize_tail(s, MAX_RP_CHARS)),
        "unknown site",
    )
}

/// Title bar text: the RP id, so it stays visible even when the body is long.
pub fn title(ctx: &ApprovalContext<'_>) -> String {
    format!("hirz: {}", site_label(ctx.rp_id))
}

fn header(ctx: &ApprovalContext<'_>) -> Vec<String> {
    let ssh = ssh_key_name(ctx.rp_id).is_some();
    let verb = match (ctx.ceremony, ssh) {
        (Ceremony::Create, false) => "Create a passkey for",
        (Ceremony::Get, false) => "Sign in with a passkey on",
        (Ceremony::Create, true) => "Create a new",
        (Ceremony::Get, true) => "Use your",
    };
    let mut lines = vec![verb.to_owned(), format!("    {}", site_label(ctx.rp_id))];
    if let Some(origin) = ctx.origin {
        lines.push(format!(
            "Requested by: {}",
            or_placeholder(sanitize_tail(origin, MAX_ORIGIN_CHARS), "unknown")
        ));
    }
    if let Some(name) = ctx.rp_name.map(|n| sanitize(n, MAX_FIELD_CHARS))
        && !ssh
        && !name.is_empty()
        && !name.eq_ignore_ascii_case(ctx.rp_id)
    {
        lines.push(format!("Name the site gives: {name}"));
    }
    lines
}

fn account_line(ctx: &ApprovalContext<'_>, selected: Option<usize>) -> Option<String> {
    let label = match ctx.ceremony {
        Ceremony::Create => ctx
            .new_account
            .map(|u: &UserEntity| account_label(u.name.as_deref(), u.display_name.as_deref())),
        Ceremony::Get => selected
            .and_then(|i| ctx.candidates.get(i))
            .map(|c| account_label(c.user_name.as_deref(), c.user_display_name.as_deref())),
    }?;
    Some(format!("Account: {label}"))
}

/// `notice` is a trusted, hirz-written line such as "Wrong PIN".
pub fn prompt_text(
    ctx: &ApprovalContext<'_>,
    selected: Option<usize>,
    step: Step,
    notice: Option<&str>,
) -> String {
    let hint = match step {
        Step::Uv(UvMethod::Pin) => PIN_ENTRY_HINT,
        Step::ClickToAllow if ssh_key_name(ctx.rp_id).is_some() => SSH_ALLOW_HINT,
        other => step_hint(other),
    };
    with_hint(&context_text(ctx, selected), notice, hint)
}

pub fn context_text(ctx: &ApprovalContext<'_>, selected: Option<usize>) -> String {
    let mut lines = header(ctx);
    if let Some(a) = account_line(ctx, selected) {
        lines.push(a);
    }
    lines.join("\n")
}

fn with_hint(context: &str, notice: Option<&str>, hint: &str) -> String {
    match notice {
        Some(n) => format!("{context}\n\n{n}\n{hint}"),
        None => format!("{context}\n\n{hint}"),
    }
}

fn zenity_timeout(remaining: Duration) -> String {
    let secs = remaining
        .as_secs()
        .saturating_add(u64::from(remaining.subsec_nanos() > 0))
        .max(1);
    format!("--timeout={secs}")
}

/// `default_cancel` puts the focus on Cancel so a stray Enter does not approve.
fn question(
    title: &str,
    text: &str,
    ok: &str,
    width: u32,
    remaining: Duration,
    default_cancel: bool,
) -> Vec<String> {
    let mut args = vec![
        "--question".to_owned(),
        "--no-markup".to_owned(),
        format!("--title={title}"),
        format!("--text={text}"),
        format!("--ok-label={ok}"),
        "--cancel-label=Cancel".to_owned(),
        format!("--width={width}"),
        zenity_timeout(remaining),
    ];
    if default_cancel {
        args.push("--default-cancel".to_owned());
    }
    args
}

/// zenity 4 sets the text of an entry dialog as a label with mnemonics and ignores `--no-markup`
/// there, so a single `_` would vanish and underline the next character; `__` shows one.
fn pin_entry(title: &str, text: &str, remaining: Duration) -> Vec<String> {
    vec![
        "--entry".to_owned(),
        "--hide-text".to_owned(),
        "--no-markup".to_owned(),
        format!("--title={title}"),
        format!("--text={}", text.replace('_', "__")),
        "--ok-label=Verify".to_owned(),
        "--cancel-label=Cancel".to_owned(),
        "--width=460".to_owned(),
        zenity_timeout(remaining),
    ]
}

/// Yes/no dialog. Click-to-allow puts the focus on Cancel so a stray Enter does not approve.
pub fn question_args(
    ctx: &ApprovalContext<'_>,
    selected: Option<usize>,
    step: Step,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    let ok = match step {
        Step::ClickToAllow => "Allow",
        Step::Uv(_) => "Continue",
    };
    question(
        &title(ctx),
        &prompt_text(ctx, selected, step, notice),
        ok,
        460,
        remaining,
        step == Step::ClickToAllow,
    )
}

/// authenticatorSelection: the browser asks which security key to use. Focus is on Cancel.
pub fn selection_args(remaining: Duration) -> Vec<String> {
    question(
        "hirz",
        "Your browser is asking which security key to use.\n\nUse hirz?",
        "Use hirz",
        420,
        remaining,
        true,
    )
}

pub fn pin_args(
    ctx: &ApprovalContext<'_>,
    selected: Option<usize>,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    pin_entry(
        &title(ctx),
        &prompt_text(ctx, selected, Step::Uv(UvMethod::Pin), notice),
        remaining,
    )
}

/// Account chooser. Column 1 is a visible row number that zenity prints back. zenity 4 ignores
/// `--no-markup` for the list text and reads it as markup, so every string in it has been through
/// [`sanitize`], which removes `< > &`. No cell may start with `-` (see `list_cell`).
pub fn list_args(
    ctx: &ApprovalContext<'_>,
    candidates: &[CandidateAccount],
    remaining: Duration,
) -> Vec<String> {
    let mut text = header(ctx);
    text.push(String::new());
    text.push(LIST_HINT.to_owned());
    let mut args = vec![
        "--list".to_owned(),
        "--no-markup".to_owned(),
        format!("--title={}", title(ctx)),
        format!("--text={}", text.join("\n")),
        "--column=#".to_owned(),
        "--column=Account".to_owned(),
        "--column=Name".to_owned(),
        // The "#" column stays visible: zenity 4 does not reliably print hidden columns.
        "--print-column=1".to_owned(),
        "--ok-label=Continue".to_owned(),
        "--cancel-label=Cancel".to_owned(),
        "--width=520".to_owned(),
        "--height=360".to_owned(),
        zenity_timeout(remaining),
    ];
    // zenity 4 keeps a "--" argument as table data instead of ending its options, so rows
    // follow the options directly and no cell may start with "-" (see `list_cell`).
    for (i, c) in candidates.iter().enumerate() {
        args.push(i.saturating_add(1).to_string());
        args.push(list_cell(c.user_name.as_deref()));
        args.push(list_cell(c.user_display_name.as_deref()));
    }
    args
}

pub const PAIRING_TITLE: &str = "hirz: approve a new device";
const PAIRING_WORD_CHARS: usize = 16;

fn device_label(name: &str) -> String {
    or_placeholder(sanitize(name, MAX_FIELD_CHARS), "unnamed device")
}

/// The name a new device gave itself, safe to put between brackets: pairing names are limited to a
/// short alphabet when a request is read, and this repeats the part that matters here. Brackets
/// cannot be forged, and a token in capitals is lowercased, so the name never looks like the
/// verification words, which are the only capitals in the window.
pub fn pairing_name_label(name: &str) -> String {
    let cleaned: String = sanitize(name, MAX_FIELD_CHARS)
        .chars()
        .map(|c| match c {
            '[' => '\u{FF3B}',
            ']' => '\u{FF3D}',
            other => other,
        })
        .collect();
    let calm: Vec<String> = cleaned
        .split(' ')
        .map(|t| {
            let letters = t.chars().filter(|c| c.is_alphabetic()).count();
            if letters >= 3 && !t.chars().any(char::is_lowercase) {
                t.to_lowercase()
            } else {
                t.to_owned()
            }
        })
        .collect();
    or_placeholder(calm.join(" "), "unnamed device")
}

fn pairing_name_line(name: &str) -> String {
    format!(
        "Name chosen by that device (hirz cannot check it): [{}]",
        pairing_name_label(name)
    )
}

/// The four words in capitals with wide gaps: `--no-markup` rules out a larger font, so the
/// words get their own line and stand out by case and spacing instead.
pub fn pairing_words_line(words: &[&str]) -> String {
    let shown: Vec<String> = words
        .iter()
        .map(|w| sanitize(w, PAIRING_WORD_CHARS).to_uppercase())
        .collect();
    format!("        {}", shown.join("    "))
}

/// First window of an approval: the four words and nothing the other device chose, not even its
/// name. A name that sits next to the words can be made to carry them (a device called
/// `laptop MAPLE ORBIT ...` next to the real request), so the person compares the words alone.
pub fn pairing_words_text(ctx: &PairingApprovalContext<'_>, now: u64) -> String {
    [
        "A new device asks to join your hirz vault.".to_owned(),
        format!("Asked {}", asked_ago(ctx.requested_at, now)),
        String::new(),
        "Verification words:".to_owned(),
        pairing_words_line(ctx.words),
        String::new(),
        "Do these 4 words match the ones on the new device? Only approve a device you are \
         setting up yourself right now."
            .to_owned(),
    ]
    .join("\n")
}

/// The comparison window. Focus is on Cancel so a stray Enter does not approve.
pub fn pairing_words_args(
    ctx: &PairingApprovalContext<'_>,
    now: u64,
    remaining: Duration,
) -> Vec<String> {
    question(
        PAIRING_TITLE,
        &pairing_words_text(ctx, now),
        "They match",
        520,
        remaining,
        true,
    )
}

/// Second window, shown only after the words matched: the name the device gave itself, labelled
/// as data it chose, and what approving does.
pub fn pairing_text(ctx: &PairingApprovalContext<'_>, step: Step, notice: Option<&str>) -> String {
    let context = [
        "The words matched. Approve this device?".to_owned(),
        pairing_name_line(ctx.device_name),
        "Approving gives it every passkey in the vault.".to_owned(),
    ]
    .join("\n");
    with_hint(&context, notice, step_hint(step))
}

/// The approval window. Focus is on Cancel so a stray Enter does not approve.
pub fn pairing_question_args(
    ctx: &PairingApprovalContext<'_>,
    step: Step,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    question(
        PAIRING_TITLE,
        &pairing_text(ctx, step, notice),
        "Approve",
        520,
        remaining,
        true,
    )
}

pub fn pairing_pin_args(
    ctx: &PairingApprovalContext<'_>,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    device_pin_args(PAIRING_TITLE, &pairing_context(ctx), notice, remaining)
}

/// What the fingerprint and PIN windows say. They come after the words were confirmed.
pub fn pairing_context(ctx: &PairingApprovalContext<'_>) -> String {
    format!(
        "Approve a new device.\n{}",
        pairing_name_line(ctx.device_name)
    )
}

fn device_pin_args(
    title: &str,
    context: &str,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    pin_entry(
        title,
        &with_hint(context, notice, PIN_ENTRY_HINT),
        remaining,
    )
}

pub const REMOVAL_TITLE: &str = "hirz: remove a device";
const DEVICE_ID_CHARS: usize = 32;

fn removal_id(ctx: &RemovalApprovalContext<'_>) -> String {
    or_placeholder(sanitize(ctx.device_id_short, DEVICE_ID_CHARS), "unknown")
}

pub fn removal_context(ctx: &RemovalApprovalContext<'_>) -> String {
    format!(
        "Remove the device: {} (id {})",
        device_label(ctx.device_name),
        removal_id(ctx)
    )
}

pub fn removal_text(ctx: &RemovalApprovalContext<'_>, step: Step, notice: Option<&str>) -> String {
    let context = [
        "Remove this device from your hirz vault?".to_owned(),
        format!("Device name: {}", device_label(ctx.device_name)),
        format!("Device id: {}", removal_id(ctx)),
        String::new(),
        "It will no longer be able to read passkeys added or changed from now on. Only remove \
         a device if you asked hirz to remove it yourself right now."
            .to_owned(),
    ]
    .join("\n");
    with_hint(&context, notice, step_hint(step))
}

/// Removal question. Focus is on Cancel so a stray Enter does not remove.
pub fn removal_question_args(
    ctx: &RemovalApprovalContext<'_>,
    step: Step,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    question(
        REMOVAL_TITLE,
        &removal_text(ctx, step, notice),
        "Remove",
        520,
        remaining,
        true,
    )
}

pub fn removal_pin_args(
    ctx: &RemovalApprovalContext<'_>,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    device_pin_args(REMOVAL_TITLE, &removal_context(ctx), notice, remaining)
}

pub const EXPORT_TITLE: &str = "hirz: export passkeys";

fn export_count(ctx: &ExportApprovalContext) -> String {
    match ctx.passkeys {
        1 => "1 passkey".to_owned(),
        n => format!("{n} passkeys"),
    }
}

pub fn export_context(ctx: &ExportApprovalContext) -> String {
    format!("Export {} to a file", export_count(ctx))
}

pub fn export_text(ctx: &ExportApprovalContext, step: Step, notice: Option<&str>) -> String {
    let file = if ctx.plain {
        "The file will NOT be encrypted. Anyone who gets it can sign in to your accounts."
    } else {
        "The file will be encrypted with the passphrase you chose."
    };
    let context = [
        "Export your passkeys, including their private keys, to a file?".to_owned(),
        format!("Passkeys: {}", ctx.passkeys),
        String::new(),
        file.to_owned(),
        "Only export if you ran `hirz export` yourself just now.".to_owned(),
    ]
    .join("\n");
    with_hint(&context, notice, step_hint(step))
}

/// Export question. Focus is on Cancel so a stray Enter does not export.
pub fn export_question_args(
    ctx: &ExportApprovalContext,
    step: Step,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    question(
        EXPORT_TITLE,
        &export_text(ctx, step, notice),
        "Export",
        520,
        remaining,
        true,
    )
}

pub fn export_pin_args(
    ctx: &ExportApprovalContext,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    device_pin_args(EXPORT_TITLE, &export_context(ctx), notice, remaining)
}

pub const REPAIR_TITLE: &str = "hirz: repair the vault";
const GENERATION_CHARS: usize = 64;

fn repair_generation(generation: &str) -> String {
    or_placeholder(sanitize(generation, GENERATION_CHARS), "unknown")
}

pub fn repair_context(ctx: &RepairApprovalContext<'_>) -> String {
    match ctx {
        RepairApprovalContext::DiscardGeneration { generation } => {
            format!("Discard the key change {}", repair_generation(generation))
        }
        RepairApprovalContext::AcceptFork => "Follow the vault folder as it is now".to_owned(),
    }
}

pub fn repair_text(ctx: &RepairApprovalContext<'_>, step: Step, notice: Option<&str>) -> String {
    let context = match ctx {
        RepairApprovalContext::DiscardGeneration { generation } => [
            "Delete this key change from your hirz vault folder?".to_owned(),
            format!("Key change: {}", repair_generation(generation)),
            String::new(),
            "hirz deletes it and every key change built on it. Only do this if you ran \
             `hirz repair` yourself just now and no device you trust made it."
                .to_owned(),
        ]
        .join("\n"),
        RepairApprovalContext::AcceptFork => [
            "Follow the vault folder as it is now?".to_owned(),
            String::new(),
            "hirz goes on from the newest key change this computer followed that is still in \
             the folder, as the folder holds it now. Devices it saw removed stay removed. Only \
             do this if you ran `hirz repair` yourself just now, and checked that no device you \
             do not trust can still change the folder."
                .to_owned(),
        ]
        .join("\n"),
    };
    with_hint(&context, notice, step_hint(step))
}

fn repair_ok_label(ctx: &RepairApprovalContext<'_>) -> &'static str {
    match ctx {
        RepairApprovalContext::DiscardGeneration { .. } => "Discard",
        RepairApprovalContext::AcceptFork => "Follow folder",
    }
}

/// Repair question. Focus is on Cancel so a stray Enter does not change the vault.
pub fn repair_question_args(
    ctx: &RepairApprovalContext<'_>,
    step: Step,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    question(
        REPAIR_TITLE,
        &repair_text(ctx, step, notice),
        repair_ok_label(ctx),
        520,
        remaining,
        true,
    )
}

pub fn repair_pin_args(
    ctx: &RepairApprovalContext<'_>,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    device_pin_args(REPAIR_TITLE, &repair_context(ctx), notice, remaining)
}

/// The window shown while `fprintd-verify` waits for a finger. `context` is hirz-written or
/// already sanitized. With a next method it is a question whose OK button switches to that
/// method; without one an information window whose only button cancels.
pub fn finger_args(
    title: &str,
    context: &str,
    notice: Option<&str>,
    fallback: Option<UvMethod>,
    remaining: Duration,
) -> Vec<String> {
    let mut args = vec![
        match fallback {
            Some(_) => "--question".to_owned(),
            None => "--info".to_owned(),
        },
        "--no-markup".to_owned(),
        format!("--title={title}"),
        format!("--text={}", with_hint(context, notice, FINGER_HINT)),
    ];
    match fallback {
        Some(next) => {
            args.push(format!("--ok-label={}", fallback_label(next)));
            args.push("--cancel-label=Cancel".to_owned());
        }
        None => args.push("--ok-label=Cancel".to_owned()),
    }
    args.push("--width=460".to_owned());
    args.push(zenity_timeout(remaining));
    args
}

/// zenity prints the row number column. Anything other than one number in range is rejected.
pub fn parse_list_selection(stdout: &[u8], count: usize) -> Option<usize> {
    let s = core::str::from_utf8(stdout).ok()?;
    let s = s.strip_suffix('\n').unwrap_or(s);
    // zenity 4 may append more fields after "|" even with --print-column=1 (it printed
    // "1|1" on GNOME 50); the first field is always the "#" column hirz asked for.
    let s = s.split('|').next().unwrap_or(s);
    if s.is_empty() || s.len() > 6 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: usize = s.parse().ok()?;
    (1..=count).contains(&n).then(|| n.saturating_sub(1))
}

/// Drops the single trailing newline zenity adds after the typed text.
pub fn strip_entry_newline(stdout: &[u8]) -> &[u8] {
    stdout.strip_suffix(b"\n").unwrap_or(stdout)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn cands() -> Vec<CandidateAccount> {
        vec![
            CandidateAccount {
                credential_id: vec![1],
                user_name: Some("alice@example.com".into()),
                user_display_name: Some("Alice".into()),
            },
            CandidateAccount {
                credential_id: vec![2],
                user_name: Some("--help".into()),
                user_display_name: None,
            },
        ]
    }

    fn get_ctx<'a>(c: &'a [CandidateAccount], origin: Option<&'a str>) -> ApprovalContext<'a> {
        ApprovalContext {
            ceremony: Ceremony::Get,
            rp_id: "example.com",
            rp_name: Some("<b>Example</b> & Co"),
            candidates: c,
            new_account: None,
            uv_required: false,
            origin,
        }
    }

    #[test]
    fn sanitize_strips_dangerous_characters() {
        assert_eq!(sanitize("alice", 64), "alice");
        assert_eq!(
            sanitize("<b>x</b> & \\n", 64),
            "\u{FF1C}b\u{FF1E}x\u{FF1C}/b\u{FF1E} \u{FF06} \u{FF3C}n"
        );
        assert_eq!(sanitize("a\u{202E}gpj.exe", 64), "agpj.exe");
        assert_eq!(sanitize("a\u{2066}b\u{2069}c\u{200B}d\u{FEFF}", 64), "abcd");
        assert_eq!(sanitize("line1\nline2\r\n\tline3", 64), "line1 line2 line3");
        assert_eq!(sanitize("a\u{0007}\u{009B}b", 64), "a b");
        assert_eq!(sanitize("   spaced     out   ", 64), "spaced out");
        assert_eq!(sanitize("x\u{2028}y\u{2029}z", 64), "x y z");
        assert_eq!(sanitize("\u{200E}\u{200F}  \n", 64), "");
        assert_eq!(sanitize("tag\u{E0041}\u{E0042}", 64), "tag");
    }

    #[test]
    fn sanitize_drops_blank_and_invisible_glyphs() {
        for c in [
            '\u{2800}',
            '\u{3164}',
            '\u{115F}',
            '\u{1160}',
            '\u{FFA0}',
            '\u{1BCA0}',
            '\u{1BCA3}',
            '\u{13430}',
            '\u{1343F}',
            '\u{1D159}',
            '\u{206A}',
            '\u{206F}',
            '\u{FE0F}',
            '\u{E0100}',
            '\u{FFFC}',
        ] {
            assert!(is_invisible(c), "{c:?}");
            assert_eq!(sanitize(&format!("a{c}b"), 64), "ab", "{c:?}");
            assert_eq!(sanitize(&c.to_string().repeat(40), 64), "", "{c:?}");
        }
        assert_eq!(
            sanitize("one\u{2800}\u{2800}\u{2800}Requested by: x", 64),
            "oneRequested by: x"
        );
    }

    #[test]
    fn sanitize_caps_combining_marks() {
        let stacked = format!("e{}", "\u{0301}".repeat(63));
        assert_eq!(sanitize(&stacked, 64), "e\u{0301}\u{0301}");
        assert_eq!(sanitize("\u{0301}\u{0301}abc", 64), "abc");
        assert_eq!(sanitize("a \u{0301}b", 64), "a b");
        assert_eq!(sanitize("e\u{0323}\u{0302}x", 64), "e\u{0323}\u{0302}x");
        let two_letters = format!("a{}b{}", "\u{0300}".repeat(10), "\u{0300}".repeat(10));
        assert_eq!(sanitize(&two_letters, 64).chars().count(), 6);
    }

    #[test]
    fn sixty_stacked_marks_of_any_block_end_up_as_two() {
        for mark in [
            '\u{0300}',
            '\u{0483}',
            '\u{0488}',
            '\u{0591}',
            '\u{064B}',
            '\u{0711}',
            '\u{07EB}',
            '\u{08F0}',
            '\u{0951}',
            '\u{093C}',
            '\u{0E31}',
            '\u{0E48}',
            '\u{0F72}',
            '\u{0F82}',
            '\u{1712}',
            '\u{1A7F}',
            '\u{1AB0}',
            '\u{1DC0}',
            '\u{20D0}',
            '\u{20DD}',
            '\u{2DE0}',
            '\u{302A}',
            '\u{3099}',
            '\u{A66F}',
            '\u{A8E0}',
            '\u{FE20}',
            '\u{101FD}',
            '\u{1D165}',
            '\u{1D185}',
            '\u{1E8D0}',
        ] {
            assert!(is_combining(mark), "{mark:?}");
            let stacked = format!("a{}", mark.to_string().repeat(60));
            assert_eq!(sanitize(&stacked, 64).chars().count(), 3, "{mark:?}");
            let two_bases = format!("a{m}b{m}", m = mark.to_string().repeat(30));
            assert_eq!(sanitize(&two_bases, 64).chars().count(), 6, "{mark:?}");
        }
        for plain in [
            'a', '\u{E9}', '5', '\u{0903}', '\u{0BBE}', '\u{4E2D}', '-', '\u{2026}',
        ] {
            assert!(!is_combining(plain), "{plain:?}");
        }
    }

    #[test]
    fn the_marks_table_is_sorted_and_disjoint() {
        for pair in COMBINING.windows(2) {
            assert!(pair[0].0 <= pair[0].1 && pair[0].1 < pair[1].0, "{pair:?}");
        }
        assert!(COMBINING.iter().all(|&(low, high)| low <= high));
        assert!(char::from_u32(COMBINING.last().unwrap().1).is_some());
    }

    #[test]
    fn long_hosts_keep_their_right_end() {
        let rp = format!("accounts.google.com.{}.evil.example", "a".repeat(80));
        let label = site_label(&rp);
        assert_eq!(label.chars().count(), MAX_RP_CHARS);
        assert!(label.starts_with('\u{2026}'));
        assert!(label.ends_with(".evil.example"));
        assert!(!label.contains("accounts.google.com"));
        assert_eq!(site_label("example.com"), "example.com");
        let exact = "a".repeat(MAX_RP_CHARS);
        assert_eq!(site_label(&exact), exact);

        let origin = format!(
            "https://accounts.google.com.{}.evil.example",
            "b".repeat(100)
        );
        let c = [CandidateAccount {
            credential_id: vec![1],
            user_name: Some("alice".into()),
            user_display_name: None,
        }];
        let mut ctx = get_ctx(&c, Some(&origin));
        ctx.rp_id = &rp;
        let t = prompt_text(&ctx, Some(0), Step::ClickToAllow, None);
        let requested = t.lines().find(|l| l.starts_with("Requested by: ")).unwrap();
        assert!(requested.ends_with(".evil.example"), "{requested}");
        assert!(!requested.contains("accounts.google.com"));
        assert_eq!(
            requested.chars().count(),
            "Requested by: ".len() + MAX_ORIGIN_CHARS
        );
        assert!(title(&ctx).ends_with(".evil.example"));
        assert_eq!(sanitize_tail("short", 10), "short");
        assert_eq!(sanitize_tail("abcdefghij", 5), "\u{2026}ghij");
    }

    #[test]
    fn sanitize_truncates() {
        assert_eq!(sanitize("abcdef", 3), "abc\u{2026}");
        assert_eq!(sanitize("abc", 3), "abc");
        assert_eq!(sanitize("ab cd", 3), "ab\u{2026}");
        let long = "\u{00E9}".repeat(1000);
        assert_eq!(sanitize(&long, 10).chars().count(), 11);
    }

    #[test]
    fn labels() {
        assert_eq!(account_label(Some("alice"), Some("Alice")), "Alice (alice)");
        assert_eq!(account_label(Some("alice"), Some("alice")), "alice");
        assert_eq!(account_label(Some("alice"), None), "alice");
        assert_eq!(account_label(None, Some("Alice")), "Alice");
        assert_eq!(account_label(Some("\u{202E}"), Some("")), "unnamed account");
    }

    #[test]
    fn prompt_shows_rp_origin_and_account() {
        let c = cands();
        let ctx = get_ctx(&c, Some("https://login.example.com"));
        let t = prompt_text(&ctx, Some(0), Step::Uv(UvMethod::Polkit), None);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "Sign in with a passkey on");
        assert_eq!(lines[1], "    example.com");
        assert_eq!(lines[2], "Requested by: https://login.example.com");
        assert!(lines[3].starts_with("Name the site gives: \u{FF1C}b\u{FF1E}Example"));
        assert_eq!(lines[4], "Account: Alice (alice@example.com)");
        assert!(t.ends_with("Next, your system will ask for your password."));
        assert!(!t.contains('<') && !t.contains('&'));
    }

    #[test]
    fn create_prompt() {
        let user = UserEntity {
            id: vec![9],
            name: Some("bob".into()),
            display_name: Some("Bob\nEvil line".into()),
        };
        let ctx = ApprovalContext {
            ceremony: Ceremony::Create,
            rp_id: "example.com",
            rp_name: Some("example.com"),
            candidates: &[],
            new_account: Some(&user),
            uv_required: true,
            origin: None,
        };
        let t = prompt_text(
            &ctx,
            None,
            Step::Uv(UvMethod::Pin),
            Some("Wrong PIN. 3 attempts left."),
        );
        assert!(
            t.starts_with("Create a passkey for\n    example.com\nAccount: Bob Evil line (bob)\n")
        );
        assert!(!t.contains("Name the site gives"));
        assert!(t.contains("Wrong PIN. 3 attempts left.\nEnter your hirz PIN"));
    }

    #[test]
    fn ssh_rp_ids_read_as_ssh_keys() {
        assert_eq!(site_label("ssh:"), "SSH key");
        assert_eq!(site_label("ssh:work"), "SSH key (work)");
        assert_eq!(
            site_label("ssh:<b>x</b>"),
            "SSH key (\u{FF1C}b\u{FF1E}x\u{FF1C}/b\u{FF1E})"
        );
        assert_eq!(site_label("ssh:\u{202E}\n"), "SSH key");
        assert_eq!(site_label("example.com"), "example.com");
        assert_eq!(site_label("sshd.example.com"), "sshd.example.com");
        assert_eq!(site_label("SSH:"), "SSH:");
        assert_eq!(site_label("\u{200B}"), "unknown site");
        assert_eq!(ssh_key_name("ssh:"), Some(""));
        assert_eq!(ssh_key_name("example.com"), None);
        assert_eq!(
            site_label_with("ssh:abcdef", |s| s.chars().take(3).collect()),
            "SSH key (abc)"
        );

        let c = cands();
        for (rp, label) in [("ssh:", "SSH key"), ("ssh:work", "SSH key (work)")] {
            let mut ctx = get_ctx(&c, None);
            ctx.rp_id = rp;
            ctx.rp_name = Some(rp);
            let t = prompt_text(&ctx, Some(0), Step::ClickToAllow, None);
            let lines: Vec<&str> = t.lines().collect();
            assert_eq!(lines[0], "Use your");
            assert_eq!(lines[1], format!("    {label}"));
            assert_eq!(lines[2], "Account: Alice (alice@example.com)");
            assert!(t.ends_with(SSH_ALLOW_HINT));
            assert!(!t.contains("ssh:") && !t.contains("Name the site gives"));
            let a = question_args(
                &ctx,
                Some(0),
                Step::ClickToAllow,
                None,
                Duration::from_secs(5),
            );
            assert!(a.contains(&format!("--title=hirz: {label}")));
            let a = pin_args(&ctx, Some(0), None, Duration::from_secs(5));
            assert!(a.contains(&format!("--title=hirz: {label}")));
            assert!(!a.iter().any(|x| x.contains("ssh:")));
            let a = list_args(&ctx, &c, Duration::from_secs(5));
            assert!(!a.iter().any(|x| x.contains("ssh:")));
            assert!(context_text(&ctx, Some(0)).contains(label));
            assert_eq!(title(&ctx), format!("hirz: {label}"));

            ctx.ceremony = Ceremony::Create;
            let t = prompt_text(&ctx, None, Step::Uv(UvMethod::Polkit), None);
            assert!(t.starts_with(&format!("Create a new\n    {label}\n")));
            assert!(t.ends_with("Next, your system will ask for your password."));
        }
    }

    #[test]
    fn question_args_shape() {
        let c = cands();
        let ctx = get_ctx(&c, None);
        let a = question_args(
            &ctx,
            Some(0),
            Step::ClickToAllow,
            None,
            Duration::from_millis(119_500),
        );
        assert_eq!(a[0], "--question");
        assert!(a.contains(&"--no-markup".to_owned()));
        assert!(a.contains(&"--default-cancel".to_owned()));
        assert!(a.contains(&"--ok-label=Allow".to_owned()));
        assert!(a.contains(&"--timeout=120".to_owned()));
        assert!(a.contains(&"--title=hirz: example.com".to_owned()));
        let a = question_args(
            &ctx,
            Some(0),
            Step::Uv(UvMethod::Polkit),
            Some("Fingerprint not recognised."),
            Duration::from_millis(10),
        );
        assert!(!a.contains(&"--default-cancel".to_owned()));
        assert!(a.iter().any(|x| x.contains(
            "Fingerprint not recognised.\nNext, your system will ask for your password."
        )));
        assert!(a.contains(&"--timeout=1".to_owned()));
        assert!(a.iter().all(|x| x.starts_with("--")));
    }

    #[test]
    fn list_rows_never_start_with_a_dash() {
        let c = cands();
        let ctx = get_ctx(&c, None);
        let a = list_args(&ctx, &c, Duration::from_secs(30));
        assert!(!a.contains(&"--".to_owned()));
        let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.ends_with("\nChoose an account, then confirm it is you."));
        assert!(!text.contains("PIN") && !text.contains("password"));
        let first_row = a.iter().position(|x| x == "1").unwrap();
        assert!(a[..first_row].iter().all(|x| x.starts_with("--")));
        assert_eq!(
            &a[first_row..],
            [
                "1",
                "alice@example.com",
                "Alice",
                "2",
                "\u{2010}-help",
                "(none)"
            ]
        );
        assert!(a[first_row..].iter().all(|x| !x.starts_with('-')));
        assert!(a.contains(&"--no-markup".to_owned()));
        assert!(a.contains(&"--print-column=1".to_owned()));
        assert!(!a.iter().any(|x| x.starts_with("--hide-column")));
    }

    #[test]
    fn nothing_hostile_survives_in_list_or_entry_text() {
        let nasty = "<b>x</b> & \\n_under_score_ a\u{202E}b";
        let c = vec![
            CandidateAccount {
                credential_id: vec![1],
                user_name: Some(nasty.into()),
                user_display_name: Some(nasty.into()),
            },
            CandidateAccount {
                credential_id: vec![2],
                user_name: Some("john_doe".into()),
                user_display_name: None,
            },
        ];
        let mut ctx = get_ctx(&c, Some("https://my_bank.example"));
        ctx.rp_id = "my_bank.example";
        ctx.rp_name = Some(nasty);
        let list = list_args(&ctx, &c, Duration::from_secs(5));
        let text = list.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        for x in list.iter().filter(|x| !x.starts_with("--column")) {
            assert!(!x.contains(['<', '>', '&', '\\']), "{x:?}");
        }
        assert!(text.contains("my_bank.example"));
        let entry = pin_args(&ctx, Some(1), None, Duration::from_secs(5));
        let text = entry
            .iter()
            .find_map(|x| x.strip_prefix("--text="))
            .unwrap();
        assert!(!text.contains(['<', '>', '&', '\\']));
        assert!(text.contains("Account: john__doe"));
        assert!(text.contains("my__bank.example"));
        assert!(
            text.replace("__", "").find('_').is_none(),
            "every underscore is doubled: {text:?}"
        );
        let title = entry.iter().find(|x| x.starts_with("--title=")).unwrap();
        assert!(title.contains("my_bank.example"));
    }

    #[test]
    fn pin_args_hide_text() {
        let c = cands();
        let ctx = get_ctx(&c, None);
        let a = pin_args(&ctx, Some(1), None, Duration::from_secs(5));
        assert_eq!(&a[..3], ["--entry", "--hide-text", "--no-markup"]);
        assert!(
            a.iter()
                .any(|x| x.starts_with("--text=") && x.contains("Account: --help"))
        );
    }

    #[test]
    fn selection_parsing() {
        assert_eq!(parse_list_selection(b"1\n", 2), Some(0));
        assert_eq!(parse_list_selection(b"2", 2), Some(1));
        assert_eq!(parse_list_selection(b"3\n", 2), None);
        assert_eq!(parse_list_selection(b"0\n", 2), None);
        assert_eq!(parse_list_selection(b"\n", 2), None);
        assert_eq!(parse_list_selection(b"", 2), None);
        assert_eq!(parse_list_selection(b"1|1\n", 2), Some(0));
        assert_eq!(parse_list_selection(b"2|alice\n", 2), Some(1));
        assert_eq!(parse_list_selection(b"|1\n", 2), None);
        assert_eq!(parse_list_selection(b"+1\n", 2), None);
        assert_eq!(parse_list_selection(b"1\n\n", 2), None);
        assert_eq!(parse_list_selection(b"99999999999999999999", 2), None);
    }

    fn pairing_ctx<'a>(name: &'a str, words: &'a [&'a str]) -> PairingApprovalContext<'a> {
        PairingApprovalContext {
            device_name: name,
            words,
            requested_at: 1_000,
        }
    }

    #[test]
    fn the_comparison_window_shows_the_words_and_nothing_the_device_chose() {
        let words = ["maple", "orbit", "quartz", "ember"];
        for name in [
            "desk <b>\u{202E}evil</b>\nline",
            "laptop MAPLE ORBIT QUARTZ EMBER",
            "MAPLE ORBIT QUARTZ EMBER",
            "m4ple 0rbit",
            "MAPLE1 ORBIT1 QUARTZ1 EMBER1",
            "M4PLE 0RB1T QU4RTZ 3MB3R",
            "MapleOrbitQuartzEmber",
        ] {
            let ctx = pairing_ctx(name, &words);
            let a = pairing_words_args(&ctx, 1_000 + 125, Duration::from_secs(60));
            assert_eq!(a[0], "--question");
            assert!(a.contains(&"--no-markup".to_owned()));
            assert!(a.contains(&"--default-cancel".to_owned()));
            assert!(a.contains(&"--ok-label=They match".to_owned()));
            assert!(a.contains(&"--timeout=60".to_owned()));
            assert!(a.iter().all(|x| x.starts_with("--")));
            let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines[1], "Asked 2 minutes ago");
            assert_eq!(lines[3], "Verification words:");
            assert_eq!(lines[4], "        MAPLE    ORBIT    QUARTZ    EMBER");
            assert!(lines[6].starts_with("Do these 4 words match the ones on the new device?"));
            assert_eq!(lines.len(), 7, "{text}");
            for part in name.split(' ') {
                if !words.iter().any(|w| w.eq_ignore_ascii_case(part)) {
                    assert!(
                        !text.contains(part),
                        "the name reached the words window: {part}"
                    );
                }
            }
            assert_eq!(text.matches("MAPLE").count(), 1);
            assert!(!text.contains("hirz cannot check it"));
        }
    }

    #[test]
    fn the_approval_window_comes_after_the_words_and_shows_the_name_as_data() {
        let words = ["maple", "orbit", "quartz", "ember"];
        let ctx = pairing_ctx("desk <b>\u{202E}evil</b>\nline", &words);
        let a = pairing_question_args(
            &ctx,
            Step::Uv(UvMethod::Polkit),
            None,
            Duration::from_secs(60),
        );
        assert_eq!(a[0], "--question");
        assert!(a.contains(&"--no-markup".to_owned()));
        assert!(a.contains(&"--default-cancel".to_owned()));
        assert!(a.contains(&"--ok-label=Approve".to_owned()));
        assert!(a.iter().all(|x| x.starts_with("--")));
        let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "The words matched. Approve this device?");
        assert_eq!(
            lines[1],
            "Name chosen by that device (hirz cannot check it): \
             [desk \u{FF1C}b\u{FF1E}evil\u{FF1C}/b\u{FF1E} line]"
        );
        assert!(text.ends_with("Next, your system will ask for your password."));
        assert!(!text.contains('<') && !text.contains('\u{202E}'));
        assert!(!text.contains("MAPLE"), "the words are not repeated");
    }

    #[test]
    fn a_device_name_cannot_pose_as_the_words_or_close_its_brackets() {
        let words = ["maple", "orbit", "quartz", "ember"];
        let ctx = pairing_ctx("laptop MAPLE ORBIT QUARTZ EMBER", &words);
        let text = pairing_text(&ctx, Step::Uv(UvMethod::Pin), None);
        assert!(!text.contains("MAPLE"));
        assert!(text.contains("[laptop maple orbit quartz ember]"));
        let forged = pairing_name_label("desk] MAPLE ORBIT [x");
        assert!(!forged.contains(['[', ']']), "{forged}");
        assert_eq!(pairing_name_label("PC"), "PC");
        assert_eq!(pairing_name_label("X1 Carbon"), "X1 Carbon");
        assert_eq!(pairing_name_label("\u{200B}"), "unnamed device");
        let c = pairing_context(&ctx);
        assert!(c.starts_with("Approve a new device.\nName chosen by that device"));
        assert!(c.ends_with("[laptop maple orbit quartz ember]"));
        assert!(!c.contains("MAPLE"));
    }

    #[test]
    fn pairing_texts_edge_cases() {
        let words = ["a", "b", "c", "d"];
        let ctx = pairing_ctx("\u{200B}", &words);
        let t = pairing_text(&ctx, Step::Uv(UvMethod::Pin), None);
        assert!(t.contains("[unnamed device]"));
        assert!(t.ends_with("Next, enter your hirz PIN."));
        let w = pairing_words_text(&ctx, 0);
        assert!(w.contains("Asked less than a minute ago"));
        assert!(w.contains("A    B    C    D"));
        assert!(pairing_words_text(&ctx, 1_060).contains("Asked 1 minute ago"));
        assert!(
            pairing_text(&ctx, Step::Uv(UvMethod::Pin), Some("note"))
                .contains("\nnote\nNext, enter")
        );
        let a = pairing_pin_args(&ctx, Some("Wrong PIN."), Duration::from_secs(5));
        assert_eq!(&a[..3], ["--entry", "--hide-text", "--no-markup"]);
        let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.contains("[unnamed device]"));
        assert!(text.contains("Wrong PIN.\nEnter your hirz PIN"));
    }

    #[test]
    fn asked_wording() {
        assert_eq!(asked_ago(100, 159), "less than a minute ago");
        assert_eq!(asked_ago(100, 160), "1 minute ago");
        assert_eq!(asked_ago(100, 100 + 14 * 60 + 59), "14 minutes ago");
        assert_eq!(asked_ago(200, 100), "less than a minute ago");
    }

    #[test]
    fn removal_question_and_pin() {
        let ctx = RemovalApprovalContext {
            device_name: "old <laptop>\u{202E}",
            device_id_short: "0a1b2c3d4e5f",
        };
        let a = removal_question_args(
            &ctx,
            Step::Uv(UvMethod::Fingerprint),
            None,
            Duration::from_secs(30),
        );
        assert_eq!(a[0], "--question");
        assert!(a.contains(&"--no-markup".to_owned()));
        assert!(a.contains(&"--default-cancel".to_owned()));
        assert!(a.contains(&"--ok-label=Remove".to_owned()));
        assert!(a.contains(&format!("--title={REMOVAL_TITLE}")));
        assert!(a.iter().all(|x| x.starts_with("--")));
        let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.contains("Device name: old \u{FF1C}laptop\u{FF1E}\n"));
        assert!(text.contains("Device id: 0a1b2c3d4e5f"));
        assert!(text.ends_with("touch the fingerprint reader."));
        let p = removal_pin_args(&ctx, Some("Wrong PIN."), Duration::from_secs(5));
        assert_eq!(&p[..3], ["--entry", "--hide-text", "--no-markup"]);
        let text = p.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(
            text.starts_with("Remove the device: old \u{FF1C}laptop\u{FF1E} (id 0a1b2c3d4e5f)")
        );
        assert!(text.ends_with("Wrong PIN.\nEnter your hirz PIN to continue."));
    }

    #[test]
    fn export_question_and_pin() {
        let plain = ExportApprovalContext {
            passkeys: 1,
            plain: true,
        };
        let a = export_question_args(
            &plain,
            Step::Uv(UvMethod::Pin),
            None,
            Duration::from_secs(30),
        );
        assert_eq!(a[0], "--question");
        assert!(a.contains(&"--no-markup".to_owned()));
        assert!(a.contains(&"--default-cancel".to_owned()));
        assert!(a.contains(&"--ok-label=Export".to_owned()));
        assert!(a.contains(&format!("--title={EXPORT_TITLE}")));
        assert!(a.iter().all(|x| x.starts_with("--")));
        let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.contains("Passkeys: 1\n"));
        assert!(text.contains("will NOT be encrypted"));
        let sealed = ExportApprovalContext {
            passkeys: 12,
            plain: false,
        };
        let a = export_question_args(
            &sealed,
            Step::Uv(UvMethod::Pin),
            None,
            Duration::from_secs(30),
        );
        let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.contains("will be encrypted"));
        let p = export_pin_args(&sealed, None, Duration::from_secs(5));
        assert_eq!(&p[..3], ["--entry", "--hide-text", "--no-markup"]);
        let text = p.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.starts_with("Export 12 passkeys to a file"));
    }

    #[test]
    fn repair_questions_and_pin() {
        let discard = RepairApprovalContext::DiscardGeneration {
            generation: "0000000002-0a1b\u{202E}2c3d",
        };
        let a = repair_question_args(
            &discard,
            Step::Uv(UvMethod::Pin),
            None,
            Duration::from_secs(30),
        );
        assert_eq!(a[0], "--question");
        assert!(a.contains(&"--no-markup".to_owned()));
        assert!(a.contains(&"--default-cancel".to_owned()));
        assert!(a.contains(&"--ok-label=Discard".to_owned()));
        assert!(a.contains(&format!("--title={REPAIR_TITLE}")));
        assert!(a.iter().all(|x| x.starts_with("--")));
        let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.contains("Key change: 0000000002-0a1b2c3d\n"), "{text}");
        assert!(!text.contains('\u{202E}'));

        let accept = RepairApprovalContext::AcceptFork;
        let a = repair_question_args(
            &accept,
            Step::Uv(UvMethod::Pin),
            None,
            Duration::from_secs(30),
        );
        assert!(a.contains(&"--ok-label=Follow folder".to_owned()));
        assert!(a.contains(&"--default-cancel".to_owned()));
        let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.starts_with("Follow the vault folder as it is now?"));

        let p = repair_pin_args(&discard, None, Duration::from_secs(5));
        assert_eq!(&p[..3], ["--entry", "--hide-text", "--no-markup"]);
        let text = p.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.starts_with("Discard the key change 0000000002-0a1b2c3d"));
        let p = repair_pin_args(&accept, None, Duration::from_secs(5));
        let text = p.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.starts_with("Follow the vault folder as it is now"));

        let blank = RepairApprovalContext::DiscardGeneration { generation: "" };
        assert!(repair_context(&blank).ends_with("unknown"));
    }

    #[test]
    fn finger_window() {
        let c = cands();
        let ctx = get_ctx(&c, None);
        let context = context_text(&ctx, Some(0));
        let a = finger_args(
            &title(&ctx),
            &context,
            Some("Not recognised. Try again (2 left)."),
            Some(UvMethod::Polkit),
            Duration::from_secs(9),
        );
        assert_eq!(a[0], "--question");
        assert!(a.contains(&"--no-markup".to_owned()));
        assert!(a.contains(&"--ok-label=Use password instead".to_owned()));
        assert!(a.contains(&"--cancel-label=Cancel".to_owned()));
        assert!(a.iter().all(|x| x.starts_with("--")));
        let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.contains("Account: Alice (alice@example.com)"));
        assert!(
            text.ends_with("Not recognised. Try again (2 left).\nTouch the fingerprint reader.")
        );
        let a = finger_args("t", "c", None, Some(UvMethod::Pin), Duration::from_secs(9));
        assert!(a.contains(&"--ok-label=Use PIN instead".to_owned()));
        let a = finger_args("t", "c", None, None, Duration::from_secs(9));
        assert_eq!(a[0], "--info");
        assert!(a.contains(&"--ok-label=Cancel".to_owned()));
        assert!(!a.iter().any(|x| x.starts_with("--cancel-label")));
    }

    #[test]
    fn entry_newline() {
        assert_eq!(strip_entry_newline(b"1234\n"), b"1234");
        assert_eq!(strip_entry_newline(b"1234"), b"1234");
        assert_eq!(strip_entry_newline(b"12 34\n\n"), b"12 34\n");
    }
}
