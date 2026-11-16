//! What the prompts say, and the zenity argument vectors that show it. Pure functions.
//!
//! RP names, user names and display names come from the relying party and are hostile. They
//! are passed with `--no-markup`, and on top of that every untrusted string goes through
//! [`sanitize`]: control, bidi and invisible characters are removed, whitespace runs collapse,
//! characters that Pango markup or zenity escape processing would interpret are replaced by
//! look-alikes, and the result is truncated.

use std::time::Duration;

use hirz_core::{ApprovalContext, CandidateAccount, Ceremony, UserEntity};

use crate::config::UvMethod;

pub const MAX_RP_CHARS: usize = 100;
pub const MAX_ORIGIN_CHARS: usize = 120;
pub const MAX_FIELD_CHARS: usize = 64;

fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Makes an untrusted string safe and readable in a dialog. Returns an empty string when
/// nothing printable is left.
pub fn sanitize(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    let mut pending_space = false;
    let mut truncated = false;
    for c in s.chars() {
        if c.is_whitespace() || c.is_control() {
            pending_space = !out.is_empty();
            continue;
        }
        if is_invisible(c) {
            continue;
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

fn or_placeholder(s: String, placeholder: &str) -> String {
    if s.is_empty() {
        placeholder.to_owned()
    } else {
        s
    }
}

/// "Display Name (name)", or whichever of the two exists.
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

/// How the user will approve; changes the last line of the dialog text.
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
        Step::Uv(UvMethod::Pin) => "Enter your hirz PIN to continue.",
    }
}

/// Title bar text: the RP id, so it stays visible even when the body is long.
pub fn title(ctx: &ApprovalContext<'_>) -> String {
    format!(
        "hirz: {}",
        or_placeholder(sanitize(ctx.rp_id, MAX_RP_CHARS), "unknown site")
    )
}

fn header(ctx: &ApprovalContext<'_>) -> Vec<String> {
    let verb = match ctx.ceremony {
        Ceremony::Create => "Create a passkey for",
        Ceremony::Get => "Sign in with a passkey on",
    };
    let mut lines = vec![
        verb.to_owned(),
        format!(
            "    {}",
            or_placeholder(sanitize(ctx.rp_id, MAX_RP_CHARS), "unknown site")
        ),
    ];
    if let Some(origin) = ctx.origin {
        lines.push(format!(
            "Requested by: {}",
            or_placeholder(sanitize(origin, MAX_ORIGIN_CHARS), "unknown")
        ));
    }
    if let Some(name) = ctx.rp_name.map(|n| sanitize(n, MAX_FIELD_CHARS))
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

/// Body text of a confirmation or PIN dialog. `notice` is a trusted, hirz-written line such
/// as "Wrong PIN".
pub fn prompt_text(
    ctx: &ApprovalContext<'_>,
    selected: Option<usize>,
    step: Step,
    notice: Option<&str>,
) -> String {
    let mut lines = header(ctx);
    if let Some(a) = account_line(ctx, selected) {
        lines.push(a);
    }
    lines.push(String::new());
    if let Some(n) = notice {
        lines.push(n.to_owned());
    }
    lines.push(step_hint(step).to_owned());
    lines.join("\n")
}

fn zenity_timeout(remaining: Duration) -> String {
    let secs = remaining
        .as_secs()
        .saturating_add(u64::from(remaining.subsec_nanos() > 0))
        .max(1);
    format!("--timeout={secs}")
}

/// Yes/no dialog. Click-to-allow puts the focus on Cancel so a stray Enter does not approve.
pub fn question_args(
    ctx: &ApprovalContext<'_>,
    selected: Option<usize>,
    step: Step,
    remaining: Duration,
) -> Vec<String> {
    let ok = match step {
        Step::ClickToAllow => "Allow",
        Step::Uv(_) => "Continue",
    };
    let mut args = vec![
        "--question".to_owned(),
        "--no-markup".to_owned(),
        format!("--title={}", title(ctx)),
        format!("--text={}", prompt_text(ctx, selected, step, None)),
        format!("--ok-label={ok}"),
        "--cancel-label=Cancel".to_owned(),
        "--width=460".to_owned(),
        zenity_timeout(remaining),
    ];
    if step == Step::ClickToAllow {
        args.push("--default-cancel".to_owned());
    }
    args
}

/// authenticatorSelection: the browser asks which security key to use. Focus is on Cancel.
pub fn selection_args(remaining: Duration) -> Vec<String> {
    vec![
        "--question".to_owned(),
        "--no-markup".to_owned(),
        "--title=hirz".to_owned(),
        "--text=Your browser is asking which security key to use.\n\nUse hirz?".to_owned(),
        "--ok-label=Use hirz".to_owned(),
        "--cancel-label=Cancel".to_owned(),
        "--width=420".to_owned(),
        zenity_timeout(remaining),
        "--default-cancel".to_owned(),
    ]
}

/// Hidden-text entry for the hirz PIN. The context is in the same dialog.
pub fn pin_args(
    ctx: &ApprovalContext<'_>,
    selected: Option<usize>,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    vec![
        "--entry".to_owned(),
        "--hide-text".to_owned(),
        "--no-markup".to_owned(),
        format!("--title={}", title(ctx)),
        format!(
            "--text={}",
            prompt_text(ctx, selected, Step::Uv(UvMethod::Pin), notice)
        ),
        "--ok-label=Verify".to_owned(),
        "--cancel-label=Cancel".to_owned(),
        "--width=460".to_owned(),
        zenity_timeout(remaining),
    ]
}

/// Account chooser. Column 1 is a hidden row number that zenity prints back; row values come
/// after `--` so a value can never be parsed as an option.
pub fn list_args(
    ctx: &ApprovalContext<'_>,
    candidates: &[CandidateAccount],
    step: Step,
    remaining: Duration,
) -> Vec<String> {
    let mut text = header(ctx);
    text.push(String::new());
    text.push("Choose an account.".to_owned());
    text.push(step_hint(step).to_owned());
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
        "--".to_owned(),
    ];
    for (i, c) in candidates.iter().enumerate() {
        args.push(i.saturating_add(1).to_string());
        args.push(or_placeholder(
            c.user_name
                .as_deref()
                .map(|s| sanitize(s, MAX_FIELD_CHARS))
                .unwrap_or_default(),
            "-",
        ));
        args.push(or_placeholder(
            c.user_display_name
                .as_deref()
                .map(|s| sanitize(s, MAX_FIELD_CHARS))
                .unwrap_or_default(),
            "-",
        ));
    }
    args
}

/// zenity prints the hidden row number. Anything other than one number in range is rejected.
pub fn parse_list_selection(stdout: &[u8], count: usize) -> Option<usize> {
    let s = core::str::from_utf8(stdout).ok()?;
    let s = s.strip_suffix('\n').unwrap_or(s);
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
    fn question_args_shape() {
        let c = cands();
        let ctx = get_ctx(&c, None);
        let a = question_args(
            &ctx,
            Some(0),
            Step::ClickToAllow,
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
            Step::Uv(UvMethod::Fingerprint),
            Duration::from_millis(10),
        );
        assert!(!a.contains(&"--default-cancel".to_owned()));
        assert!(a.contains(&"--timeout=1".to_owned()));
        assert!(a.iter().all(|x| x.starts_with("--")));
    }

    #[test]
    fn list_args_put_rows_after_terminator() {
        let c = cands();
        let ctx = get_ctx(&c, None);
        let a = list_args(&ctx, &c, Step::Uv(UvMethod::Pin), Duration::from_secs(30));
        let term = a.iter().position(|x| x == "--").unwrap();
        assert!(a[..term].iter().all(|x| x.starts_with("--")));
        assert_eq!(
            &a[term + 1..],
            ["1", "alice@example.com", "Alice", "2", "--help", "-"]
        );
        assert!(a.contains(&"--no-markup".to_owned()));
        assert!(a.contains(&"--print-column=1".to_owned()));
        assert!(!a.iter().any(|x| x.starts_with("--hide-column")));
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
        assert_eq!(parse_list_selection(b"1|2\n", 2), None);
        assert_eq!(parse_list_selection(b"+1\n", 2), None);
        assert_eq!(parse_list_selection(b"1\n\n", 2), None);
        assert_eq!(parse_list_selection(b"99999999999999999999", 2), None);
    }

    #[test]
    fn entry_newline() {
        assert_eq!(strip_entry_newline(b"1234\n"), b"1234");
        assert_eq!(strip_entry_newline(b"1234"), b"1234");
        assert_eq!(strip_entry_newline(b"12 34\n\n"), b"12 34\n");
    }
}
