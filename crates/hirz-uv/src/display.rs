//! What the prompts say, and the zenity argument vectors that show it. Pure functions.
//!
//! RP names, user names and display names come from the relying party and are hostile. They
//! are passed with `--no-markup`, and on top of that every untrusted string goes through
//! [`sanitize`]: control, bidi and invisible characters are removed, whitespace runs collapse,
//! characters that Pango markup or zenity escape processing would interpret are replaced by
//! look-alikes, and the result is truncated.

use std::time::Duration;

use hirz_core::{
    ApprovalContext, CandidateAccount, Ceremony, PairingApprovalContext, RemovalApprovalContext,
    UserEntity,
};

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

/// What happens after the question is answered.
fn step_hint(step: Step) -> &'static str {
    match step {
        Step::ClickToAllow => "Allow only if you started this on the site above.",
        Step::Uv(UvMethod::Polkit) => "Next, your system will ask for your password.",
        Step::Uv(UvMethod::Fingerprint) => "After you continue, touch the fingerprint reader.",
        Step::Uv(UvMethod::Pin) => "Next, enter your hirz PIN.",
    }
}

/// Last line of every hirz PIN entry.
const PIN_ENTRY_HINT: &str = "Enter your hirz PIN to continue.";
/// Last line of the fingerprint window, shown while the reader waits.
pub const FINGER_HINT: &str = "Touch the fingerprint reader.";
/// Account list: the same for every method, since what follows depends on what is available.
pub const LIST_HINT: &str = "Choose an account, then confirm it is you.";

/// How long ago something was asked, the same words in the terminal and in windows.
pub fn asked_ago(requested_at: u64, now: u64) -> String {
    match now.saturating_sub(requested_at) / 60 {
        0 => "less than a minute ago".to_owned(),
        1 => "1 minute ago".to_owned(),
        n => format!("{n} minutes ago"),
    }
}

/// Label of the fingerprint window's button that switches to the next method.
pub fn fallback_label(next: UvMethod) -> &'static str {
    match next {
        UvMethod::Polkit => "Use password instead",
        UvMethod::Pin => "Use PIN instead",
        UvMethod::Fingerprint => "Use fingerprint instead",
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
    lines.push(match step {
        Step::Uv(UvMethod::Pin) => PIN_ENTRY_HINT.to_owned(),
        other => step_hint(other).to_owned(),
    });
    lines.join("\n")
}

/// Site and account, for the fingerprint window.
pub fn context_text(ctx: &ApprovalContext<'_>, selected: Option<usize>) -> String {
    let mut lines = header(ctx);
    if let Some(a) = account_line(ctx, selected) {
        lines.push(a);
    }
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
    notice: Option<&str>,
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
        format!("--text={}", prompt_text(ctx, selected, step, notice)),
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

fn pairing_device(ctx: &PairingApprovalContext<'_>) -> String {
    or_placeholder(sanitize(ctx.device_name, MAX_FIELD_CHARS), "unnamed device")
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

/// Body of the pairing question: device name, age of the request, the words and the step.
pub fn pairing_text(
    ctx: &PairingApprovalContext<'_>,
    now: u64,
    step: Step,
    notice: Option<&str>,
) -> String {
    let mut lines = vec![
        "A new device asks to join your hirz vault.".to_owned(),
        format!("Device name: {}", pairing_device(ctx)),
        format!("Asked {}", asked_ago(ctx.requested_at, now)),
        String::new(),
        pairing_words_line(ctx.words),
        String::new(),
        "Do these 4 words match the ones on the new device? Only approve a device you are \
         setting up yourself right now."
            .to_owned(),
        "Approving gives it every passkey in the vault.".to_owned(),
        String::new(),
    ];
    if let Some(n) = notice {
        lines.push(n.to_owned());
    }
    lines.push(step_hint(step).to_owned());
    lines.join("\n")
}

/// Pairing question. Focus is on Cancel so a stray Enter does not approve.
pub fn pairing_question_args(
    ctx: &PairingApprovalContext<'_>,
    now: u64,
    step: Step,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    vec![
        "--question".to_owned(),
        "--no-markup".to_owned(),
        format!("--title={PAIRING_TITLE}"),
        format!("--text={}", pairing_text(ctx, now, step, notice)),
        "--ok-label=They match".to_owned(),
        "--cancel-label=Cancel".to_owned(),
        "--width=520".to_owned(),
        zenity_timeout(remaining),
        "--default-cancel".to_owned(),
    ]
}

/// Hidden-text entry for the hirz PIN when approving a new device.
pub fn pairing_pin_args(
    ctx: &PairingApprovalContext<'_>,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    device_pin_args(PAIRING_TITLE, &pairing_context(ctx), notice, remaining)
}

/// The device and its words, repeated in the PIN and fingerprint windows of a pairing.
pub fn pairing_context(ctx: &PairingApprovalContext<'_>) -> String {
    format!(
        "Approve the new device: {}\n{}",
        pairing_device(ctx),
        pairing_words_line(ctx.words)
    )
}

fn device_pin_args(
    title: &str,
    context: &str,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    let mut lines = vec![context.to_owned(), String::new()];
    if let Some(n) = notice {
        lines.push(n.to_owned());
    }
    lines.push(PIN_ENTRY_HINT.to_owned());
    vec![
        "--entry".to_owned(),
        "--hide-text".to_owned(),
        "--no-markup".to_owned(),
        format!("--title={title}"),
        format!("--text={}", lines.join("\n")),
        "--ok-label=Verify".to_owned(),
        "--cancel-label=Cancel".to_owned(),
        "--width=460".to_owned(),
        zenity_timeout(remaining),
    ]
}

pub const REMOVAL_TITLE: &str = "hirz: remove a device";
const DEVICE_ID_CHARS: usize = 32;

fn removal_device(ctx: &RemovalApprovalContext<'_>) -> String {
    or_placeholder(sanitize(ctx.device_name, MAX_FIELD_CHARS), "unnamed device")
}

fn removal_id(ctx: &RemovalApprovalContext<'_>) -> String {
    or_placeholder(sanitize(ctx.device_id_short, DEVICE_ID_CHARS), "unknown")
}

/// The device being removed, repeated in the PIN and fingerprint windows.
pub fn removal_context(ctx: &RemovalApprovalContext<'_>) -> String {
    format!(
        "Remove the device: {} (id {})",
        removal_device(ctx),
        removal_id(ctx)
    )
}

/// Body of the removal question: which device, what removal does, and the step.
pub fn removal_text(ctx: &RemovalApprovalContext<'_>, step: Step, notice: Option<&str>) -> String {
    let mut lines = vec![
        "Remove this device from your hirz vault?".to_owned(),
        format!("Device name: {}", removal_device(ctx)),
        format!("Device id: {}", removal_id(ctx)),
        String::new(),
        "It will no longer be able to read passkeys added or changed from now on. Only remove \
         a device if you asked hirz to remove it yourself right now."
            .to_owned(),
        String::new(),
    ];
    if let Some(n) = notice {
        lines.push(n.to_owned());
    }
    lines.push(step_hint(step).to_owned());
    lines.join("\n")
}

/// Removal question. Focus is on Cancel so a stray Enter does not remove.
pub fn removal_question_args(
    ctx: &RemovalApprovalContext<'_>,
    step: Step,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    vec![
        "--question".to_owned(),
        "--no-markup".to_owned(),
        format!("--title={REMOVAL_TITLE}"),
        format!("--text={}", removal_text(ctx, step, notice)),
        "--ok-label=Remove".to_owned(),
        "--cancel-label=Cancel".to_owned(),
        "--width=520".to_owned(),
        zenity_timeout(remaining),
        "--default-cancel".to_owned(),
    ]
}

/// Hidden-text entry for the hirz PIN when removing a device.
pub fn removal_pin_args(
    ctx: &RemovalApprovalContext<'_>,
    notice: Option<&str>,
    remaining: Duration,
) -> Vec<String> {
    device_pin_args(REMOVAL_TITLE, &removal_context(ctx), notice, remaining)
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
    let mut lines = vec![context.to_owned(), String::new()];
    if let Some(n) = notice {
        lines.push(n.to_owned());
    }
    lines.push(FINGER_HINT.to_owned());
    let mut args = vec![
        match fallback {
            Some(_) => "--question".to_owned(),
            None => "--info".to_owned(),
        },
        "--no-markup".to_owned(),
        format!("--title={title}"),
        format!("--text={}", lines.join("\n")),
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

/// zenity prints the hidden row number. Anything other than one number in range is rejected.
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
    fn pairing_question_shows_name_words_and_focuses_cancel() {
        let words = ["maple", "orbit", "quartz", "ember"];
        let ctx = pairing_ctx("desk <b>\u{202E}evil</b>\nline", &words);
        let a = pairing_question_args(
            &ctx,
            1_000 + 125,
            Step::Uv(UvMethod::Polkit),
            None,
            Duration::from_secs(60),
        );
        assert_eq!(a[0], "--question");
        assert!(a.contains(&"--no-markup".to_owned()));
        assert!(a.contains(&"--default-cancel".to_owned()));
        assert!(a.contains(&"--timeout=60".to_owned()));
        assert!(a.iter().all(|x| x.starts_with("--")));
        let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[1],
            "Device name: desk \u{FF1C}b\u{FF1E}evil\u{FF1C}/b\u{FF1E} line"
        );
        assert_eq!(lines[2], "Asked 2 minutes ago");
        assert_eq!(lines[4], "        MAPLE    ORBIT    QUARTZ    EMBER");
        assert!(text.contains(
            "Do these 4 words match the ones on the new device? Only approve a device you are \
             setting up yourself right now."
        ));
        assert!(text.ends_with("Next, your system will ask for your password."));
        assert!(!text.contains('<') && !text.contains('\u{202E}'));
    }

    #[test]
    fn pairing_texts_edge_cases() {
        let words = ["a", "b", "c", "d"];
        let ctx = pairing_ctx("\u{200B}", &words);
        let t = pairing_text(&ctx, 0, Step::Uv(UvMethod::Pin), None);
        assert!(t.contains("Device name: unnamed device"));
        assert!(t.contains("Asked less than a minute ago"));
        assert!(t.ends_with("Next, enter your hirz PIN."));
        assert!(
            pairing_text(&ctx, 1_060, Step::Uv(UvMethod::Pin), None).contains("Asked 1 minute ago")
        );
        assert!(
            pairing_text(&ctx, 1_000, Step::Uv(UvMethod::Pin), Some("note"))
                .contains("\nnote\nNext, enter")
        );
        let a = pairing_pin_args(&ctx, Some("Wrong PIN."), Duration::from_secs(5));
        assert_eq!(&a[..3], ["--entry", "--hide-text", "--no-markup"]);
        let text = a.iter().find_map(|x| x.strip_prefix("--text=")).unwrap();
        assert!(text.contains("A    B    C    D"));
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
