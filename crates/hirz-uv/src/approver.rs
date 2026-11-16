//! The approval flow: pick a method, show the site and account, run the check, map the
//! result. Everything outside the process goes through [`CommandRunner`].

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, TryLockError};
use std::time::{Duration, Instant};

use hirz_core::{
    Approval, ApprovalContext, ApprovalError, Approver, Ceremony, PairingApprovalContext,
    RemovalApprovalContext,
};
use hirz_crypto::Secret;

use crate::config::{self, Config, Paths, UvMethod};
use crate::display::{self, Step};
use crate::fprint::{self, Retry, VerifyOutcome};
use crate::pin::{PinError, PinStore};
use crate::polkit::{self, PkcheckOutcome};
use crate::ratelimit::RateLimiter;
use crate::runner::{CommandRunner, CommandSpec, EnvPolicy, Race, RunResult, SystemRunner, Tool};

/// Extra time a zenity child gets past its own `--timeout` before hirz kills it.
const DIALOG_GRACE: Duration = Duration::from_secs(2);
const FPRINTD_LIST_TIMEOUT: Duration = Duration::from_secs(5);
const FINGER_ATTEMPTS: u32 = 3;
/// Scans the reader could not read (too short, off centre, ...) do not count as attempts,
/// up to this many per request.
const FINGER_RESCANS: u32 = 5;
const PIN_PROMPTS: u32 = 5;
/// Rate limit key for pairing prompts. Not a valid RP id, so it never shares a site's budget.
const PAIRING_RATE_KEY: &str = "hirz pairing";
const REMOVAL_RATE_KEY: &str = "hirz removal";
const PAIRING_WORDS: usize = 4;
const NO_FINGERS_HINT: &str = "No fingerprint is set up for your user. Set up your fingerprint in Settings > Users, or run fprintd-enroll.";
const ZENITY_MISSING: &str =
    "zenity was not found in /usr/bin or /bin; install zenity to approve passkey requests";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Sets UP only. Never used when the RP requires UV.
    ClickToAllow,
    Uv(UvMethod),
}

impl Method {
    fn step(self) -> Step {
        match self {
            Method::ClickToAllow => Step::ClickToAllow,
            Method::Uv(m) => Step::Uv(m),
        }
    }
}

/// Methods to try, in order. Click-to-allow is used alone, and only for an RP the user listed
/// in `click_to_allow` that does not require UV; otherwise the configured UV methods.
pub fn plan_methods(
    config: &Config,
    ctx: &ApprovalContext<'_>,
) -> Result<Vec<Method>, ApprovalError> {
    if !ctx.uv_required && config.click_to_allow_for(ctx.rp_id) {
        return Ok(vec![Method::ClickToAllow]);
    }
    let plan: Vec<Method> = config.methods.iter().map(|m| Method::Uv(*m)).collect();
    if plan.is_empty() {
        Err(ApprovalError::Unavailable)
    } else {
        Ok(plan)
    }
}

/// zenity exit status: 0 OK, 1 Cancel or closed, 5 its own timeout.
pub fn map_dialog(r: RunResult) -> Result<Secret, ApprovalError> {
    match r {
        RunResult::Exited {
            code: Some(0),
            stdout,
            ..
        } => Ok(stdout),
        RunResult::Exited {
            code: Some(1),
            stderr,
            ..
        } if mentions_display(&stderr) => {
            diag("zenity could not open the display");
            Err(ApprovalError::Unavailable)
        }
        RunResult::Exited { code: Some(1), .. } => {
            diag("prompt cancelled");
            Err(ApprovalError::Denied)
        }
        RunResult::Exited { code: Some(5), .. } => Err(ApprovalError::Timeout),
        RunResult::Exited { code, .. } => Err(ApprovalError::Internal(format!(
            "zenity exited with {code:?}"
        ))),
        RunResult::TimedOut => Err(ApprovalError::Timeout),
        RunResult::NotFound => {
            diag(ZENITY_MISSING);
            Err(ApprovalError::Unavailable)
        }
        RunResult::Failed(m) => Err(ApprovalError::Internal(format!("zenity: {m}"))),
    }
}

fn mentions_display(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr)
        .to_ascii_lowercase()
        .contains("display")
}

/// pkcheck exit status per pkcheck(1). Errors that mean "polkit cannot be used here" map to
/// `Unavailable` so the next method is tried.
pub fn map_pkcheck(r: RunResult) -> Result<(), ApprovalError> {
    match r {
        RunResult::Exited { code, .. } => match polkit::classify_pkcheck(code) {
            PkcheckOutcome::Authorized => Ok(()),
            PkcheckOutcome::NotAuthorized | PkcheckOutcome::Dismissed => Err(ApprovalError::Denied),
            PkcheckOutcome::NoAgent => {
                diag("polkit: no authentication agent is running in this session");
                Err(ApprovalError::Unavailable)
            }
            PkcheckOutcome::CheckError => {
                diag("polkit: check failed; is the dev.hirz.authenticate action installed?");
                Err(ApprovalError::Unavailable)
            }
            PkcheckOutcome::BadArguments | PkcheckOutcome::Unknown => Err(ApprovalError::Internal(
                format!("pkcheck exited with {code:?}"),
            )),
        },
        RunResult::TimedOut => Err(ApprovalError::Timeout),
        RunResult::NotFound => Err(ApprovalError::Unavailable),
        RunResult::Failed(m) => Err(ApprovalError::Internal(format!("pkcheck: {m}"))),
    }
}

/// Structure of unexpected dialog output for diagnostics: digits and separators are kept,
/// every other character becomes `a`, so no account name reaches the log.
fn shape(out: &[u8]) -> String {
    String::from_utf8_lossy(out)
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_digit() || matches!(c, '|' | '\n' | ' ' | '.' | '-') {
                c
            } else {
                'a'
            }
        })
        .collect()
}

fn outcome(r: &Result<(), Fail>) -> &'static str {
    match r {
        Ok(()) => "approved",
        Err(Fail::Next { chosen: true, .. }) => "you chose the next method",
        Err(Fail::Next { .. }) => "not available, trying the next method",
        Err(Fail::Stop(ApprovalError::Denied)) => "refused or cancelled",
        Err(Fail::Stop(ApprovalError::Timeout)) => "timed out",
        Err(Fail::Stop(ApprovalError::Locked)) => "locked",
        Err(Fail::Stop(_)) => "error",
    }
}

/// Why a method did not approve.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fail {
    /// Ends the request.
    Stop(ApprovalError),
    /// The next available method is tried. `otherwise` is the result when none is left,
    /// `note` is shown in the next method's window, and `chosen` is set when the user asked
    /// for the next method (so its context window is not shown again).
    Next {
        otherwise: ApprovalError,
        note: Option<String>,
        chosen: bool,
    },
}

impl Fail {
    fn next(otherwise: ApprovalError, note: Option<String>) -> Fail {
        Fail::Next {
            otherwise,
            note,
            chosen: false,
        }
    }
}

impl From<ApprovalError> for Fail {
    fn from(e: ApprovalError) -> Fail {
        match e {
            ApprovalError::Unavailable | ApprovalError::Locked => Fail::next(e, None),
            other => Fail::Stop(other),
        }
    }
}

/// Runs `perform` for each method `next` yields until one approves. The error when none is
/// left is the last meaningful reason (a refusal or a lock) rather than "unavailable".
fn run_methods<M: Copy>(
    mut next: impl FnMut() -> Option<M>,
    mut perform: impl FnMut(M, Option<&str>, bool) -> Result<(), Fail>,
) -> Result<M, ApprovalError> {
    let mut method = next().ok_or(ApprovalError::Unavailable)?;
    let mut note: Option<String> = None;
    let mut chosen = false;
    let mut last = ApprovalError::Unavailable;
    loop {
        match perform(method, note.as_deref(), chosen) {
            Ok(()) => return Ok(method),
            Err(Fail::Stop(e)) => return Err(e),
            Err(Fail::Next {
                otherwise,
                note: n,
                chosen: c,
            }) => {
                if otherwise != ApprovalError::Unavailable {
                    last = otherwise;
                }
                note = n;
                chosen = c;
            }
        }
        method = match next() {
            Some(m) => m,
            None => return Err(last),
        };
    }
}

/// A device change the user confirms with user verification.
#[derive(Clone, Copy)]
enum DeviceChange<'a> {
    Pair(&'a PairingApprovalContext<'a>),
    Remove(&'a RemovalApprovalContext<'a>),
}

impl DeviceChange<'_> {
    fn rate_key(self) -> &'static str {
        match self {
            DeviceChange::Pair(_) => PAIRING_RATE_KEY,
            DeviceChange::Remove(_) => REMOVAL_RATE_KEY,
        }
    }

    fn title(self) -> &'static str {
        match self {
            DeviceChange::Pair(_) => display::PAIRING_TITLE,
            DeviceChange::Remove(_) => display::REMOVAL_TITLE,
        }
    }

    fn context(self) -> String {
        match self {
            DeviceChange::Pair(c) => display::pairing_context(c),
            DeviceChange::Remove(c) => display::removal_context(c),
        }
    }

    fn question(self, now: u64, step: Step, notice: Option<&str>, rem: Duration) -> Vec<String> {
        match self {
            DeviceChange::Pair(c) => display::pairing_question_args(c, now, step, notice, rem),
            DeviceChange::Remove(c) => display::removal_question_args(c, step, notice, rem),
        }
    }

    fn pin(self, notice: Option<&str>, rem: Duration) -> Vec<String> {
        match self {
            DeviceChange::Pair(c) => display::pairing_pin_args(c, notice, rem),
            DeviceChange::Remove(c) => display::removal_pin_args(c, notice, rem),
        }
    }

    fn what(self) -> &'static str {
        match self {
            DeviceChange::Pair(_) => "pairing approval",
            DeviceChange::Remove(_) => "device removal",
        }
    }
}

/// Messages never contain PINs, account names or other request data.
fn diag(msg: &str) {
    eprintln!("hirz-uv: {msg}");
}

struct Deadline {
    end: Option<Instant>,
}

impl Deadline {
    fn start(timeout: Duration) -> Self {
        Deadline {
            end: Instant::now().checked_add(timeout),
        }
    }

    fn remaining(&self) -> Result<Duration, ApprovalError> {
        match self.end {
            None => Ok(Duration::from_secs(config::MAX_TIMEOUT_SECS)),
            Some(end) => end
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(ApprovalError::Timeout),
        }
    }
}

#[derive(Debug, Clone)]
enum ConfigSource {
    File(PathBuf),
    Fixed(Config),
}

/// The [`Approver`] hirzd and hirz-nmh use. One prompt at a time per instance: a request that
/// arrives while a prompt is open is denied rather than queued.
#[derive(Debug)]
pub struct HirzApprover<R: CommandRunner = SystemRunner> {
    runner: R,
    config: ConfigSource,
    pins: PinStore,
    limiter: Mutex<RateLimiter>,
    busy: Mutex<()>,
    no_fingers_hinted: AtomicBool,
}

impl HirzApprover<SystemRunner> {
    /// Real runner, config and state from the XDG locations. The config file is re-read for
    /// every ceremony, so edits apply without a restart.
    pub fn from_env() -> Result<Self, &'static str> {
        Ok(Self::new(SystemRunner, &Paths::from_env()?))
    }
}

impl<R: CommandRunner> HirzApprover<R> {
    pub fn new(runner: R, paths: &Paths) -> Self {
        HirzApprover {
            runner,
            config: ConfigSource::File(paths.config_file.clone()),
            pins: PinStore::new(paths.state_dir.clone()),
            limiter: Mutex::new(RateLimiter::new()),
            busy: Mutex::new(()),
            no_fingers_hinted: AtomicBool::new(false),
        }
    }

    /// Uses `config` instead of reading the config file.
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = ConfigSource::Fixed(config);
        self
    }

    pub fn with_pin_store(mut self, pins: PinStore) -> Self {
        self.pins = pins;
        self
    }

    /// For the CLI: set, change and reset the hirz PIN.
    pub fn pin_store(&self) -> &PinStore {
        &self.pins
    }

    pub fn config(&self) -> Result<Config, ApprovalError> {
        match &self.config {
            ConfigSource::Fixed(c) => Ok(c.clone()),
            ConfigSource::File(path) => config::load_config(path).map_err(|e| {
                diag(&e.to_string());
                ApprovalError::Internal(e.to_string())
            }),
        }
    }

    /// UV methods usable right now, in configured order. Lets frontends answer capability
    /// queries truthfully.
    pub fn available_uv_methods(&self) -> Result<Vec<UvMethod>, ApprovalError> {
        let cfg = self.config()?;
        let deadline = Deadline::start(FPRINTD_LIST_TIMEOUT);
        Ok(cfg
            .methods
            .iter()
            .copied()
            .filter(|m| {
                self.runner.tool_available(Tool::Zenity) && self.uv_available(*m, &deadline)
            })
            .collect())
    }

    /// The hint about enrolling a finger, the first time it applies.
    fn no_fingers_hint(&self) -> Option<String> {
        if self.no_fingers_hinted.swap(true, Ordering::Relaxed) {
            return None;
        }
        diag(NO_FINGERS_HINT);
        Some(NO_FINGERS_HINT.to_owned())
    }

    fn uv_available(&self, m: UvMethod, deadline: &Deadline) -> bool {
        match m {
            UvMethod::Polkit => self.polkit_ready(),
            UvMethod::Fingerprint => {
                if !self.runner.tool_available(Tool::FprintdVerify) {
                    return false;
                }
                let (Some(user), Ok(remaining)) = (self.runner.username(), deadline.remaining())
                else {
                    return false;
                };
                match self.runner.run(&CommandSpec {
                    tool: Tool::FprintdList,
                    args: vec![user],
                    env: EnvPolicy::System,
                    timeout: remaining.min(FPRINTD_LIST_TIMEOUT),
                }) {
                    RunResult::Exited { code, stdout, .. } => {
                        let enrolled = fprint::has_enrolled_fingers(code, &stdout);
                        if !enrolled && fprint::says_no_fingers(&stdout) {
                            let _ = self.no_fingers_hint();
                        }
                        enrolled
                    }
                    _ => false,
                }
            }
            UvMethod::Pin => self.pins.is_set(),
        }
    }

    fn polkit_ready(&self) -> bool {
        self.runner.tool_available(Tool::Pkcheck) && self.runner.polkit_action_installed()
    }

    /// The method a "use ... instead" button would switch to: the first of `rest` that is
    /// usable without running anything. Fingerprint never follows itself.
    fn fallback_after(&self, rest: &[UvMethod]) -> Option<UvMethod> {
        rest.iter().copied().find(|m| match m {
            UvMethod::Polkit => self.polkit_ready(),
            UvMethod::Pin => self.pins.is_set(),
            UvMethod::Fingerprint => false,
        })
    }

    /// Adds the hirz window icon, when one is installed, right after the dialog type.
    fn zenity_args(&self, mut args: Vec<String>) -> Vec<String> {
        if let Some(icon) = self
            .runner
            .window_icon()
            .and_then(|p| p.to_str().map(str::to_owned))
        {
            let at = usize::from(!args.is_empty());
            args.insert(at, format!("--window-icon={icon}"));
        }
        args
    }

    fn dialog(
        &self,
        deadline: &Deadline,
        build: impl FnOnce(Duration) -> Vec<String>,
    ) -> Result<Secret, ApprovalError> {
        let remaining = deadline.remaining()?;
        map_dialog(self.runner.run(&CommandSpec {
            tool: Tool::Zenity,
            args: self.zenity_args(build(remaining)),
            env: EnvPolicy::Desktop,
            timeout: remaining.saturating_add(DIALOG_GRACE),
        }))
    }

    /// Get with several accounts: the user picks one first. Returns the selection and whether
    /// the context (site and account) was shown.
    fn select(
        &self,
        ctx: &ApprovalContext<'_>,
        deadline: &Deadline,
    ) -> Result<(Option<usize>, bool), ApprovalError> {
        match (ctx.ceremony, ctx.candidates.len()) {
            (Ceremony::Create, _) => Ok((None, false)),
            (Ceremony::Get, 0) => Err(ApprovalError::Internal("no candidate accounts".into())),
            (Ceremony::Get, 1) => Ok((Some(0), false)),
            (Ceremony::Get, n) => {
                let out =
                    self.dialog(deadline, |rem| display::list_args(ctx, ctx.candidates, rem))?;
                let idx = display::parse_list_selection(&out, n).ok_or_else(|| {
                    diag(&format!(
                        "account list returned an unreadable selection ({} bytes, shape {:?})",
                        out.len(),
                        shape(&out)
                    ));
                    ApprovalError::Denied
                })?;
                Ok((Some(idx), true))
            }
        }
    }

    fn ensure_context(
        &self,
        ctx: &ApprovalContext<'_>,
        selected: Option<usize>,
        step: Step,
        note: Option<&str>,
        shown: &mut Option<Step>,
        deadline: &Deadline,
    ) -> Result<(), ApprovalError> {
        if *shown == Some(step) && note.is_none() {
            return Ok(());
        }
        self.dialog(deadline, |rem| {
            display::question_args(ctx, selected, step, note, rem)
        })?;
        *shown = Some(step);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn perform(
        &self,
        method: Method,
        ctx: &ApprovalContext<'_>,
        selected: Option<usize>,
        fallback: Option<UvMethod>,
        note: Option<&str>,
        chosen: bool,
        shown: &mut Option<Step>,
        deadline: &Deadline,
    ) -> Result<(), Fail> {
        let r = match method {
            Method::ClickToAllow => {
                if ctx.uv_required {
                    return Err(ApprovalError::Unavailable.into());
                }
                return Ok(self.ensure_context(
                    ctx,
                    selected,
                    Step::ClickToAllow,
                    note,
                    shown,
                    deadline,
                )?);
            }
            Method::Uv(UvMethod::Polkit) => {
                if chosen && shown.is_some() {
                    *shown = Some(method.step());
                }
                self.ensure_context(ctx, selected, method.step(), note, shown, deadline)?;
                diag("asking for your password (polkit)");
                self.run_polkit(deadline)
            }
            Method::Uv(UvMethod::Fingerprint) => {
                *shown = Some(method.step());
                let r = self.run_fingerprint(deadline, fallback, note, |notice, fb, rem| {
                    display::finger_args(
                        &display::title(ctx),
                        &display::context_text(ctx, selected),
                        notice,
                        fb,
                        rem,
                    )
                });
                diag(&format!("fingerprint: {}", outcome(&r)));
                return r;
            }
            Method::Uv(UvMethod::Pin) => {
                *shown = Some(method.step());
                self.run_pin(deadline, note, |notice, rem| {
                    display::pin_args(ctx, selected, notice, rem)
                })
            }
        };
        diag(&format!("{:?}: {}", method, outcome(&r)));
        r
    }

    fn run_polkit(&self, deadline: &Deadline) -> Result<(), Fail> {
        let id = self
            .runner
            .process_identity()
            .ok_or_else(|| ApprovalError::Internal("cannot read the process identity".into()))?;
        Ok(map_pkcheck(self.runner.run(&CommandSpec {
            tool: Tool::Pkcheck,
            args: polkit::pkcheck_args(&id),
            env: EnvPolicy::System,
            timeout: deadline.remaining()?,
        }))?)
    }

    /// The fingerprint window ended before `fprintd-verify`.
    fn finger_window_closed(r: RunResult, fallback: Option<UvMethod>) -> Fail {
        match map_dialog(r) {
            Ok(_) if fallback.is_some() => Fail::Next {
                otherwise: ApprovalError::Unavailable,
                note: None,
                chosen: true,
            },
            // Without a next method the window's only button is Cancel.
            Ok(_) => Fail::Stop(ApprovalError::Denied),
            Err(e) => e.into(),
        }
    }

    /// Runs `fprintd-verify` while a window shows the context and "Touch the fingerprint
    /// reader". Cancel stops the request; the "use ... instead" button, too many misses or a
    /// reader error move on to the next method.
    fn run_fingerprint(
        &self,
        deadline: &Deadline,
        fallback: Option<UvMethod>,
        note: Option<&str>,
        window: impl Fn(Option<&str>, Option<UvMethod>, Duration) -> Vec<String>,
    ) -> Result<(), Fail> {
        let mut misses = 0u32;
        let mut rescans = 0u32;
        let mut notice: Option<String> = note.map(str::to_owned);
        loop {
            let remaining = deadline.remaining()?;
            let verify = CommandSpec {
                tool: Tool::FprintdVerify,
                args: Vec::new(),
                env: EnvPolicy::System,
                timeout: remaining,
            };
            let shown = CommandSpec {
                tool: Tool::Zenity,
                args: self.zenity_args(window(notice.as_deref(), fallback, remaining)),
                env: EnvPolicy::Desktop,
                timeout: remaining.saturating_add(DIALOG_GRACE),
            };
            diag("waiting for your fingerprint");
            let (code, stdout) = match self.runner.run_with_dialog(&verify, &shown) {
                Race::Dialog(r) => return Err(Self::finger_window_closed(r, fallback)),
                Race::Main(RunResult::Exited { code, stdout, .. }) => (code, stdout),
                Race::Main(RunResult::TimedOut) => return Err(Fail::Stop(ApprovalError::Timeout)),
                Race::Main(RunResult::NotFound) => return Err(ApprovalError::Unavailable.into()),
                Race::Main(RunResult::Failed(m)) => {
                    return Err(Fail::Stop(ApprovalError::Internal(format!(
                        "fprintd-verify: {m}"
                    ))));
                }
            };
            match fprint::classify_verify(code, &stdout) {
                VerifyOutcome::Match => return Ok(()),
                VerifyOutcome::Retry(Retry::NoMatch) => {
                    misses = misses.saturating_add(1);
                    let left = FINGER_ATTEMPTS.saturating_sub(misses);
                    if left == 0 {
                        return Err(Fail::next(
                            ApprovalError::Denied,
                            Some("Your fingerprint was not recognised.".to_owned()),
                        ));
                    }
                    notice = Some(format!("Not recognised. Try again ({left} left)."));
                }
                VerifyOutcome::Retry(r) => {
                    rescans = rescans.saturating_add(1);
                    if rescans > FINGER_RESCANS {
                        return Err(Fail::next(
                            ApprovalError::Denied,
                            Some("The fingerprint reader could not read your finger.".to_owned()),
                        ));
                    }
                    notice = Some(format!("{} Try again.", r.message()));
                }
                VerifyOutcome::NoFingers => {
                    return Err(Fail::next(
                        ApprovalError::Unavailable,
                        self.no_fingers_hint(),
                    ));
                }
                VerifyOutcome::ReaderError | VerifyOutcome::Unavailable => {
                    diag(
                        "fingerprint verification unavailable (no reader, no enrolled finger or device error)",
                    );
                    return Err(Fail::next(
                        ApprovalError::Unavailable,
                        Some("The fingerprint reader is not working right now.".to_owned()),
                    ));
                }
            }
        }
    }

    fn run_pin(
        &self,
        deadline: &Deadline,
        first_notice: Option<&str>,
        build: impl Fn(Option<&str>, Duration) -> Vec<String>,
    ) -> Result<(), Fail> {
        let mut notice: Option<String> = first_notice.map(str::to_owned);
        for _ in 0..PIN_PROMPTS {
            let out = self.dialog(deadline, |rem| build(notice.as_deref(), rem))?;
            match self.pins.verify(display::strip_entry_newline(&out)) {
                Ok(()) => return Ok(()),
                Err(PinError::Wrong { remaining: 0 } | PinError::Locked) => {
                    diag(
                        "the hirz PIN is locked after too many wrong attempts; reset it with the hirz CLI",
                    );
                    return Err(ApprovalError::Locked.into());
                }
                Err(PinError::Wrong { remaining }) => {
                    notice = Some(format!(
                        "Wrong PIN. {remaining} attempts left before the PIN locks."
                    ));
                }
                Err(PinError::TooShort | PinError::TooLong | PinError::NotUtf8) => {
                    notice = Some(
                        "A hirz PIN has at least 4 characters and at most 63 bytes.".to_owned(),
                    );
                }
                Err(PinError::NotSet) => return Err(ApprovalError::Unavailable.into()),
                Err(PinError::Corrupt) => {
                    return Err(Fail::Stop(ApprovalError::Internal(
                        "the PIN verifier file is damaged".into(),
                    )));
                }
                Err(PinError::Io(kind)) => {
                    return Err(Fail::Stop(ApprovalError::Internal(format!(
                        "PIN verifier: {kind}"
                    ))));
                }
                Err(PinError::Crypto | PinError::AlreadySet) => {
                    return Err(Fail::Stop(ApprovalError::Internal(
                        "PIN check failed".into(),
                    )));
                }
            }
        }
        Err(Fail::Stop(ApprovalError::Denied))
    }

    fn take_busy(&self) -> Result<std::sync::MutexGuard<'_, ()>, ApprovalError> {
        match self.busy.try_lock() {
            Ok(g) => Ok(g),
            Err(TryLockError::WouldBlock) => Err(ApprovalError::Denied),
            Err(TryLockError::Poisoned(p)) => Ok(p.into_inner()),
        }
    }

    fn rate_allowed(&self, key: &str, per_minute: u32) -> bool {
        match self.limiter.lock() {
            Ok(mut l) => l.allow(key, Instant::now(), per_minute),
            Err(p) => p.into_inner().allow(key, Instant::now(), per_minute),
        }
    }

    /// One UV method for a device change. The question with the device (and for pairing the
    /// words) is shown once, before the first method runs, and again before the password
    /// when an earlier method left a note.
    #[allow(clippy::too_many_arguments)]
    fn perform_device(
        &self,
        method: UvMethod,
        change: DeviceChange<'_>,
        now: u64,
        fallback: Option<UvMethod>,
        note: Option<&str>,
        chosen: bool,
        shown: &mut bool,
        deadline: &Deadline,
    ) -> Result<(), Fail> {
        let step = Step::Uv(method);
        let question = !*shown || (method == UvMethod::Polkit && note.is_some() && !chosen);
        if question {
            self.dialog(deadline, |rem| change.question(now, step, note, rem))?;
            *shown = true;
        }
        let note = if question { None } else { note };
        let r = match method {
            UvMethod::Polkit => {
                diag("asking for your password (polkit)");
                self.run_polkit(deadline)
            }
            UvMethod::Fingerprint => {
                let context = change.context();
                self.run_fingerprint(deadline, fallback, note, |notice, fb, rem| {
                    display::finger_args(change.title(), &context, notice, fb, rem)
                })
            }
            UvMethod::Pin => self.run_pin(deadline, note, |notice, rem| change.pin(notice, rem)),
        };
        diag(&format!("{}: {}", change.what(), outcome(&r)));
        r
    }

    /// Only the configured UV methods are tried; click-to-allow never confirms a device
    /// change, whatever the config says. Nothing is shown when no UV method is available.
    fn confirm_device(&self, change: DeviceChange<'_>) -> Result<Approval, ApprovalError> {
        let _busy = self.take_busy()?;
        let config = self.config()?;
        if !self.rate_allowed(change.rate_key(), config.prompts_per_minute) {
            diag("too many device prompts; try again in a minute");
            return Err(ApprovalError::Denied);
        }
        if !self.runner.tool_available(Tool::Zenity) {
            diag(ZENITY_MISSING);
            return Err(ApprovalError::Unavailable);
        }
        let deadline = Deadline::start(config.timeout);
        let now = unix_now();
        let methods = config.methods;
        let mut pos = 0usize;
        let mut shown = false;
        run_methods(
            || {
                while let Some(m) = methods.get(pos).copied() {
                    pos = pos.saturating_add(1);
                    if self.uv_available(m, &deadline) {
                        return Some((m, pos));
                    }
                }
                None
            },
            |(m, after), note, chosen| {
                let fallback = self.fallback_after(methods.get(after..).unwrap_or(&[]));
                self.perform_device(
                    m, change, now, fallback, note, chosen, &mut shown, &deadline,
                )
            },
        )?;
        Ok(Approval {
            user_present: true,
            user_verified: true,
            selected: None,
        })
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl<R: CommandRunner> Approver for HirzApprover<R> {
    fn approve(&self, ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        let _busy = self.take_busy()?;
        let config = self.config()?;
        if !self.rate_allowed(ctx.rp_id, config.prompts_per_minute) {
            diag("too many approval prompts for one site; try again in a minute");
            return Err(ApprovalError::Denied);
        }
        if !self.runner.tool_available(Tool::Zenity) {
            diag(ZENITY_MISSING);
            return Err(ApprovalError::Unavailable);
        }
        let deadline = Deadline::start(config.timeout);
        let plan = plan_methods(&config, ctx)?;
        let available = |m: &Method| match m {
            Method::ClickToAllow => !ctx.uv_required,
            Method::Uv(u) => self.uv_available(*u, &deadline),
        };
        let first = plan
            .iter()
            .position(available)
            .ok_or(ApprovalError::Unavailable)?;
        let (selected, list_shown) = self.select(ctx, &deadline)?;
        // The list showed the site, so the first method needs no second context window.
        let mut shown = if list_shown {
            plan.get(first).map(|m| m.step())
        } else {
            None
        };
        let mut pos = first.saturating_add(1);
        let mut first_pending = true;
        let method = run_methods(
            || {
                if core::mem::take(&mut first_pending) {
                    return plan.get(first).map(|m| (*m, pos));
                }
                while let Some(m) = plan.get(pos).copied() {
                    pos = pos.saturating_add(1);
                    if available(&m) {
                        return Some((m, pos));
                    }
                }
                None
            },
            |(m, after), note, chosen| {
                let rest: Vec<UvMethod> = plan
                    .get(after..)
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|x| match x {
                        Method::Uv(u) => Some(*u),
                        Method::ClickToAllow => None,
                    })
                    .collect();
                let fallback = self.fallback_after(&rest);
                self.perform(
                    m, ctx, selected, fallback, note, chosen, &mut shown, &deadline,
                )
            },
        )?;
        Ok(Approval {
            user_present: true,
            user_verified: matches!(method.0, Method::Uv(_)),
            selected,
        })
    }

    fn confirm_selection(&self) -> Result<Approval, ApprovalError> {
        let _busy = self.take_busy()?;
        let config = self.config()?;
        if !self.runner.tool_available(Tool::Zenity) {
            diag(ZENITY_MISSING);
            return Err(ApprovalError::Unavailable);
        }
        let deadline = Deadline::start(config.timeout);
        self.dialog(&deadline, display::selection_args)?;
        Ok(Approval {
            user_present: true,
            user_verified: false,
            selected: None,
        })
    }

    fn confirm_pairing(&self, ctx: &PairingApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        if ctx.words.len() != PAIRING_WORDS || ctx.words.iter().any(|w| w.is_empty()) {
            return Err(ApprovalError::Internal(
                "pairing approval needs four words".into(),
            ));
        }
        self.confirm_device(DeviceChange::Pair(ctx))
    }

    fn confirm_removal(&self, ctx: &RemovalApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        self.confirm_device(DeviceChange::Remove(ctx))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::pin::tests::{TEST_PARAMS, TempDir, crypto_ready};
    use crate::pin::{MAX_FAILURES, Verifier, serialize_verifier};
    use crate::polkit::ProcessIdentity;
    use hirz_core::{CandidateAccount, UserEntity};
    use std::collections::VecDeque;

    struct Fake {
        tools: Vec<Tool>,
        polkit_installed: bool,
        icon: Option<PathBuf>,
        script: Mutex<VecDeque<(Tool, RunResult)>>,
        calls: Mutex<Vec<CommandSpec>>,
    }

    impl Fake {
        fn new(tools: &[Tool], script: Vec<(Tool, RunResult)>) -> Self {
            Fake {
                tools: tools.to_vec(),
                polkit_installed: true,
                icon: None,
                script: Mutex::new(script.into()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl core::fmt::Debug for Fake {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("Fake")
        }
    }

    impl CommandRunner for Fake {
        fn run(&self, spec: &CommandSpec) -> RunResult {
            self.calls.lock().unwrap().push(spec.clone());
            let (tool, r) = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected call {spec:?}"));
            assert_eq!(tool, spec.tool, "{spec:?}");
            r
        }
        /// One script entry decides the race: the main tool's result, or zenity's.
        fn run_with_dialog(&self, main: &CommandSpec, dialog: &CommandSpec) -> Race {
            {
                let mut calls = self.calls.lock().unwrap();
                calls.push(main.clone());
                calls.push(dialog.clone());
            }
            let (tool, r) = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected race {main:?} / {dialog:?}"));
            if tool == main.tool {
                Race::Main(r)
            } else {
                assert_eq!(tool, dialog.tool, "{dialog:?}");
                Race::Dialog(r)
            }
        }
        fn window_icon(&self) -> Option<PathBuf> {
            self.icon.clone()
        }
        fn tool_available(&self, tool: Tool) -> bool {
            self.tools.contains(&tool)
        }
        fn polkit_action_installed(&self) -> bool {
            self.polkit_installed
        }
        fn process_identity(&self) -> Option<ProcessIdentity> {
            Some(ProcessIdentity {
                pid: 4242,
                start_time: 987654,
                uid: 1000,
            })
        }
        fn username(&self) -> Option<String> {
            Some("alice".into())
        }
    }

    fn exit(code: i32, out: &str) -> RunResult {
        RunResult::Exited {
            code: Some(code),
            stdout: Secret::new(out.as_bytes().to_vec()),
            stderr: Vec::new(),
        }
    }

    const ALL: &[Tool] = &[
        Tool::Zenity,
        Tool::Pkcheck,
        Tool::FprintdVerify,
        Tool::FprintdList,
    ];
    const ENROLLED: &str =
        "Fingerprints for user alice on Acme Reader (press):\n - #0: right-index-finger\n";
    const MATCH: &str = "Verify started!\nVerify result: verify-match (done)\n";
    const NO_MATCH: &str = "Verify started!\nVerify result: verify-no-match (done)\n";

    fn approver(fake: Fake, cfg: Config, dir: &TempDir) -> HirzApprover<Fake> {
        let paths = Paths {
            config_file: dir.0.join("config"),
            state_dir: dir.0.join("state"),
        };
        HirzApprover::new(fake, &paths)
            .with_config(cfg)
            .with_pin_store(
                PinStore::with_params(dir.0.join("state"), TEST_PARAMS).with_sleep(|_| {}),
            )
    }

    fn cfg(methods: &[UvMethod]) -> Config {
        Config {
            methods: methods.to_vec(),
            ..Config::default()
        }
    }

    fn one() -> Vec<CandidateAccount> {
        vec![CandidateAccount {
            credential_id: vec![1],
            user_name: Some("alice".into()),
            user_display_name: None,
        }]
    }

    fn two() -> Vec<CandidateAccount> {
        let mut v = one();
        v.push(CandidateAccount {
            credential_id: vec![2],
            user_name: Some("bob".into()),
            user_display_name: None,
        });
        v
    }

    fn get(c: &[CandidateAccount], uv_required: bool) -> ApprovalContext<'_> {
        ApprovalContext {
            ceremony: Ceremony::Get,
            rp_id: "example.com",
            rp_name: None,
            candidates: c,
            new_account: None,
            uv_required,
            origin: Some("https://example.com"),
        }
    }

    fn calls(a: &HirzApprover<Fake>) -> Vec<CommandSpec> {
        a.runner.calls.lock().unwrap().clone()
    }

    fn write_verifier(dir: &TempDir, failures: u32) {
        let v = Verifier {
            params: TEST_PARAMS,
            salt: vec![1; 16],
            hash: vec![2; 32],
            failures,
        };
        crate::pin::ensure_private_dir(&dir.0.join("state")).unwrap();
        std::fs::write(dir.0.join("state").join("pin"), serialize_verifier(&v)).unwrap();
    }

    #[test]
    fn plan() {
        let c = one();
        let mut config = cfg(&[UvMethod::Pin, UvMethod::Polkit]);
        assert_eq!(
            plan_methods(&config, &get(&c, false)).unwrap(),
            [Method::Uv(UvMethod::Pin), Method::Uv(UvMethod::Polkit)]
        );
        config.click_to_allow = vec!["example.com".into()];
        assert_eq!(
            plan_methods(&config, &get(&c, false)).unwrap(),
            [Method::ClickToAllow]
        );
        assert_eq!(
            plan_methods(&config, &get(&c, true)).unwrap(),
            [Method::Uv(UvMethod::Pin), Method::Uv(UvMethod::Polkit)]
        );
        config.methods.clear();
        assert_eq!(
            plan_methods(&config, &get(&c, true)),
            Err(ApprovalError::Unavailable)
        );
    }

    #[test]
    fn dialog_mapping() {
        assert_eq!(&map_dialog(exit(0, "x\n")).unwrap()[..], b"x\n");
        assert_eq!(map_dialog(exit(1, "")).unwrap_err(), ApprovalError::Denied);
        assert_eq!(map_dialog(exit(5, "")).unwrap_err(), ApprovalError::Timeout);
        assert!(matches!(
            map_dialog(exit(255, "")),
            Err(ApprovalError::Internal(_))
        ));
        assert!(matches!(
            map_dialog(exit(-1, "")),
            Err(ApprovalError::Internal(_))
        ));
        let nodisplay = RunResult::Exited {
            code: Some(1),
            stdout: Secret::new(vec![]),
            stderr: b"cannot open display".to_vec(),
        };
        assert_eq!(
            map_dialog(nodisplay).unwrap_err(),
            ApprovalError::Unavailable
        );
        assert_eq!(
            map_dialog(RunResult::TimedOut).unwrap_err(),
            ApprovalError::Timeout
        );
        assert_eq!(
            map_dialog(RunResult::NotFound).unwrap_err(),
            ApprovalError::Unavailable
        );
        let killed = RunResult::Exited {
            code: None,
            stdout: Secret::new(vec![]),
            stderr: vec![],
        };
        assert!(matches!(
            map_dialog(killed),
            Err(ApprovalError::Internal(_))
        ));
    }

    #[test]
    fn pkcheck_mapping() {
        assert_eq!(map_pkcheck(exit(0, "")), Ok(()));
        assert_eq!(map_pkcheck(exit(0, "polkit.dismissed=true\n")), Ok(()));
        assert_eq!(map_pkcheck(exit(1, "")), Err(ApprovalError::Denied));
        assert_eq!(map_pkcheck(exit(2, "")), Err(ApprovalError::Unavailable));
        assert_eq!(map_pkcheck(exit(3, "")), Err(ApprovalError::Denied));
        assert_eq!(map_pkcheck(exit(127, "")), Err(ApprovalError::Unavailable));
        assert!(matches!(
            map_pkcheck(exit(126, "")),
            Err(ApprovalError::Internal(_))
        ));
        assert!(matches!(
            map_pkcheck(exit(4, "")),
            Err(ApprovalError::Internal(_))
        ));
        let killed = RunResult::Exited {
            code: None,
            stdout: Secret::new(vec![]),
            stderr: vec![],
        };
        assert!(matches!(
            map_pkcheck(killed),
            Err(ApprovalError::Internal(_))
        ));
        assert_eq!(
            map_pkcheck(RunResult::TimedOut),
            Err(ApprovalError::Timeout)
        );
        assert_eq!(
            map_pkcheck(RunResult::NotFound),
            Err(ApprovalError::Unavailable)
        );
    }

    #[test]
    fn click_to_allow_sets_up_only() {
        let d = TempDir::new("click");
        let c = one();
        let mut config = cfg(&[UvMethod::Polkit]);
        config.click_to_allow = vec!["example.com".into()];
        let a = approver(
            Fake::new(ALL, vec![(Tool::Zenity, exit(0, ""))]),
            config,
            &d,
        );
        let r = a.approve(&get(&c, false)).unwrap();
        assert_eq!(
            r,
            Approval {
                user_present: true,
                user_verified: false,
                selected: Some(0)
            }
        );
        let cl = calls(&a);
        assert_eq!(cl.len(), 1);
        assert!(cl[0].args.contains(&"--default-cancel".to_owned()));
        assert!(cl[0].args.contains(&"--ok-label=Allow".to_owned()));
        assert_eq!(cl[0].env, EnvPolicy::Desktop);
    }

    #[test]
    fn click_to_allow_refused_when_uv_required() {
        let d = TempDir::new("click-uv");
        let c = one();
        let mut config = cfg(&[UvMethod::Pin]);
        config.click_to_allow = vec!["example.com".into()];
        let a = approver(Fake::new(ALL, vec![]), config, &d);
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Unavailable));
        assert!(calls(&a).is_empty());
        let mut shown = None;
        let deadline = Deadline::start(Duration::from_secs(5));
        assert_eq!(
            a.perform(
                Method::ClickToAllow,
                &get(&c, true),
                Some(0),
                None,
                None,
                false,
                &mut shown,
                &deadline
            ),
            Err(Fail::next(ApprovalError::Unavailable, None))
        );
    }

    #[test]
    fn click_to_allow_cancel_is_denied() {
        let d = TempDir::new("click-cancel");
        let c = one();
        let mut config = cfg(&[UvMethod::Polkit]);
        config.click_to_allow = vec!["example.com".into()];
        let a = approver(
            Fake::new(ALL, vec![(Tool::Zenity, exit(1, ""))]),
            config,
            &d,
        );
        assert_eq!(a.approve(&get(&c, false)), Err(ApprovalError::Denied));
    }

    #[test]
    fn polkit_success_sets_uv() {
        let d = TempDir::new("polkit");
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![(Tool::Zenity, exit(0, "")), (Tool::Pkcheck, exit(0, ""))],
            ),
            cfg(&[UvMethod::Polkit]),
            &d,
        );
        let r = a.approve(&get(&c, true)).unwrap();
        assert_eq!(
            r,
            Approval {
                user_present: true,
                user_verified: true,
                selected: Some(0)
            }
        );
        let cl = calls(&a);
        assert!(
            cl[0]
                .args
                .iter()
                .any(|x| x.starts_with("--text=") && x.contains("example.com"))
        );
        assert!(
            cl[0]
                .args
                .iter()
                .any(|x| x.contains("Requested by: https://example.com"))
        );
        assert_eq!(
            cl[1].args,
            polkit::pkcheck_args(&ProcessIdentity {
                pid: 4242,
                start_time: 987654,
                uid: 1000
            })
        );
        assert_eq!(cl[1].env, EnvPolicy::System);
    }

    #[test]
    fn polkit_outcomes() {
        for (code, want) in [
            (1, ApprovalError::Denied),
            (3, ApprovalError::Denied),
            (2, ApprovalError::Unavailable),
        ] {
            let d = TempDir::new("polkit-out");
            let c = one();
            let a = approver(
                Fake::new(
                    ALL,
                    vec![(Tool::Zenity, exit(0, "")), (Tool::Pkcheck, exit(code, ""))],
                ),
                cfg(&[UvMethod::Polkit]),
                &d,
            );
            assert_eq!(a.approve(&get(&c, true)), Err(want), "code {code}");
        }
    }

    #[test]
    fn polkit_cancel_at_context_never_runs_pkcheck() {
        let d = TempDir::new("polkit-cancel");
        let c = one();
        let a = approver(
            Fake::new(ALL, vec![(Tool::Zenity, exit(1, ""))]),
            cfg(&[UvMethod::Polkit]),
            &d,
        );
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Denied));
        assert_eq!(calls(&a).len(), 1);
    }

    #[test]
    fn polkit_not_installed_is_skipped() {
        let d = TempDir::new("polkit-missing");
        let c = one();
        let mut fake = Fake::new(ALL, vec![]);
        fake.polkit_installed = false;
        let a = approver(fake, cfg(&[UvMethod::Polkit]), &d);
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Unavailable));
        assert!(calls(&a).is_empty());
    }

    #[test]
    fn polkit_error_falls_back_to_fingerprint_with_new_context() {
        let d = TempDir::new("fallback");
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::Zenity, exit(0, "")),
                    (Tool::Pkcheck, exit(127, "")),
                    (Tool::FprintdList, exit(0, ENROLLED)),
                    (Tool::FprintdVerify, exit(0, MATCH)),
                ],
            ),
            cfg(&[UvMethod::Polkit, UvMethod::Fingerprint]),
            &d,
        );
        let r = a.approve(&get(&c, true)).unwrap();
        assert!(r.user_verified);
        let cl = calls(&a);
        assert_eq!(cl[2].args, ["alice"]);
        assert_eq!(cl[3].tool, Tool::FprintdVerify);
        assert_eq!(cl[4].tool, Tool::Zenity);
        assert_eq!(cl[4].args[0], "--info", "no method left to switch to");
        assert!(
            cl[4]
                .args
                .iter()
                .any(|x| x.contains("Touch the fingerprint reader.") && x.contains("example.com"))
        );
    }

    #[test]
    fn list_selection_then_polkit_without_extra_question() {
        let d = TempDir::new("list");
        let c = two();
        let a = approver(
            Fake::new(
                ALL,
                vec![(Tool::Zenity, exit(0, "2\n")), (Tool::Pkcheck, exit(0, ""))],
            ),
            cfg(&[UvMethod::Polkit]),
            &d,
        );
        let r = a.approve(&get(&c, false)).unwrap();
        assert_eq!(
            r,
            Approval {
                user_present: true,
                user_verified: true,
                selected: Some(1)
            }
        );
        let cl = calls(&a);
        assert_eq!(cl[0].args[0], "--list");
        assert_eq!(cl.len(), 2);
    }

    #[test]
    fn list_cancel_or_garbage_is_denied() {
        for script in [exit(1, ""), exit(0, "7\n"), exit(0, ""), exit(0, "|2\n")] {
            let d = TempDir::new("list-bad");
            let c = two();
            let a = approver(
                Fake::new(ALL, vec![(Tool::Zenity, script)]),
                cfg(&[UvMethod::Polkit]),
                &d,
            );
            assert_eq!(a.approve(&get(&c, false)), Err(ApprovalError::Denied));
        }
    }

    #[test]
    fn list_counts_as_the_click() {
        let d = TempDir::new("list-click");
        let c = two();
        let mut config = cfg(&[UvMethod::Polkit]);
        config.click_to_allow = vec!["example.com".into()];
        let a = approver(
            Fake::new(ALL, vec![(Tool::Zenity, exit(0, "1\n"))]),
            config,
            &d,
        );
        let r = a.approve(&get(&c, false)).unwrap();
        assert_eq!(
            r,
            Approval {
                user_present: true,
                user_verified: false,
                selected: Some(0)
            }
        );
    }

    #[test]
    fn create_has_no_selection() {
        let d = TempDir::new("create");
        let user = UserEntity {
            id: vec![7],
            name: Some("alice".into()),
            display_name: Some("Alice".into()),
        };
        let ctx = ApprovalContext {
            ceremony: Ceremony::Create,
            rp_id: "example.com",
            rp_name: Some("Example"),
            candidates: &[],
            new_account: Some(&user),
            uv_required: false,
            origin: None,
        };
        let a = approver(
            Fake::new(
                ALL,
                vec![(Tool::Zenity, exit(0, "")), (Tool::Pkcheck, exit(0, ""))],
            ),
            cfg(&[UvMethod::Polkit]),
            &d,
        );
        assert_eq!(
            a.approve(&ctx).unwrap(),
            Approval {
                user_present: true,
                user_verified: true,
                selected: None
            }
        );
        assert!(
            calls(&a)[0]
                .args
                .iter()
                .any(|x| x.contains("Create a passkey for") && x.contains("Alice (alice)"))
        );
    }

    #[test]
    fn get_without_candidates_is_internal() {
        let d = TempDir::new("nocand");
        let a = approver(Fake::new(ALL, vec![]), cfg(&[UvMethod::Polkit]), &d);
        assert!(matches!(
            a.approve(&get(&[], false)),
            Err(ApprovalError::Internal(_))
        ));
    }

    #[test]
    fn fingerprint_retries_then_matches() {
        let d = TempDir::new("finger");
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::FprintdList, exit(0, ENROLLED)),
                    (Tool::FprintdVerify, exit(1, NO_MATCH)),
                    (
                        Tool::FprintdVerify,
                        exit(1, "Verify result: verify-swipe-too-short (done)\n"),
                    ),
                    (Tool::FprintdVerify, exit(0, MATCH)),
                ],
            ),
            cfg(&[UvMethod::Fingerprint]),
            &d,
        );
        assert!(a.approve(&get(&c, true)).unwrap().user_verified);
        let windows: Vec<String> = calls(&a)
            .iter()
            .filter(|c| c.tool == Tool::Zenity)
            .map(|c| {
                c.args
                    .iter()
                    .find(|x| x.starts_with("--text="))
                    .unwrap()
                    .clone()
            })
            .collect();
        assert_eq!(windows.len(), 3);
        assert!(windows[0].ends_with("\nTouch the fingerprint reader."));
        assert!(windows[1].contains("Not recognised. Try again (2 left).\nTouch"));
        assert!(windows[2].contains("The swipe was too short. Try again.\nTouch"));
    }

    #[test]
    fn fingerprint_three_misses_is_denied() {
        let d = TempDir::new("finger-miss");
        let c = one();
        let mut script = vec![(Tool::FprintdList, exit(0, ENROLLED))];
        script.extend((0..3).map(|_| (Tool::FprintdVerify, exit(1, NO_MATCH))));
        let a = approver(Fake::new(ALL, script), cfg(&[UvMethod::Fingerprint]), &d);
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Denied));
    }

    #[test]
    fn fingerprint_partial_output_is_not_trusted() {
        let d = TempDir::new("finger-partial");
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::FprintdList, exit(0, ENROLLED)),
                    (
                        Tool::FprintdVerify,
                        exit(0, "Verify result: verify-match (not done)\n"),
                    ),
                ],
            ),
            cfg(&[UvMethod::Fingerprint]),
            &d,
        );
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Unavailable));
    }

    #[test]
    fn fingerprint_timeout() {
        let d = TempDir::new("finger-timeout");
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::FprintdList, exit(0, ENROLLED)),
                    (Tool::FprintdVerify, RunResult::TimedOut),
                ],
            ),
            cfg(&[UvMethod::Fingerprint]),
            &d,
        );
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Timeout));
    }

    #[test]
    fn no_enrolled_finger_means_unavailable() {
        let d = TempDir::new("finger-none");
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![(
                    Tool::FprintdList,
                    exit(0, "User alice has no fingers enrolled.\n"),
                )],
            ),
            cfg(&[UvMethod::Fingerprint]),
            &d,
        );
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Unavailable));
    }

    #[test]
    fn zenity_missing() {
        let d = TempDir::new("nozenity");
        let c = one();
        let a = approver(
            Fake::new(&[Tool::Pkcheck], vec![]),
            cfg(&[UvMethod::Polkit]),
            &d,
        );
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Unavailable));
        assert!(calls(&a).is_empty());
    }

    #[test]
    fn dialog_timeouts() {
        for r in [exit(5, ""), RunResult::TimedOut] {
            let d = TempDir::new("timeout");
            let c = one();
            let a = approver(
                Fake::new(ALL, vec![(Tool::Zenity, r)]),
                cfg(&[UvMethod::Polkit]),
                &d,
            );
            assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Timeout));
        }
    }

    #[test]
    fn zenity_gets_its_own_timeout_and_grace() {
        let d = TempDir::new("grace");
        let c = one();
        let mut config = cfg(&[UvMethod::Polkit]);
        config.timeout = Duration::from_secs(30);
        let a = approver(
            Fake::new(ALL, vec![(Tool::Zenity, exit(1, ""))]),
            config,
            &d,
        );
        let _ = a.approve(&get(&c, true));
        let spec = &calls(&a)[0];
        assert!(spec.args.contains(&"--timeout=30".to_owned()));
        assert!(spec.timeout > Duration::from_secs(30) && spec.timeout <= Duration::from_secs(32));
    }

    #[test]
    fn rate_limited_per_rp() {
        let d = TempDir::new("rate");
        let c = one();
        let mut config = cfg(&[UvMethod::Polkit]);
        config.prompts_per_minute = 1;
        let a = approver(
            Fake::new(ALL, vec![(Tool::Zenity, exit(1, ""))]),
            config,
            &d,
        );
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Denied));
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Denied));
        assert_eq!(calls(&a).len(), 1);
    }

    #[test]
    fn config_file_errors_fail_closed() {
        let d = TempDir::new("badcfg");
        std::fs::create_dir_all(&d.0).unwrap();
        std::fs::write(d.0.join("config"), "methods = everything\n").unwrap();
        let paths = Paths {
            config_file: d.0.join("config"),
            state_dir: d.0.join("state"),
        };
        let a = HirzApprover::new(Fake::new(ALL, vec![]), &paths);
        let c = one();
        assert!(matches!(
            a.approve(&get(&c, true)),
            Err(ApprovalError::Internal(_))
        ));
    }

    #[test]
    fn pin_not_set_is_unavailable() {
        let d = TempDir::new("pin-unset");
        let c = one();
        let a = approver(Fake::new(ALL, vec![]), cfg(&[UvMethod::Pin]), &d);
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Unavailable));
        assert_eq!(a.available_uv_methods().unwrap(), []);
    }

    #[test]
    fn pin_locked() {
        let d = TempDir::new("pin-locked");
        write_verifier(&d, MAX_FAILURES);
        let c = one();
        let a = approver(
            Fake::new(ALL, vec![(Tool::Zenity, exit(0, "1234\n"))]),
            cfg(&[UvMethod::Pin]),
            &d,
        );
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Locked));
    }

    #[test]
    fn pin_locked_falls_back_to_polkit() {
        let d = TempDir::new("pin-locked-fb");
        write_verifier(&d, MAX_FAILURES);
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::Zenity, exit(0, "1234\n")),
                    (Tool::Zenity, exit(0, "")),
                    (Tool::Pkcheck, exit(0, "")),
                ],
            ),
            cfg(&[UvMethod::Pin, UvMethod::Polkit]),
            &d,
        );
        assert!(a.approve(&get(&c, true)).unwrap().user_verified);
    }

    #[test]
    fn pin_format_error_reprompts_without_counting() {
        let d = TempDir::new("pin-format");
        write_verifier(&d, 0);
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![(Tool::Zenity, exit(0, "12\n")), (Tool::Zenity, exit(1, ""))],
            ),
            cfg(&[UvMethod::Pin]),
            &d,
        );
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Denied));
        let cl = calls(&a);
        assert!(
            cl[1]
                .args
                .iter()
                .any(|x| x.contains("at least 4 characters"))
        );
        assert_eq!(a.pin_store().status().unwrap().unwrap().failures, 0);
    }

    #[test]
    fn pin_flow_with_real_crypto() {
        if !crypto_ready() {
            eprintln!("skipped: hirz-crypto placeholder");
            return;
        }
        let d = TempDir::new("pin-real");
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::Zenity, exit(0, "0000\n")),
                    (Tool::Zenity, exit(0, "1234\n")),
                ],
            ),
            cfg(&[UvMethod::Pin]),
            &d,
        );
        a.pin_store().set_pin(b"1234").unwrap();
        let r = a.approve(&get(&c, true)).unwrap();
        assert_eq!(
            r,
            Approval {
                user_present: true,
                user_verified: true,
                selected: Some(0)
            }
        );
        let cl = calls(&a);
        assert_eq!(&cl[0].args[..2], ["--entry", "--hide-text"]);
        assert!(
            cl[1]
                .args
                .iter()
                .any(|x| x.contains("Wrong PIN. 7 attempts left"))
        );
        assert_eq!(a.pin_store().status().unwrap().unwrap().failures, 0);
    }

    const WORDS: [&str; 4] = ["maple", "orbit", "quartz", "ember"];

    fn pairing() -> PairingApprovalContext<'static> {
        PairingApprovalContext {
            device_name: "desk",
            words: &WORDS,
            requested_at: 0,
        }
    }

    const VERIFIED: Approval = Approval {
        user_present: true,
        user_verified: true,
        selected: None,
    };

    #[test]
    fn pairing_shows_words_then_polkit() {
        let d = TempDir::new("pair-polkit");
        let a = approver(
            Fake::new(
                ALL,
                vec![(Tool::Zenity, exit(0, "")), (Tool::Pkcheck, exit(0, ""))],
            ),
            cfg(&[UvMethod::Polkit, UvMethod::Pin]),
            &d,
        );
        assert_eq!(a.confirm_pairing(&pairing()), Ok(VERIFIED));
        let cl = calls(&a);
        assert_eq!(cl.len(), 2);
        assert_eq!(cl[0].args[0], "--question");
        assert!(cl[0].args.contains(&"--default-cancel".to_owned()));
        assert!(cl[0].args.contains(&"--no-markup".to_owned()));
        let text = cl[0]
            .args
            .iter()
            .find_map(|x| x.strip_prefix("--text="))
            .unwrap();
        assert!(text.contains("Device name: desk"));
        assert!(text.contains("MAPLE    ORBIT    QUARTZ    EMBER"));
        assert!(text.contains("Do these 4 words match the ones on the new device?"));
        assert_eq!(cl[1].tool, Tool::Pkcheck);
        assert_eq!(cl[1].env, EnvPolicy::System);
    }

    #[test]
    fn pairing_cancel_is_denied_without_uv() {
        let d = TempDir::new("pair-cancel");
        let a = approver(
            Fake::new(ALL, vec![(Tool::Zenity, exit(1, ""))]),
            cfg(&[UvMethod::Polkit]),
            &d,
        );
        assert_eq!(a.confirm_pairing(&pairing()), Err(ApprovalError::Denied));
        assert_eq!(calls(&a).len(), 1);
    }

    #[test]
    fn pairing_uv_refused_or_timed_out() {
        for (r, want) in [
            (exit(1, ""), ApprovalError::Denied),
            (exit(3, ""), ApprovalError::Denied),
            (RunResult::TimedOut, ApprovalError::Timeout),
        ] {
            let d = TempDir::new("pair-uv-no");
            let a = approver(
                Fake::new(ALL, vec![(Tool::Zenity, exit(0, "")), (Tool::Pkcheck, r)]),
                cfg(&[UvMethod::Polkit]),
                &d,
            );
            assert_eq!(a.confirm_pairing(&pairing()), Err(want));
        }
    }

    #[test]
    fn pairing_falls_back_to_fingerprint_with_its_hint() {
        let d = TempDir::new("pair-finger");
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::Zenity, exit(0, "")),
                    (Tool::Pkcheck, exit(2, "")),
                    (Tool::FprintdList, exit(0, ENROLLED)),
                    (Tool::FprintdVerify, exit(0, MATCH)),
                ],
            ),
            cfg(&[UvMethod::Polkit, UvMethod::Fingerprint]),
            &d,
        );
        assert_eq!(a.confirm_pairing(&pairing()), Ok(VERIFIED));
        let cl = calls(&a);
        assert_eq!(cl.len(), 5);
        assert!(
            cl[4]
                .args
                .iter()
                .any(|x| x.contains("Touch the fingerprint reader.")
                    && x.contains("Approve the new device: desk")
                    && x.contains("MAPLE"))
        );
    }

    #[test]
    fn pairing_unavailable_everywhere_shows_nothing() {
        let d = TempDir::new("pair-none");
        let mut fake = Fake::new(
            ALL,
            vec![(
                Tool::FprintdList,
                exit(0, "User alice has no fingers enrolled.\n"),
            )],
        );
        fake.polkit_installed = false;
        let a = approver(
            fake,
            cfg(&[UvMethod::Polkit, UvMethod::Fingerprint, UvMethod::Pin]),
            &d,
        );
        assert_eq!(
            a.confirm_pairing(&pairing()),
            Err(ApprovalError::Unavailable)
        );
        assert!(calls(&a).iter().all(|c| c.tool != Tool::Zenity));
    }

    #[test]
    fn pairing_never_uses_click_to_allow() {
        for methods in [&[][..], &[UvMethod::Pin][..]] {
            let d = TempDir::new("pair-click");
            let mut config = cfg(methods);
            config.click_to_allow = vec!["example.com".into(), "desk".into()];
            let a = approver(Fake::new(ALL, vec![]), config, &d);
            assert_eq!(
                a.confirm_pairing(&pairing()),
                Err(ApprovalError::Unavailable)
            );
            assert!(calls(&a).is_empty());
        }
    }

    #[test]
    fn pairing_needs_zenity_and_four_words() {
        let d = TempDir::new("pair-zenity");
        let a = approver(
            Fake::new(&[Tool::Pkcheck], vec![]),
            cfg(&[UvMethod::Polkit]),
            &d,
        );
        assert_eq!(
            a.confirm_pairing(&pairing()),
            Err(ApprovalError::Unavailable)
        );
        let three = ["maple", "orbit", "quartz"];
        let ctx = PairingApprovalContext {
            device_name: "desk",
            words: &three,
            requested_at: 0,
        };
        assert!(matches!(
            a.confirm_pairing(&ctx),
            Err(ApprovalError::Internal(_))
        ));
        assert!(calls(&a).is_empty());
    }

    #[test]
    fn pairing_busy_and_rate_limited() {
        let d = TempDir::new("pair-rate");
        let mut config = cfg(&[UvMethod::Polkit]);
        config.prompts_per_minute = 1;
        let a = approver(
            Fake::new(ALL, vec![(Tool::Zenity, exit(1, ""))]),
            config,
            &d,
        );
        {
            let _held = a.busy.lock().unwrap();
            assert_eq!(a.confirm_pairing(&pairing()), Err(ApprovalError::Denied));
        }
        assert!(calls(&a).is_empty());
        assert_eq!(a.confirm_pairing(&pairing()), Err(ApprovalError::Denied));
        assert_eq!(a.confirm_pairing(&pairing()), Err(ApprovalError::Denied));
        assert_eq!(calls(&a).len(), 1);
    }

    #[test]
    fn pairing_pin_locked() {
        let d = TempDir::new("pair-pin-locked");
        write_verifier(&d, MAX_FAILURES);
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::Zenity, exit(0, "")),
                    (Tool::Zenity, exit(0, "1234\n")),
                ],
            ),
            cfg(&[UvMethod::Pin]),
            &d,
        );
        assert_eq!(a.confirm_pairing(&pairing()), Err(ApprovalError::Locked));
    }

    #[test]
    fn pairing_pin_with_real_crypto() {
        if !crypto_ready() {
            eprintln!("skipped: hirz-crypto placeholder");
            return;
        }
        let d = TempDir::new("pair-pin");
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::Zenity, exit(0, "")),
                    (Tool::Zenity, exit(0, "0000\n")),
                    (Tool::Zenity, exit(0, "1234\n")),
                ],
            ),
            cfg(&[UvMethod::Pin]),
            &d,
        );
        a.pin_store().set_pin(b"1234").unwrap();
        assert_eq!(a.confirm_pairing(&pairing()), Ok(VERIFIED));
        let cl = calls(&a);
        assert_eq!(cl[0].args[0], "--question");
        assert_eq!(&cl[1].args[..2], ["--entry", "--hide-text"]);
        assert!(
            cl[2]
                .args
                .iter()
                .any(|x| x.contains("Wrong PIN.") && x.contains("Approve the new device: desk"))
        );
    }

    fn texts(a: &HirzApprover<Fake>) -> Vec<String> {
        calls(a)
            .iter()
            .filter(|c| c.tool == Tool::Zenity)
            .map(|c| {
                c.args
                    .iter()
                    .find_map(|x| x.strip_prefix("--text="))
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn fingerprint_window_cancel_is_denied() {
        let d = TempDir::new("finger-cancel");
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::FprintdList, exit(0, ENROLLED)),
                    (Tool::Zenity, exit(1, "")),
                ],
            ),
            cfg(&[UvMethod::Fingerprint, UvMethod::Polkit]),
            &d,
        );
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Denied));
        let cl = calls(&a);
        assert_eq!(cl.len(), 3);
        assert_eq!(cl[1].tool, Tool::FprintdVerify);
        assert_eq!(cl[1].env, EnvPolicy::System);
        assert_eq!(cl[2].args[0], "--question");
        assert!(cl[2].args.contains(&"--no-markup".to_owned()));
        assert!(
            cl[2]
                .args
                .contains(&"--ok-label=Use password instead".to_owned())
        );
        assert!(cl[2].args.iter().all(|x| x.starts_with("--")));
    }

    #[test]
    fn fingerprint_use_password_instead_goes_straight_to_polkit() {
        let d = TempDir::new("finger-choose");
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::FprintdList, exit(0, ENROLLED)),
                    (Tool::FprintdVerify, exit(1, NO_MATCH)),
                    (Tool::Zenity, exit(0, "")),
                    (Tool::Pkcheck, exit(0, "")),
                ],
            ),
            cfg(&[UvMethod::Fingerprint, UvMethod::Polkit]),
            &d,
        );
        assert!(a.approve(&get(&c, true)).unwrap().user_verified);
        let tools: Vec<Tool> = calls(&a).iter().map(|c| c.tool).collect();
        assert_eq!(
            tools,
            [
                Tool::FprintdList,
                Tool::FprintdVerify,
                Tool::Zenity,
                Tool::FprintdVerify,
                Tool::Zenity,
                Tool::Pkcheck
            ]
        );
    }

    #[test]
    fn fingerprint_misses_fall_back_with_a_note() {
        let d = TempDir::new("finger-fallback");
        let c = one();
        let mut script = vec![(Tool::FprintdList, exit(0, ENROLLED))];
        script.extend((0..3).map(|_| (Tool::FprintdVerify, exit(1, NO_MATCH))));
        script.push((Tool::Zenity, exit(0, "")));
        script.push((Tool::Pkcheck, exit(0, "")));
        let a = approver(
            Fake::new(ALL, script),
            cfg(&[UvMethod::Fingerprint, UvMethod::Polkit]),
            &d,
        );
        assert!(a.approve(&get(&c, true)).unwrap().user_verified);
        let t = texts(&a);
        assert_eq!(t.len(), 4);
        assert!(t[2].contains("Not recognised. Try again (1 left)."));
        assert!(t[3].contains(
            "Your fingerprint was not recognised.\nNext, your system will ask for your password."
        ));
    }

    #[test]
    fn reader_error_falls_back_and_missing_fingers_hint_once() {
        let d = TempDir::new("finger-error");
        let c = one();
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::FprintdList, exit(0, ENROLLED)),
                    (
                        Tool::FprintdVerify,
                        exit(1, "Verify result: verify-disconnected (done)\n"),
                    ),
                    (Tool::Zenity, exit(0, "")),
                    (Tool::Pkcheck, exit(0, "")),
                    (Tool::FprintdList, exit(0, ENROLLED)),
                    (
                        Tool::FprintdVerify,
                        exit(
                            1,
                            "VerifyStart failed: net.reactivated.Fprint.Error.NoEnrolledPrints\n",
                        ),
                    ),
                    (Tool::Zenity, exit(0, "")),
                    (Tool::Pkcheck, exit(0, "")),
                    (Tool::FprintdList, exit(0, ENROLLED)),
                    (
                        Tool::FprintdVerify,
                        exit(
                            1,
                            "VerifyStart failed: net.reactivated.Fprint.Error.NoEnrolledPrints\n",
                        ),
                    ),
                    (Tool::Zenity, exit(0, "")),
                    (Tool::Pkcheck, exit(0, "")),
                ],
            ),
            cfg(&[UvMethod::Fingerprint, UvMethod::Polkit]),
            &d,
        );
        for _ in 0..3 {
            assert!(a.approve(&get(&c, true)).unwrap().user_verified);
        }
        let t = texts(&a);
        assert_eq!(t.len(), 6);
        assert!(t[1].contains("The fingerprint reader is not working right now."));
        assert!(t[3].contains("Settings > Users, or run fprintd-enroll"));
        assert!(!t[5].contains("fprintd-enroll"), "the hint is shown once");
    }

    #[test]
    fn listing_no_fingers_sets_the_hint() {
        let d = TempDir::new("finger-list-none");
        let a = approver(
            Fake::new(
                ALL,
                vec![(
                    Tool::FprintdList,
                    exit(0, "User alice has no fingers enrolled for Acme Reader.\n"),
                )],
            ),
            cfg(&[UvMethod::Fingerprint]),
            &d,
        );
        assert_eq!(a.available_uv_methods().unwrap(), []);
        assert!(a.no_fingers_hinted.load(Ordering::Relaxed));
    }

    #[test]
    fn window_icon_from_the_runner() {
        const ICON: &str = "/usr/share/icons/hicolor/scalable/apps/hirz.svg";
        let d = TempDir::new("icon");
        let c = one();
        let mut fake = Fake::new(
            ALL,
            vec![
                (Tool::FprintdList, exit(0, ENROLLED)),
                (Tool::FprintdVerify, exit(1, NO_MATCH)),
                (Tool::Zenity, exit(0, "")),
                (Tool::Pkcheck, exit(0, "")),
            ],
        );
        fake.icon = Some(PathBuf::from(ICON));
        let a = approver(fake, cfg(&[UvMethod::Fingerprint, UvMethod::Polkit]), &d);
        a.approve(&get(&c, true)).unwrap();
        let zenity: Vec<CommandSpec> = calls(&a)
            .into_iter()
            .filter(|c| c.tool == Tool::Zenity)
            .collect();
        assert_eq!(zenity.len(), 2);
        for z in &zenity {
            assert_eq!(z.args[1], format!("--window-icon={ICON}"));
        }
        let d = TempDir::new("no-icon");
        let a = approver(
            Fake::new(ALL, vec![(Tool::Zenity, exit(1, ""))]),
            cfg(&[UvMethod::Polkit]),
            &d,
        );
        let _ = a.approve(&get(&c, true));
        assert!(
            !calls(&a)[0]
                .args
                .iter()
                .any(|x| x.starts_with("--window-icon"))
        );
    }

    fn removal() -> RemovalApprovalContext<'static> {
        RemovalApprovalContext {
            device_name: "old-laptop",
            device_id_short: "0a1b2c3d4e5f",
        }
    }

    #[test]
    fn removal_shows_device_then_polkit() {
        let d = TempDir::new("rm-polkit");
        let a = approver(
            Fake::new(
                ALL,
                vec![(Tool::Zenity, exit(0, "")), (Tool::Pkcheck, exit(0, ""))],
            ),
            cfg(&[UvMethod::Polkit]),
            &d,
        );
        assert_eq!(a.confirm_removal(&removal()), Ok(VERIFIED));
        let cl = calls(&a);
        assert_eq!(cl.len(), 2);
        assert_eq!(cl[0].args[0], "--question");
        assert!(cl[0].args.contains(&"--default-cancel".to_owned()));
        assert!(cl[0].args.contains(&"--ok-label=Remove".to_owned()));
        let t = texts(&a);
        assert!(t[0].contains("Device name: old-laptop") && t[0].contains("0a1b2c3d4e5f"));
        assert_eq!(cl[1].tool, Tool::Pkcheck);
    }

    #[test]
    fn removal_cancel_refusal_and_no_click() {
        let d = TempDir::new("rm-cancel");
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::Zenity, exit(1, "")),
                    (Tool::Zenity, exit(0, "")),
                    (Tool::Pkcheck, exit(1, "")),
                ],
            ),
            cfg(&[UvMethod::Polkit]),
            &d,
        );
        assert_eq!(a.confirm_removal(&removal()), Err(ApprovalError::Denied));
        assert_eq!(calls(&a).len(), 1);
        assert_eq!(a.confirm_removal(&removal()), Err(ApprovalError::Denied));
        assert_eq!(calls(&a).len(), 3);

        for methods in [&[][..], &[UvMethod::Pin][..]] {
            let d = TempDir::new("rm-click");
            let mut config = cfg(methods);
            config.click_to_allow = vec!["example.com".into(), "old-laptop".into()];
            let a = approver(Fake::new(ALL, vec![]), config, &d);
            assert_eq!(
                a.confirm_removal(&removal()),
                Err(ApprovalError::Unavailable)
            );
            assert!(calls(&a).is_empty());
        }
    }

    #[test]
    fn removal_fingerprint_window_and_pin_lock() {
        let d = TempDir::new("rm-finger");
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::FprintdList, exit(0, ENROLLED)),
                    (Tool::Zenity, exit(0, "")),
                    (Tool::FprintdVerify, exit(0, MATCH)),
                ],
            ),
            cfg(&[UvMethod::Fingerprint]),
            &d,
        );
        assert_eq!(a.confirm_removal(&removal()), Ok(VERIFIED));
        let t = texts(&a);
        assert!(t[0].ends_with("After you continue, touch the fingerprint reader."));
        assert!(t[1].starts_with("Remove the device: old-laptop (id 0a1b2c3d4e5f)"));

        let d = TempDir::new("rm-pin-locked");
        write_verifier(&d, MAX_FAILURES);
        let a = approver(
            Fake::new(
                ALL,
                vec![
                    (Tool::Zenity, exit(0, "")),
                    (Tool::Zenity, exit(0, "1234\n")),
                ],
            ),
            cfg(&[UvMethod::Pin]),
            &d,
        );
        assert_eq!(a.confirm_removal(&removal()), Err(ApprovalError::Locked));
        let t = texts(&a);
        assert!(t[0].ends_with("Next, enter your hirz PIN."));
        assert!(t[1].starts_with("Remove the device: old-laptop"));
    }

    #[test]
    fn removal_and_pairing_have_separate_limits() {
        let d = TempDir::new("rm-rate");
        let mut config = cfg(&[UvMethod::Polkit]);
        config.prompts_per_minute = 1;
        let a = approver(
            Fake::new(
                ALL,
                vec![(Tool::Zenity, exit(1, "")), (Tool::Zenity, exit(1, ""))],
            ),
            config,
            &d,
        );
        assert_eq!(a.confirm_pairing(&pairing()), Err(ApprovalError::Denied));
        assert_eq!(a.confirm_removal(&removal()), Err(ApprovalError::Denied));
        assert_eq!(a.confirm_removal(&removal()), Err(ApprovalError::Denied));
        assert_eq!(calls(&a).len(), 2);
    }

    #[test]
    fn list_hint_is_neutral() {
        let d = TempDir::new("list-hint");
        let c = two();
        let a = approver(
            Fake::new(ALL, vec![(Tool::Zenity, exit(1, ""))]),
            cfg(&[UvMethod::Pin]),
            &d,
        );
        write_verifier(&d, 0);
        assert_eq!(a.approve(&get(&c, true)), Err(ApprovalError::Denied));
        let t = texts(&a);
        assert!(t[0].ends_with("Choose an account, then confirm it is you."));
        assert!(!t[0].contains("PIN"));
    }
}
