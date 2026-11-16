//! The approval flow: pick a method, show the site and account, run the check, map the
//! result. Everything outside the process goes through [`CommandRunner`].

use std::path::PathBuf;
use std::sync::{Mutex, TryLockError};
use std::time::{Duration, Instant};

use hirz_core::{Approval, ApprovalContext, ApprovalError, Approver, Ceremony};
use hirz_crypto::Secret;

use crate::config::{self, Config, Paths, UvMethod};
use crate::display::{self, Step};
use crate::fprint::{self, VerifyOutcome};
use crate::pin::{PinError, PinStore};
use crate::polkit::{self, PkcheckOutcome};
use crate::ratelimit::RateLimiter;
use crate::runner::{CommandRunner, CommandSpec, EnvPolicy, RunResult, SystemRunner, Tool};

/// Extra time a zenity child gets past its own `--timeout` before hirz kills it.
const DIALOG_GRACE: Duration = Duration::from_secs(2);
const FPRINTD_LIST_TIMEOUT: Duration = Duration::from_secs(5);
const FINGER_ATTEMPTS: u32 = 3;
const PIN_PROMPTS: u32 = 5;
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
        RunResult::Exited { code: Some(1), .. } => Err(ApprovalError::Denied),
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

    fn uv_available(&self, m: UvMethod, deadline: &Deadline) -> bool {
        match m {
            UvMethod::Polkit => {
                self.runner.tool_available(Tool::Pkcheck) && self.runner.polkit_action_installed()
            }
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
                        fprint::has_enrolled_fingers(code, &stdout)
                    }
                    _ => false,
                }
            }
            UvMethod::Pin => self.pins.is_set(),
        }
    }

    fn next_available(
        &self,
        queue: &mut impl Iterator<Item = Method>,
        ctx: &ApprovalContext<'_>,
        deadline: &Deadline,
    ) -> Option<Method> {
        queue.find(|m| match m {
            Method::ClickToAllow => !ctx.uv_required,
            Method::Uv(u) => self.uv_available(*u, deadline),
        })
    }

    fn dialog(
        &self,
        deadline: &Deadline,
        build: impl FnOnce(Duration) -> Vec<String>,
    ) -> Result<Secret, ApprovalError> {
        let remaining = deadline.remaining()?;
        map_dialog(self.runner.run(&CommandSpec {
            tool: Tool::Zenity,
            args: build(remaining),
            env: EnvPolicy::Desktop,
            timeout: remaining.saturating_add(DIALOG_GRACE),
        }))
    }

    /// Get with several accounts: the user picks one first. Returns the selection and whether
    /// the context (site and account) was shown.
    fn select(
        &self,
        ctx: &ApprovalContext<'_>,
        step: Step,
        deadline: &Deadline,
    ) -> Result<(Option<usize>, bool), ApprovalError> {
        match (ctx.ceremony, ctx.candidates.len()) {
            (Ceremony::Create, _) => Ok((None, false)),
            (Ceremony::Get, 0) => Err(ApprovalError::Internal("no candidate accounts".into())),
            (Ceremony::Get, 1) => Ok((Some(0), false)),
            (Ceremony::Get, n) => {
                let out = self.dialog(deadline, |rem| {
                    display::list_args(ctx, ctx.candidates, step, rem)
                })?;
                let idx = display::parse_list_selection(&out, n).ok_or(ApprovalError::Denied)?;
                Ok((Some(idx), true))
            }
        }
    }

    fn ensure_context(
        &self,
        ctx: &ApprovalContext<'_>,
        selected: Option<usize>,
        step: Step,
        shown: &mut Option<Step>,
        deadline: &Deadline,
    ) -> Result<(), ApprovalError> {
        if *shown == Some(step) {
            return Ok(());
        }
        self.dialog(deadline, |rem| {
            display::question_args(ctx, selected, step, rem)
        })?;
        *shown = Some(step);
        Ok(())
    }

    fn perform(
        &self,
        method: Method,
        ctx: &ApprovalContext<'_>,
        selected: Option<usize>,
        shown: &mut Option<Step>,
        deadline: &Deadline,
    ) -> Result<(), ApprovalError> {
        match method {
            Method::ClickToAllow => {
                if ctx.uv_required {
                    return Err(ApprovalError::Unavailable);
                }
                self.ensure_context(ctx, selected, Step::ClickToAllow, shown, deadline)
            }
            Method::Uv(UvMethod::Polkit) => {
                self.ensure_context(ctx, selected, method.step(), shown, deadline)?;
                self.run_polkit(deadline)
            }
            Method::Uv(UvMethod::Fingerprint) => {
                self.ensure_context(ctx, selected, method.step(), shown, deadline)?;
                self.run_fingerprint(deadline)
            }
            Method::Uv(UvMethod::Pin) => {
                let r = self.run_pin(ctx, selected, deadline);
                *shown = Some(method.step());
                r
            }
        }
    }

    fn run_polkit(&self, deadline: &Deadline) -> Result<(), ApprovalError> {
        let id = self
            .runner
            .process_identity()
            .ok_or_else(|| ApprovalError::Internal("cannot read the process identity".into()))?;
        map_pkcheck(self.runner.run(&CommandSpec {
            tool: Tool::Pkcheck,
            args: polkit::pkcheck_args(&id),
            env: EnvPolicy::System,
            timeout: deadline.remaining()?,
        }))
    }

    fn run_fingerprint(&self, deadline: &Deadline) -> Result<(), ApprovalError> {
        for _ in 0..FINGER_ATTEMPTS {
            let r = self.runner.run(&CommandSpec {
                tool: Tool::FprintdVerify,
                args: Vec::new(),
                env: EnvPolicy::System,
                timeout: deadline.remaining()?,
            });
            match r {
                RunResult::Exited { code, stdout, .. } => {
                    match fprint::classify_verify(code, &stdout) {
                        VerifyOutcome::Match => return Ok(()),
                        VerifyOutcome::NoMatch => {}
                        VerifyOutcome::Unavailable => {
                            diag(
                                "fingerprint verification unavailable (no reader, no enrolled finger or device error)",
                            );
                            return Err(ApprovalError::Unavailable);
                        }
                    }
                }
                RunResult::TimedOut => return Err(ApprovalError::Timeout),
                RunResult::NotFound => return Err(ApprovalError::Unavailable),
                RunResult::Failed(m) => {
                    return Err(ApprovalError::Internal(format!("fprintd-verify: {m}")));
                }
            }
        }
        Err(ApprovalError::Denied)
    }

    fn run_pin(
        &self,
        ctx: &ApprovalContext<'_>,
        selected: Option<usize>,
        deadline: &Deadline,
    ) -> Result<(), ApprovalError> {
        let mut notice: Option<String> = None;
        for _ in 0..PIN_PROMPTS {
            let out = self.dialog(deadline, |rem| {
                display::pin_args(ctx, selected, notice.as_deref(), rem)
            })?;
            match self.pins.verify(display::strip_entry_newline(&out)) {
                Ok(()) => return Ok(()),
                Err(PinError::Wrong { remaining: 0 } | PinError::Locked) => {
                    diag(
                        "the hirz PIN is locked after too many wrong attempts; reset it with the hirz CLI",
                    );
                    return Err(ApprovalError::Locked);
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
                Err(PinError::NotSet) => return Err(ApprovalError::Unavailable),
                Err(PinError::Corrupt) => {
                    return Err(ApprovalError::Internal(
                        "the PIN verifier file is damaged".into(),
                    ));
                }
                Err(PinError::Io(kind)) => {
                    return Err(ApprovalError::Internal(format!("PIN verifier: {kind}")));
                }
                Err(PinError::Crypto | PinError::AlreadySet) => {
                    return Err(ApprovalError::Internal("PIN check failed".into()));
                }
            }
        }
        Err(ApprovalError::Denied)
    }
}

impl<R: CommandRunner> Approver for HirzApprover<R> {
    fn approve(&self, ctx: &ApprovalContext<'_>) -> Result<Approval, ApprovalError> {
        let _busy = match self.busy.try_lock() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => return Err(ApprovalError::Denied),
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
        };
        let config = self.config()?;
        let allowed = match self.limiter.lock() {
            Ok(mut l) => l.allow(ctx.rp_id, Instant::now(), config.prompts_per_minute),
            Err(p) => p
                .into_inner()
                .allow(ctx.rp_id, Instant::now(), config.prompts_per_minute),
        };
        if !allowed {
            diag("too many approval prompts for one site; try again in a minute");
            return Err(ApprovalError::Denied);
        }
        if !self.runner.tool_available(Tool::Zenity) {
            diag(ZENITY_MISSING);
            return Err(ApprovalError::Unavailable);
        }
        let deadline = Deadline::start(config.timeout);
        let mut queue = plan_methods(&config, ctx)?.into_iter();
        let mut method = self
            .next_available(&mut queue, ctx, &deadline)
            .ok_or(ApprovalError::Unavailable)?;
        let (selected, list_shown) = self.select(ctx, method.step(), &deadline)?;
        let mut shown = list_shown.then_some(method.step());
        let mut locked = false;
        loop {
            match self.perform(method, ctx, selected, &mut shown, &deadline) {
                Ok(()) => {
                    return Ok(Approval {
                        user_present: true,
                        user_verified: matches!(method, Method::Uv(_)),
                        selected,
                    });
                }
                Err(ApprovalError::Unavailable) => {}
                Err(ApprovalError::Locked) => locked = true,
                Err(e) => return Err(e),
            }
            method = match self.next_available(&mut queue, ctx, &deadline) {
                Some(m) => m,
                None if locked => return Err(ApprovalError::Locked),
                None => return Err(ApprovalError::Unavailable),
            };
        }
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
        script: Mutex<VecDeque<(Tool, RunResult)>>,
        calls: Mutex<Vec<CommandSpec>>,
    }

    impl Fake {
        fn new(tools: &[Tool], script: Vec<(Tool, RunResult)>) -> Self {
            Fake {
                tools: tools.to_vec(),
                polkit_installed: true,
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
                &mut shown,
                &deadline
            ),
            Err(ApprovalError::Unavailable)
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
                    (Tool::Zenity, exit(0, "")),
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
        assert!(
            cl[3]
                .args
                .iter()
                .any(|x| x.contains("touch the fingerprint reader"))
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
        for script in [exit(1, ""), exit(0, "7\n"), exit(0, ""), exit(0, "1|2\n")] {
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
                    (Tool::Zenity, exit(0, "")),
                    (Tool::FprintdVerify, exit(1, NO_MATCH)),
                    (Tool::FprintdVerify, exit(0, MATCH)),
                ],
            ),
            cfg(&[UvMethod::Fingerprint]),
            &d,
        );
        assert!(a.approve(&get(&c, true)).unwrap().user_verified);
    }

    #[test]
    fn fingerprint_three_misses_is_denied() {
        let d = TempDir::new("finger-miss");
        let c = one();
        let mut script = vec![
            (Tool::FprintdList, exit(0, ENROLLED)),
            (Tool::Zenity, exit(0, "")),
        ];
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
                    (Tool::Zenity, exit(0, "")),
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
                    (Tool::Zenity, exit(0, "")),
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
}
