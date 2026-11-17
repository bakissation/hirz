//! The CTAP engine adapter: [`hirz_ctap::Authenticator`] over a [`Session`]. The approval prompt
//! cannot be interrupted, so a cancelled request creates and signs nothing (docs/uhid.md,
//! "Cancellation").

use std::time::{Duration, Instant};

use hirz_core::{
    ApprovalError, Approver, AssertionResponse, CoreError, GetAssertionRequest, HmacSecretWrap,
    MakeCredentialRequest, MakeCredentialResponse,
};
use hirz_ctap::Authenticator;
use hirz_ctap::hid::RequestContext;

use hirz_uv::{CommandRunner, HirzApprover};

use crate::log;
use crate::session::{
    FORK_ENDED_NOTICE, FORK_NOTICE, FirstRun, HOLD_POLL, Hold, QUIET_NOTICE, READ_ONLY_MAX_AGE,
    REMOVED_NOTICE, Session, SetupLauncher, SetupOffer, SystemLauncher, VaultStatus,
};

const NOTICE_INTERVAL: Duration = Duration::from_secs(600);
const NO_VAULT: &str = "no hirz vault on this device; run `hirz init` first";
const SETUP_OPENED: &str = "no hirz vault on this device yet; a setup window was opened";

#[derive(Debug)]
pub struct Notice {
    desktop: bool,
    last: Option<Instant>,
    removed_told: bool,
}

impl Notice {
    pub fn new(desktop: bool) -> Self {
        Notice {
            desktop,
            last: None,
            removed_told: false,
        }
    }

    fn removed(&mut self) {
        if core::mem::replace(&mut self.removed_told, true) {
            return;
        }
        log(format_args!("{REMOVED_NOTICE}"));
        if self.desktop {
            notify_desktop(&format!("hirz: {REMOVED_NOTICE}."));
        }
    }

    /// `active`: the vault folder started to report a fork (true) or stopped (false).
    fn fork(&mut self, active: bool) {
        if !active {
            log(format_args!("{FORK_ENDED_NOTICE}"));
            return;
        }
        log(format_args!("{FORK_NOTICE}"));
        if self.desktop {
            notify_desktop(&format!("hirz: {FORK_NOTICE}"));
        }
    }

    /// `setup_opened`: this request started the setup window, which is said at once.
    fn no_vault(&mut self, setup_opened: bool) {
        let now = Instant::now();
        if !setup_opened
            && self
                .last
                .is_some_and(|t| now.saturating_duration_since(t) < NOTICE_INTERVAL)
        {
            return;
        }
        self.last = Some(now);
        if setup_opened {
            // The setup window itself is the feedback.
            log(format_args!("{SETUP_OPENED}"));
            return;
        }
        log(format_args!("{NO_VAULT}"));
        if self.desktop {
            notify_desktop("hirz: no passkey vault on this device yet. Run \"hirz init\" first.");
        }
    }
}

fn notify_desktop(text: &str) {
    hirz_uv::first_run::notify_desktop(text);
}

/// What getInfo says about user verification: whether some verifying method works right now.
pub trait UvProbe {
    fn uv_available(&self) -> bool;
}

impl<R: CommandRunner> UvProbe for HirzApprover<R> {
    fn uv_available(&self) -> bool {
        self.available_uv_methods()
            .is_ok_and(|methods| !methods.is_empty())
    }
}

#[derive(Debug)]
pub struct VaultAuthenticator<A, L = SystemLauncher> {
    session: Session<A>,
    notice: Notice,
    first_run: FirstRun<L>,
    hold: Hold,
}

/// How long a request waits for the setup window: the CTAPHID transaction limit less the margin
/// the approval prompt keeps (docs/approval.md, "Setting up hirz").
pub fn default_hold() -> Hold {
    Hold {
        limit: hirz_ctap::hid::Config::default()
            .processing_timeout
            .saturating_sub(crate::APPROVAL_MARGIN),
        poll: HOLD_POLL,
    }
}

impl<A: Approver> VaultAuthenticator<A> {
    /// Without a setup window: see [`VaultAuthenticator::with_first_run`].
    pub fn new(session: Session<A>, notice: Notice) -> Self {
        VaultAuthenticator {
            session,
            notice,
            first_run: FirstRun::disabled(),
            hold: default_hold(),
        }
    }
}

impl<A: Approver, L: SetupLauncher> VaultAuthenticator<A, L> {
    /// Requests that would ask the user start the first-run setup when there is no vault.
    pub fn with_first_run<M: SetupLauncher>(
        self,
        first_run: FirstRun<M>,
    ) -> VaultAuthenticator<A, M> {
        VaultAuthenticator {
            session: self.session,
            notice: self.notice,
            first_run,
            hold: self.hold,
        }
    }

    #[cfg(test)]
    pub fn with_hold(mut self, hold: Hold) -> Self {
        self.hold = hold;
        self
    }

    /// After `prepare`: the vault was looked at for this request already.
    fn select_prepared(&mut self, ctx: &RequestContext) -> Result<(), CoreError> {
        logged(
            self.session
                .with_engine(&|| ctx.is_cancelled(), |e| e.select()),
        )
    }

    /// A fork is logged (and shown once on the desktop) when it starts and when it ends, not
    /// with every request.
    fn report_fork(&mut self) {
        if let Some(active) = self.session.take_fork_change() {
            self.notice.fork(active);
        }
    }

    /// `probe`: a silent existence check (`up: false`), which asks nobody and writes nothing. The
    /// browser sends one per listed credential on every page, so a probe uses the last look at the
    /// vault folder when that is recent instead of scanning and maintaining it again.
    fn prepare(&mut self, ctx: &RequestContext, request: Request) -> Result<(), CoreError> {
        if ctx.is_cancelled() {
            return Err(CoreError::Approval(ApprovalError::Denied));
        }
        let probe = request == Request::Probe;
        let mut status = if probe {
            self.session.ensure_vault_recent(READ_ONLY_MAX_AGE)
        } else {
            self.session.ensure_vault()
        };
        self.report_fork();
        // A request that would ask the user opens the setup window. Only a registration waits for
        // it, like for an approval, and then goes on with the normal approval; anything else has
        // nothing to use yet and is answered at once. Silent probes never open it.
        let mut told = false;
        if status == VaultStatus::Missing && !probe {
            match self.first_run.offer() {
                offer @ (SetupOffer::Opened | SetupOffer::AlreadyOpen) => {
                    if offer == SetupOffer::Opened {
                        self.notice.no_vault(true);
                    }
                    if request == Request::Register {
                        status = self.first_run.wait_for_setup(
                            &mut self.session,
                            &|| ctx.is_cancelled(),
                            self.hold,
                        );
                        self.report_fork();
                    }
                    told = true;
                }
                SetupOffer::QuietNotice => {
                    log(format_args!("{QUIET_NOTICE}"));
                    told = true;
                }
                SetupOffer::NotOffered => {}
            }
        }
        match status {
            VaultStatus::Ready => Ok(()),
            VaultStatus::Missing => {
                if !told {
                    self.notice.no_vault(false);
                }
                if request == Request::SignIn {
                    // No vault, no passkey: the platform says so and offers other ways in. The
                    // setup window, when it opened, is the feedback; no "no passkey" notice.
                    return Err(CoreError::NoCredentials);
                }
                // NOT_ALLOWED: the platform ends the ceremony and the user sees that the key refused.
                Err(CoreError::Approval(ApprovalError::Unavailable))
            }
            VaultStatus::Removed => {
                self.notice.removed();
                Err(CoreError::Approval(ApprovalError::Unavailable))
            }
            VaultStatus::Broken(why) => {
                log(format_args!("cannot open the vault: {why}"));
                Err(CoreError::Vault(why))
            }
        }
    }
}

/// What a request is, for what it does without a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Request {
    /// getAssertion with `up: false`: asks nobody, opens nothing.
    Probe,
    /// A real makeCredential: waits for the setup window.
    Register,
    /// getAssertion with user presence, or a touch request: "no passkey" at once.
    SignIn,
    /// authenticatorSelection: refused at once (CTAP allows no "no credential" answer there).
    Select,
}

/// Platforms send a throwaway makeCredential only to wait for a touch: Firefox (authenticator-rs
/// `dummy_make_credentials_cmd`) uses the RP id `make.me.blink`, Chromium `.dummy`. Asks for
/// presence like authenticatorSelection and stores nothing.
fn is_touch_request(req: &MakeCredentialRequest) -> bool {
    req.rp.id == "make.me.blink" || req.rp.id.starts_with('.')
}

/// Relying party ids of machine login and disk unlock (`pam://HOST` from pam-u2f, and the ids
/// systemd-homed and systemd-cryptenroll use; the list is in `hirz_core::machine_login`). Refused
/// before the vault is opened or anything is shown; the engine refuses them as well.
fn refuse_machine_login(rp_id: &str) -> Result<(), CoreError> {
    if hirz_core::engine::is_machine_login_rp_id(rp_id) {
        log(format_args!(
            "refused rp id {rp_id:?}: hirz passkeys cannot unlock or log in to this computer \
             (pam-u2f, systemd-homed, systemd-cryptenroll); use a hardware security key for that"
        ));
        return Err(CoreError::Approval(ApprovalError::Unavailable));
    }
    Ok(())
}

fn logged<T>(r: Result<T, CoreError>) -> Result<T, CoreError> {
    if let Err(CoreError::Vault(e) | CoreError::Crypto(e)) = &r {
        log(format_args!("request failed: {e}"));
    }
    r
}

impl<A: Approver + UvProbe + Send, L: SetupLauncher + Send> Authenticator
    for VaultAuthenticator<A, L>
{
    fn make_credential(
        &mut self,
        req: &MakeCredentialRequest,
        ctx: &RequestContext,
    ) -> Result<MakeCredentialResponse, CoreError> {
        refuse_machine_login(&req.rp.id)?;
        let touch = is_touch_request(req);
        self.prepare(
            ctx,
            if touch {
                Request::SignIn
            } else {
                Request::Register
            },
        )?;
        if touch {
            self.select_prepared(ctx)?;
            // The touch happened; the throwaway request itself is refused with NOT_ALLOWED, not
            // with the OPERATION_DENIED of a user who declined.
            return Err(CoreError::Approval(ApprovalError::Unavailable));
        }
        let result = logged(
            self.session
                .with_engine(&|| ctx.is_cancelled(), |e| e.make_credential(req, None)),
        );
        self.report_fork();
        result
    }

    fn get_assertion(
        &mut self,
        req: &GetAssertionRequest,
        hmac: Option<&dyn HmacSecretWrap>,
        ctx: &RequestContext,
    ) -> Result<AssertionResponse, CoreError> {
        refuse_machine_login(&req.rp_id)?;
        self.prepare(
            ctx,
            if req.up {
                Request::SignIn
            } else {
                Request::Probe
            },
        )?;
        let result = logged(
            self.session
                .with_engine(&|| ctx.is_cancelled(), |e| e.get_assertion(req, None, hmac)),
        );
        self.report_fork();
        if req.up && result.as_ref().err() == Some(&CoreError::NoCredentials) {
            self.first_run.no_passkey_notice(&req.rp_id);
        }
        result
    }

    fn select(&mut self, ctx: &RequestContext) -> Result<(), CoreError> {
        self.prepare(ctx, Request::Select)?;
        self.select_prepared(ctx)
    }

    fn user_verification_available(&mut self) -> bool {
        self.session.approver().uv_available()
    }
}
