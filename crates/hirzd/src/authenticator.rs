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

use crate::log;
use crate::session::{REMOVED_NOTICE, Session, VaultStatus};

const NOTICE_INTERVAL: Duration = Duration::from_secs(600);
const NO_VAULT: &str = "no hirz vault on this device; run `hirz init` first";

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

    fn no_vault(&mut self) {
        let now = Instant::now();
        if self
            .last
            .is_some_and(|t| now.saturating_duration_since(t) < NOTICE_INTERVAL)
        {
            return;
        }
        self.last = Some(now);
        log(format_args!("{NO_VAULT}"));
        if self.desktop {
            notify_desktop("hirz: no passkey vault on this device yet. Run \"hirz init\" first.");
        }
    }
}

/// Best effort; zenity comes from a root-owned system directory like every hirz prompt.
fn notify_desktop(text: &str) {
    let Some(zenity) = hirz_uv::runner::resolve_tool("zenity") else {
        return;
    };
    let child = std::process::Command::new(zenity)
        .args(["--notification".to_owned(), format!("--text={text}")])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    if let Ok(mut child) = child {
        let _ = std::thread::Builder::new()
            .name("notice".into())
            .spawn(move || child.wait());
    }
}

#[derive(Debug)]
pub struct VaultAuthenticator<A> {
    session: Session<A>,
    notice: Notice,
}

impl<A: Approver> VaultAuthenticator<A> {
    pub fn new(session: Session<A>, notice: Notice) -> Self {
        VaultAuthenticator { session, notice }
    }

    fn prepare(&mut self, ctx: &RequestContext) -> Result<(), CoreError> {
        if ctx.is_cancelled() {
            return Err(CoreError::Approval(ApprovalError::Denied));
        }
        match self.session.ensure_vault() {
            VaultStatus::Ready => Ok(()),
            VaultStatus::Missing => {
                self.notice.no_vault();
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

/// Platforms send a throwaway makeCredential only to wait for a touch: Firefox (authenticator-rs
/// `dummy_make_credentials_cmd`) uses the RP id `make.me.blink`, Chromium `.dummy`. Asks for
/// presence like authenticatorSelection and stores nothing.
fn is_touch_request(req: &MakeCredentialRequest) -> bool {
    req.rp.id == "make.me.blink" || req.rp.id.starts_with('.')
}

/// pam-u2f asks with `pam://HOST`. Refused before the vault is opened or anything is shown;
/// the engine refuses it as well.
fn refuse_machine_login(rp_id: &str) -> Result<(), CoreError> {
    if hirz_core::engine::is_machine_login_rp_id(rp_id) {
        log(format_args!(
            "refused rp id {rp_id:?}: hirz passkeys cannot be a login factor for this computer \
             (pam-u2f); use a hardware security key for that"
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

impl<A: Approver + Send> Authenticator for VaultAuthenticator<A> {
    fn make_credential(
        &mut self,
        req: &MakeCredentialRequest,
        ctx: &RequestContext,
    ) -> Result<MakeCredentialResponse, CoreError> {
        refuse_machine_login(&req.rp.id)?;
        self.prepare(ctx)?;
        if is_touch_request(req) {
            self.select(ctx)?;
            return Err(CoreError::Approval(ApprovalError::Denied));
        }
        logged(
            self.session
                .with_engine(&|| ctx.is_cancelled(), |e| e.make_credential(req, None)),
        )
    }

    fn get_assertion(
        &mut self,
        req: &GetAssertionRequest,
        hmac: Option<&dyn HmacSecretWrap>,
        ctx: &RequestContext,
    ) -> Result<AssertionResponse, CoreError> {
        refuse_machine_login(&req.rp_id)?;
        self.prepare(ctx)?;
        logged(
            self.session
                .with_engine(&|| ctx.is_cancelled(), |e| e.get_assertion(req, None, hmac)),
        )
    }

    fn select(&mut self, ctx: &RequestContext) -> Result<(), CoreError> {
        self.prepare(ctx)?;
        logged(
            self.session
                .with_engine(&|| ctx.is_cancelled(), |e| e.select()),
        )
    }
}
