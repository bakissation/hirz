//! The CTAP engine adapter: [`hirz_ctap::Authenticator`] over a [`Session`].
//!
//! The approval prompt cannot be interrupted. When the platform cancels, the transport
//! answers CTAP2_ERR_KEEPALIVE_CANCEL at once and drops the late result; the prompt stays
//! open until it is answered or times out, and its approval then counts as refused, so a
//! cancelled request creates and signs nothing.

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

/// Tells the user about a missing vault, at most once per [`NOTICE_INTERVAL`].
#[derive(Debug)]
pub struct Notice {
    desktop: bool,
    last: Option<Instant>,
    removed_told: bool,
}

impl Notice {
    /// `desktop`: also show a desktop notification with zenity.
    pub fn new(desktop: bool) -> Self {
        Notice {
            desktop,
            last: None,
            removed_told: false,
        }
    }

    /// Tells the user once per run that this device was removed from the vault.
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

/// Platforms send a throwaway makeCredential only to wait for a touch, for example when a
/// silent probe found none of the allowed credentials: Firefox (authenticator-rs
/// `dummy_make_credentials_cmd`) uses the RP id `make.me.blink`, Chromium `.dummy`. hirz
/// asks for presence like authenticatorSelection and stores nothing.
fn is_touch_request(req: &MakeCredentialRequest) -> bool {
    req.rp.id == "make.me.blink" || req.rp.id.starts_with('.')
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
