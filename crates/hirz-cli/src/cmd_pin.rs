//! `hirz pin`: the hirz PIN through hirz-uv's PinStore.

use crate::app::Ctx;
use crate::args::PinAction;
use crate::env::{STATE_DEVICE, VAULT_HEADER};
use crate::error::{CliError, CliResult, Exit, phrase_problem};
use crate::prompt::{self, confirm};
use hirz_uv::pin::{MAX_FAILURES, MAX_PIN_BYTES, MIN_PIN_CODE_POINTS};
use hirz_uv::{PinError, PinStore};
use hirz_vault::{RecoveryPhrase, VaultError};

fn store(ctx: &Ctx<'_>) -> PinStore {
    PinStore::with_params(ctx.env.state_dir(), ctx.kdf)
}

fn pin_error(e: PinError) -> CliError {
    match e {
        PinError::TooShort => CliError::usage(format!(
            "A PIN needs at least {MIN_PIN_CODE_POINTS} characters."
        )),
        PinError::TooLong => {
            CliError::usage(format!("A PIN can be at most {MAX_PIN_BYTES} bytes long."))
        }
        PinError::NotUtf8 => CliError::usage("The PIN is not valid text."),
        PinError::NotSet => CliError::failed("No PIN is set. Set one with: hirz pin set"),
        PinError::AlreadySet => {
            CliError::failed("A PIN is already set. Change it with: hirz pin change")
        }
        PinError::Wrong { remaining } => CliError::denied(format!(
            "Wrong PIN. {remaining} tries left before the PIN is locked."
        )),
        PinError::Locked => CliError::denied(
            "The PIN is locked after too many wrong tries. Remove it with `hirz pin reset`, \
             then set a new one.",
        ),
        PinError::Corrupt => CliError::failed(
            "The PIN file is damaged. Remove it with `hirz pin reset`, then set a new PIN.",
        ),
        PinError::Io(kind) => CliError::failed(format!(
            "Could not access the PIN file: {}.",
            crate::error::describe_io(kind)
        )),
        PinError::Crypto => CliError::failed("The PIN could not be processed."),
    }
}

fn new_pin(ctx: &mut Ctx<'_>) -> CliResult<hirz_crypto::Zeroizing<String>> {
    for _ in 0..3 {
        let first = prompt::read_secret(ctx.prompt, "New PIN: ")?;
        if let Err(e) = hirz_uv::pin::validate_pin(first.as_bytes()) {
            ctx.say(&pin_error(e).message)?;
            continue;
        }
        let second = prompt::read_secret(ctx.prompt, "Type the new PIN again: ")?;
        if hirz_crypto::ct_eq(first.as_bytes(), second.as_bytes()) {
            return Ok(first);
        }
        ctx.say("The two PINs are different. Try again.")?;
    }
    Err(CliError::cancelled("No PIN was set."))
}

pub fn pin(ctx: &mut Ctx<'_>, action: PinAction) -> CliResult<Exit> {
    let pins = store(ctx);
    match action {
        PinAction::Status => {
            match pins.status().map_err(pin_error)? {
                None => ctx.say("No hirz PIN is set. Set one with: hirz pin set")?,
                Some(s) if s.locked => ctx.say(
                    "A hirz PIN is set but locked after too many wrong tries. Remove it with \
                     `hirz pin reset`.",
                )?,
                Some(s) => ctx.say(&format!(
                    "A hirz PIN is set. Wrong tries since the last correct PIN: {} of {MAX_FAILURES}.",
                    s.failures
                ))?,
            }
            Ok(Exit::Ok)
        }
        PinAction::Set => {
            if pins.is_set() {
                return Err(pin_error(PinError::AlreadySet));
            }
            ctx.say(&format!(
                "Choose a PIN of at least {MIN_PIN_CODE_POINTS} characters. hirz asks for it to \
                 approve passkey requests. After {MAX_FAILURES} wrong tries in a row it is locked."
            ))?;
            let p = new_pin(ctx)?;
            pins.set_pin(p.as_bytes()).map_err(pin_error)?;
            ctx.say("PIN set.")?;
            Ok(Exit::Ok)
        }
        PinAction::Change => {
            if !pins.is_set() {
                return Err(pin_error(PinError::NotSet));
            }
            let old = prompt::read_secret(ctx.prompt, "Current PIN: ")?;
            pins.verify(old.as_bytes()).map_err(pin_error)?;
            let p = new_pin(ctx)?;
            pins.change_pin(old.as_bytes(), p.as_bytes())
                .map_err(pin_error)?;
            ctx.say("PIN changed.")?;
            Ok(Exit::Ok)
        }
        PinAction::Reset => {
            if !pins.is_set() {
                ctx.say("No hirz PIN is set, so there is nothing to reset.")?;
                return Ok(Exit::Ok);
            }
            ctx.say(
                "Resetting removes the PIN. Approvals then use your other methods until you set a\n\
                 new PIN with `hirz pin set`.",
            )?;
            if ctx.env.state_dir().join(STATE_DEVICE).exists() {
                prove_owner(ctx)?;
            } else if !confirm(ctx.prompt, "Remove the PIN?")? {
                return Err(CliError::cancelled("Nothing was changed."));
            }
            pins.reset().map_err(pin_error)?;
            ctx.say("The PIN was removed.")?;
            Ok(Exit::Ok)
        }
    }
}

/// Someone who forgot the PIN proves they own the vault with the recovery phrase.
fn prove_owner(ctx: &mut Ctx<'_>) -> CliResult<()> {
    let dir = ctx.vault_dir()?;
    if !dir.join(VAULT_HEADER).exists() {
        return Err(CliError::not_set_up(format!(
            "The vault folder {} is missing, so hirz cannot check your recovery phrase.",
            dir.display()
        )));
    }
    let (vault, _) = ctx.open_vault()?;
    ctx.say("To show that you own this vault, type its 24-word recovery phrase.")?;
    let typed = prompt::read_secret(ctx.prompt, "Recovery phrase: ")?;
    let phrase = match RecoveryPhrase::parse(&typed) {
        Ok(p) => p,
        Err(VaultError::Phrase(p)) => return Err(CliError::denied(phrase_problem(p))),
        Err(e) => return Err(e.into()),
    };
    // export_backup checks the phrase against the vault before doing anything else.
    match vault.export_backup(&phrase, None) {
        Ok(_) => Ok(()),
        Err(VaultError::WrongRecoveryKey) => Err(CliError::denied(
            "That recovery phrase does not belong to this vault. The PIN was not removed.",
        )),
        Err(e) => Err(e.into()),
    }
}
