//! Adding a device without the recovery phrase: `join --request`, `devices approve`,
//! `devices deny`. See docs/sync.md and docs/vault-format.md, section 11.

use crate::app::Ctx;
use crate::cmd_vault::{already_set_up, join_target};
use crate::error::{CliError, CliResult, Exit};
use crate::prompt::{self, confirm_word};
use crate::ui::{self, clean, count, hex};
use hirz_vault::{PairingPoll, PairingRequest, PendingJoin, Vault, VaultError};
use std::path::Path;
use std::time::Duration;

const POLL_EVERY: Duration = Duration::from_secs(2);
/// An approval made just before the request expired may still be on its way.
const SYNC_GRACE_SECS: u64 = 120;
const NAME_CHARS: usize = 64;
const REQUEST_ID_HEX: usize = 12;

fn short(id: &[u8; 16]) -> String {
    let h = hex(id);
    h.get(..REQUEST_ID_HEX).unwrap_or(&h).to_string()
}

fn minutes(secs: u64) -> String {
    count(
        usize::try_from(secs.div_ceil(60)).unwrap_or(usize::MAX),
        "minute",
    )
}

/// Prints the words large enough that they are hard to miss.
fn show_words(ctx: &mut Ctx<'_>, words: &str) -> CliResult {
    let spaced: Vec<String> = words.split(' ').map(str::to_uppercase).collect();
    ctx.say("")?;
    ctx.say(&format!("        {}", spaced.join("   ")))?;
    ctx.say("")
}

pub fn join_request(ctx: &mut Ctx<'_>, name: Option<String>) -> CliResult<Exit> {
    let (dir, name) = join_target(ctx, name)?;
    let state = ctx.env.state_dir().to_path_buf();
    let pending = match PendingJoin::start(&dir, &state, &name) {
        Ok(p) => p,
        Err(VaultError::AlreadyExists) => return Err(already_set_up(ctx)),
        Err(VaultError::NotFound) => {
            return Err(CliError::not_set_up(format!(
                "The vault in {} is not completely copied yet. Wait until your sync tool has \
                 finished, then try again.",
                dir.display()
            )));
        }
        Err(VaultError::Corrupt(_)) => {
            return Err(CliError::failed(format!(
                "The folder {} holds more than one vault start, so hirz cannot tell which one \
                 is yours. Someone with access to the synced folder may have tampered with it. \
                 Join with the recovery phrase instead: hirz join --vault DIR",
                dir.display()
            )));
        }
        Err(e) => return Err(e.into()),
    };
    let req = pending.request().clone();
    ctx.say(&format!(
        "This computer (\"{}\") is asking to join the vault in {}.\n\nVerification words:",
        clean(&name, NAME_CHARS),
        dir.display()
    ))?;
    show_words(ctx, pending.words())?;
    ctx.say(
        "On a device that already has hirz, run: hirz devices approve\n\
         It shows four words. Approve there only if they are exactly the words above.",
    )?;
    ctx.say(&format!(
        "Waiting for approval (the request expires in {}; press Ctrl-C to stop) ...",
        minutes(req.expires_at.saturating_sub(req.created_at))
    ))?;
    let deadline = req.expires_at.saturating_add(SYNC_GRACE_SECS);
    let mut warned = false;
    loop {
        match pending.poll(&state) {
            Ok(PairingPoll::Joined(vault)) => return finish(ctx, &dir, &name, &vault),
            Ok(PairingPoll::Waiting) => {}
            Ok(PairingPoll::Invalid(why)) => {
                if !warned {
                    ctx.say(&format!(
                        "Warning: an approval appeared that does not open this vault ({why}).\n\
                         It may still be being copied. If this warning was not expected, someone \
                         with access to the\nsynced folder may be tampering with it. Still \
                         waiting for a valid approval."
                    ))?;
                    warned = true;
                }
            }
            Err(VaultError::AlreadyExists) => return Err(already_set_up(ctx)),
            Err(e) => {
                let _ = pending.cancel();
                return Err(e.into());
            }
        }
        if ctx.sys.now() > deadline {
            let _ = pending.cancel();
            return Err(CliError::failed(format!(
                "No approval arrived in time. Nothing was changed on this computer.\n\
                 Run the command again for new words, or join with the recovery phrase:\n  \
                 {} join --vault {}",
                ctx.program,
                dir.display()
            )));
        }
        ctx.sys.sleep(POLL_EVERY);
    }
}

fn finish(ctx: &mut Ctx<'_>, dir: &Path, name: &str, vault: &Vault) -> CliResult<Exit> {
    ctx.env.record_vault_dir(dir)?;
    let mut others: Vec<String> = vault
        .devices()
        .into_iter()
        .filter(|d| !d.removed && !d.this_device)
        .map(|d| format!("\"{}\"", clean(&d.name, NAME_CHARS)))
        .collect();
    others.sort();
    ctx.say(&format!(
        "Approved. This computer (\"{}\") now uses the vault in {}.\n\
         You have {} here. Other devices of this vault: {}.",
        clean(name, NAME_CHARS),
        dir.display(),
        count(vault.list_all().len(), "passkey"),
        others.join(", ")
    ))?;
    ctx.say(&format!(
        "Passkeys you add on any device appear on the others once your sync tool has copied\n\
         the files. Connect Firefox with: {} setup firefox",
        ctx.program
    ))?;
    Ok(Exit::Ok)
}

fn request_rows(ctx: &Ctx<'_>, reqs: &[PairingRequest]) -> Vec<Vec<String>> {
    let now = ctx.sys.now();
    reqs.iter()
        .enumerate()
        .map(|(i, r)| {
            vec![
                i.saturating_add(1).to_string(),
                clean(&r.name, NAME_CHARS),
                format!("{} ago", minutes(now.saturating_sub(r.created_at))),
                short(&r.request_id),
            ]
        })
        .collect()
}

fn no_requests() -> CliError {
    CliError::failed(
        "No device is waiting for approval. On the new device, run:\n  \
         hirz join --vault DIR --request\n\
         A request lasts 15 minutes, and your sync tool must have copied it to this computer.",
    )
}

fn by_prefix(reqs: Vec<PairingRequest>, prefix: &str) -> CliResult<Vec<PairingRequest>> {
    let Some(p) = ui::hex_prefix(prefix) else {
        return Err(CliError::usage(
            "Give at least 4 characters of the request id shown by `hirz devices approve`.",
        ));
    };
    Ok(reqs
        .into_iter()
        .filter(|r| hex(&r.request_id).starts_with(&p))
        .collect())
}

fn choose(
    ctx: &mut Ctx<'_>,
    reqs: Vec<PairingRequest>,
    prefix: Option<&str>,
) -> CliResult<PairingRequest> {
    let reqs = match prefix {
        Some(p) => by_prefix(reqs, p)?,
        None => reqs,
    };
    let header = ["#", "NAME", "ASKED", "REQUEST"];
    match reqs.as_slice() {
        [] => Err(CliError::failed(
            "No waiting device matches. Run `hirz devices approve` to see them.",
        )),
        [one] => Ok(one.clone()),
        several => {
            ctx.write_raw(&ui::table(&header, &request_rows(ctx, several)))?;
            ctx.say(
                "Several devices are waiting. If you started only one, the others may have been\n\
                 planted by someone with access to your synced folder: deny them with\n\
                 `hirz devices deny REQUEST`.",
            )?;
            let answer = prompt::read_line(ctx.prompt, "Which one do you want to check? Number: ")?;
            answer
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| several.get(i))
                .cloned()
                .ok_or_else(|| CliError::usage("That is not one of the numbers in the list."))
        }
    }
}

pub fn approve(ctx: &mut Ctx<'_>, prefix: Option<String>) -> CliResult<Exit> {
    let (mut vault, _) = ctx.open_vault()?;
    let reqs = vault.pairing_requests()?;
    if reqs.is_empty() {
        return Err(no_requests());
    }
    let req = choose(ctx, reqs, prefix.as_deref())?;
    let name = clean(&req.name, NAME_CHARS);
    let now = ctx.sys.now();
    ctx.say(&format!(
        "A new device called \"{name}\" asked to join this vault {} ago (request {}).\n\
         Approving gives it every passkey in the vault.\n\n\
         Compare the words below with the words on the new device's screen:",
        minutes(now.saturating_sub(req.created_at)),
        short(&req.request_id)
    ))?;
    show_words(ctx, &vault.pairing_words(&req)?)?;
    ctx.say(
        "Answer yes only if all four words are exactly the same AND you started `hirz join`\n\
         on that device yourself in the last 15 minutes. If anything differs, someone with\n\
         access to your synced folder may be trying to get your passkeys: answer no.",
    )?;
    if !confirm_word(ctx.prompt, "Do all four words match?", "yes")? {
        let _ = vault.deny_pairing(&req.request_id);
        return Err(CliError::cancelled(
            "Not approved. hirz removed the request. If you started `hirz join --request` on a\n\
             new device yourself, start it again there for new words.",
        ));
    }
    match vault.approve_pairing(&req) {
        Ok(()) => {}
        Err(VaultError::NotFound) => {
            return Err(CliError::failed(
                "The request expired or was removed before you approved it. Nothing was \
                 approved. Start `hirz join --request` on the new device again.",
            ));
        }
        Err(VaultError::Corrupt(_)) => {
            return Err(CliError::failed(
                "The request changed while you were checking it, so nothing was approved. \
                 Someone with access to your synced folder may be tampering with it.",
            ));
        }
        Err(VaultError::AlreadyExists) => {
            return Err(CliError::failed(
                "That device already belongs to this vault. Nothing was approved.",
            ));
        }
        Err(e) => return Err(e.into()),
    }
    ctx.say(&format!(
        "Approved \"{name}\". It finishes joining as soon as your sync tool has copied the\n\
         files to it. If you ever lose it, remove it with `{} remove-device`.",
        ctx.program
    ))?;
    Ok(Exit::Ok)
}

pub fn deny(ctx: &mut Ctx<'_>, prefix: &str) -> CliResult<Exit> {
    let (mut vault, _) = ctx.open_vault()?;
    let reqs = by_prefix(vault.pairing_requests()?, prefix)?;
    let req = match reqs.as_slice() {
        [] => {
            return Err(CliError::failed(
                "No waiting device matches. Run `hirz devices approve` to see them.",
            ));
        }
        [one] => one.clone(),
        several => {
            ctx.write_raw(&ui::table(
                &["#", "NAME", "ASKED", "REQUEST"],
                &request_rows(ctx, several),
            ))?;
            return Err(CliError::usage(
                "Several requests match. Give a longer request id.",
            ));
        }
    };
    vault.deny_pairing(&req.request_id)?;
    ctx.say(&format!(
        "Removed the request from \"{}\". That device cannot join with it.",
        clean(&req.name, NAME_CHARS)
    ))?;
    Ok(Exit::Ok)
}
