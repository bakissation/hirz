//! `hirz repair`: shows a fork or rotation conflict of the vault folder and, after user
//! verification, ends it by deleting a named foreign key change or by following the folder as it
//! is. See docs/sync.md ("Fork recovery") and docs/vault-format.md, sections 9.3 and 9.4.

use crate::app::{Ctx, removed};
use crate::args::RepairAction;
use crate::cmd_pair::{Change, check_verdict, ensure_uv_possible};
use crate::error::{CliError, CliResult, Exit};
use crate::prompt::{confirm, confirm_word};
use crate::ui::{clean, count};
use hirz_core::RepairApprovalContext;
use hirz_vault::{GenId, Vault};

const MAX_LISTED: usize = 20;
const NAME_CHARS: usize = 64;

pub fn repair(ctx: &mut Ctx<'_>, action: RepairAction, yes: bool) -> CliResult<Exit> {
    let (mut vault, dir) = ctx.open_vault()?;
    let report = vault.report();
    if report.this_device_removed && !(report.fork_detected || report.rotation_conflict) {
        return Err(removed(&ctx.program));
    }
    match action {
        RepairAction::Show => show(ctx, &vault, &dir),
        RepairAction::Discard(name) => discard(ctx, &mut vault, &name, yes),
        RepairAction::AcceptFork => accept_fork(ctx, &mut vault, yes),
    }
}

/// "made by NAME" when the id is a device of this vault. The id is just a directory name that
/// whoever wrote the folder chose, so an unknown one says so.
fn maker(vault: &Vault, id: &GenId) -> String {
    match vault.devices().into_iter().find(|d| d.id == id.rotator) {
        Some(d) => format!(
            "made by \"{}\"{}",
            clean(&d.name, NAME_CHARS),
            if d.removed { " (removed)" } else { "" }
        ),
        None => "made by a device this vault does not know".to_string(),
    }
}

fn list_rejected(ctx: &mut Ctx<'_>, vault: &Vault) -> CliResult {
    let rejected = &vault.report().rejected;
    ctx.say(&format!(
        "Key changes this computer does not follow ({}):",
        rejected.len()
    ))?;
    for id in rejected.iter().take(MAX_LISTED) {
        ctx.say(&format!("  {}  {}", id.dir_name(), maker(vault, id)))?;
    }
    if rejected.len() > MAX_LISTED {
        ctx.say(&format!(
            "  and {} more",
            rejected.len().saturating_sub(MAX_LISTED)
        ))?;
    }
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, vault: &Vault, dir: &std::path::Path) -> CliResult<Exit> {
    let r = vault.report();
    ctx.say(&format!("Vault folder: {}", dir.display()))?;
    ctx.say(&format!(
        "Key generation this computer follows: {}",
        r.generation
    ))?;
    if r.fork_detected {
        ctx.say(&format!(
            "\nFork: the vault folder no longer holds the key changes this computer followed\n\
             before. Someone with access to the folder deleted or rewrote them, or your sync\n\
             tool restored an older copy. Passkeys still work, but nothing new is saved.\n\
             1. Restore the folder from your sync tool's history if you can.\n\
             2. Stop sharing the folder with every device you do not trust.\n\
             3. Only if the folder cannot be restored, and you trust it as it is now:\n   \
                {} repair --accept-fork",
            ctx.program
        ))?;
    }
    if r.rotation_conflict {
        ctx.say(&format!(
            "\nConflict: two devices removed each other, and nothing settles which one to\n\
             trust. Passkeys still work, but nothing new is saved. Stop sharing the folder\n\
             with the device you do not trust, then run `{p} remove-device` for it again on a\n\
             device you trust, or delete the key change it made with\n  {p} repair --discard NAME",
            p = ctx.program
        ))?;
    }
    if r.locked_out {
        ctx.say(
            "\nA newer key change exists that this computer holds no key for. It may still be on\n\
             its way through your sync tool, or this computer was removed; `hirz status` says more.",
        )?;
    }
    if !r.rejected.is_empty() {
        ctx.say("")?;
        list_rejected(ctx, vault)?;
        if r.fork_detected || r.rotation_conflict {
            ctx.say(&format!(
                "To delete one of them and everything built on it: {} repair --discard NAME",
                ctx.program
            ))?;
        } else {
            ctx.say(
                "They do not stop anything here. Deleting one is optional clean-up\n\
                 (`hirz repair --discard NAME`).",
            )?;
        }
    }
    if !(r.fork_detected || r.rotation_conflict || r.locked_out || !r.rejected.is_empty()) {
        ctx.say("\nNothing to repair: the vault folder reports no fork and no conflict.")?;
    }
    Ok(Exit::Ok)
}

fn settled(ctx: &mut Ctx<'_>, vault: &Vault) -> CliResult {
    let r = vault.report();
    if r.fork_detected {
        ctx.say("hirz still reports a fork. Run `hirz repair` to see what is left.")?;
    } else if r.rotation_conflict {
        ctx.say("hirz still reports a rotation conflict. Run `hirz repair` to see what is left.")?;
    } else {
        ctx.say("hirz reports no fork and no conflict now. Nothing else needs doing.")?;
    }
    Ok(())
}

fn discard(ctx: &mut Ctx<'_>, vault: &mut Vault, name: &str, yes: bool) -> CliResult<Exit> {
    let Some(id) = GenId::parse_dir(name) else {
        return Err(CliError::usage(
            "Give the folder name of a key change as `hirz repair` lists it: 10 digits, a dash \
             and 32 hex digits.",
        ));
    };
    if !vault.report().rejected.contains(&id) {
        return Err(CliError::failed(
            "That is not one of the key changes this computer does not follow, so hirz will not \
             delete it. Run `hirz repair` to list them.",
        ));
    }
    let folder = id.dir_name();
    let change = Change {
        action: "Deleting a key change",
        retry: format!("{} repair --discard {folder}", ctx.program),
        unchanged: "Nothing was deleted.".to_string(),
    };
    ensure_uv_possible(ctx, &change)?;
    ctx.say(&format!(
        "Deleting the key change {folder} ({}):\n\
         - hirz deletes its folder and every key change built on it from the vault folder, on\n  \
           every device once your sync tool copies the deletion.\n\
         - Passkeys and the key changes this computer follows are not touched.\n\
         - Do this for a key change that a device you do not trust made. Stop sharing the vault\n  \
           folder with that device too, or it can write another one.",
        maker(vault, &id)
    ))?;
    if !yes && !confirm(ctx.prompt, "Delete this key change now?")? {
        return Err(CliError::cancelled("Nothing was changed."));
    }
    ctx.say(
        "Confirm in the hirz window: it shows the key change, then asks for your system password,\n\
         your fingerprint or your hirz PIN.",
    )?;
    let approval = RepairApprovalContext::DiscardGeneration {
        generation: &folder,
    };
    let sys = ctx.sys;
    let verdict = sys.pairing_approver(ctx.env).confirm_repair(&approval);
    check_verdict(ctx, verdict, &change)?;
    if vault.discard_generation(&id)? {
        ctx.say(&format!("Deleted the key change {folder}."))?;
    } else {
        ctx.say("That key change was already gone.")?;
    }
    settled(ctx, vault)?;
    Ok(Exit::Ok)
}

fn accept_fork(ctx: &mut Ctx<'_>, vault: &mut Vault, yes: bool) -> CliResult<Exit> {
    if !vault.report().fork_detected {
        return Err(CliError::failed(
            "hirz does not report a fork, so there is nothing to accept. Run `hirz repair` to \
             see the state of the vault folder.",
        ));
    }
    let change = Change {
        action: "Following the vault folder as it is",
        retry: format!("{} repair --accept-fork", ctx.program),
        unchanged: "Nothing was changed.".to_string(),
    };
    ensure_uv_possible(ctx, &change)?;
    ctx.say(
        "The vault folder no longer holds the key changes this computer followed. If you\n\
         follow it as it is now, hirz goes on from the newest of them that is still there, as\n\
         the folder holds it now.\n\
         - Every device that this computer saw removed stays removed: key changes made through\n  \
           one are ignored, and if one could still read the vault key hirz goes on from, hirz\n  \
           changes the vault key again before it saves anything.\n\
         - Restoring the folder from your sync tool's history ends the fork without this.\n\
         - A device you do not trust that can still write to the folder can change it again,\n  \
           or take back passkeys you delete. Stop sharing the folder with it first.",
    )?;
    if !yes
        && !confirm_word(
            ctx.prompt,
            "Follow the vault folder as it is now?",
            "follow",
        )?
    {
        return Err(CliError::cancelled("Nothing was changed."));
    }
    ctx.say(
        "Confirm in the hirz window: it asks for your system password, your fingerprint or\n\
         your hirz PIN.",
    )?;
    let sys = ctx.sys;
    let verdict = sys
        .pairing_approver(ctx.env)
        .confirm_repair(&RepairApprovalContext::AcceptFork);
    check_verdict(ctx, verdict, &change)?;
    vault.accept_fork()?;
    ctx.say(&format!(
        "Done. This computer follows the vault folder as it is now; it has {} here.",
        count(vault.list_all().len(), "passkey")
    ))?;
    settled(ctx, vault)?;
    Ok(Exit::Ok)
}
