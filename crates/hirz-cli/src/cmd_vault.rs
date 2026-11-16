//! Vault commands: init, join, list, delete, devices, remove-device, backup confirm.

use crate::app::Ctx;
use crate::args::DeleteTarget;
use crate::error::{CliError, CliResult, Exit, phrase_problem};
use crate::prompt::{self, confirm};
use crate::ui::{self, clean, count, hex};
use hirz_vault::{CredentialRecord, DeviceInfo, RecoveryPhrase, Vault, VaultError};
use serde_json::{Value, json};
use std::path::Path;

const PHRASE_WORDS: usize = 24;
const QUIZ_WORDS: usize = 3;
const QUIZ_ROUNDS: usize = 3;
const PHRASE_ATTEMPTS: usize = 3;
const MAX_NAME_CHARS: usize = 64;
const ID_PREFIX_HEX: usize = 12;
/// Clears the screen and the scrollback, so the recovery phrase does not stay on screen.
const CLEAR_SCREEN: &str = "\x1b[2J\x1b[3J\x1b[H";

fn device_name(ctx: &Ctx<'_>, given: Option<String>) -> CliResult<String> {
    let name = match given {
        Some(n) => n.trim().to_string(),
        None => ctx
            .sys
            .hostname()
            .map(|h| clean(&h, MAX_NAME_CHARS))
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "my computer".to_string()),
    };
    if name.is_empty() || clean(&name, MAX_NAME_CHARS) != name {
        return Err(CliError::usage(format!(
            "A device name has 1 to {MAX_NAME_CHARS} characters and no control characters."
        )));
    }
    Ok(name)
}

fn dir_is_empty(dir: &Path) -> CliResult<bool> {
    match std::fs::read_dir(dir) {
        Ok(mut rd) => Ok(rd.next().is_none()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(CliError::io(
            &format!("Could not read {}", dir.display()),
            &e,
        )),
    }
}

pub(crate) fn already_set_up(ctx: &Ctx<'_>) -> CliError {
    let where_ = ctx
        .env
        .vault_dir(None)
        .map(|d| format!(" (vault: {})", d.display()))
        .unwrap_or_default();
    CliError::failed(format!(
        "This computer is already set up with a vault{where_}. hirz uses one vault per user; \
         see `hirz status`."
    ))
}

fn show_phrase(ctx: &mut Ctx<'_>, words: &[&str]) -> CliResult {
    ctx.say("")?;
    for (row, chunk) in words.chunks(4).enumerate() {
        let mut line = String::from(" ");
        for (col, w) in chunk.iter().enumerate() {
            let n = row.saturating_mul(4).saturating_add(col).saturating_add(1);
            line.push_str(&format!(" {n:>2}. {w:<10}"));
        }
        ctx.say(line.trim_end())?;
    }
    ctx.say("")?;
    ctx.say("Do not copy, paste or screenshot this screen.")?;
    ctx.say("")
}

fn random_positions() -> CliResult<Vec<usize>> {
    let mut picked: Vec<usize> = Vec::with_capacity(QUIZ_WORDS);
    let mut guard = 0u32;
    while picked.len() < QUIZ_WORDS {
        guard = guard.saturating_add(1);
        if guard > 10_000 {
            return Err(CliError::failed("Could not pick random words."));
        }
        let mut b = [0u8; 1];
        hirz_crypto::random_fill(&mut b)
            .map_err(|_| CliError::failed("The system random generator failed."))?;
        let [v] = b;
        // 240 = 10 * 24, so the reduction is unbiased.
        if v >= 240 {
            continue;
        }
        let pos = usize::from(v % 24);
        if !picked.contains(&pos) {
            picked.push(pos);
        }
    }
    picked.sort_unstable();
    Ok(picked)
}

fn word_matches(typed: &str, word: &str) -> bool {
    let t = typed.trim().to_lowercase();
    t == word || (t.chars().count() >= 4 && word.starts_with(&t))
}

/// Asks for a few words of the phrase. Returns false when the user gave up.
fn quiz(ctx: &mut Ctx<'_>, words: &[&str]) -> CliResult<bool> {
    for round in 0..QUIZ_ROUNDS {
        if round > 0 {
            ctx.say("Here is the phrase again. Check what you wrote down.")?;
            show_phrase(ctx, words)?;
        }
        if prompt::read_line(
            ctx.prompt,
            "Press Enter when you have written down all 24 words.",
        )
        .is_err()
        {
            return Ok(false);
        }
        ctx.say("To check, type the words hirz asks for.")?;
        let mut all_ok = true;
        for pos in random_positions()? {
            let Some(word) = words.get(pos) else {
                return Err(CliError::failed("Internal error: word position."));
            };
            let typed = match ctx
                .prompt
                .secret(&format!("Word {}: ", pos.saturating_add(1)))
            {
                Ok(Some(t)) => t,
                Ok(None) => return Ok(false),
                Err(e) => return Err(CliError::io("Could not read your answer", &e)),
            };
            if !word_matches(&typed, word) {
                ctx.say(&format!("That is not word {}.", pos.saturating_add(1)))?;
                all_ok = false;
                break;
            }
        }
        if all_ok {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn init(ctx: &mut Ctx<'_>, name: Option<String>, saved: bool) -> CliResult<Exit> {
    let dir = match ctx.vault_flag.clone() {
        Some(p) => ctx.env.absolute(&p)?,
        None => ctx.env.default_vault(),
    };
    if ctx.env.device_state_exists() {
        return Err(already_set_up(ctx));
    }
    if Vault::exists(&dir) {
        return Err(CliError::failed(format!(
            "There is already a vault in {d}. To use it on this computer, run:\n  hirz join --vault {d}",
            d = dir.display()
        )));
    }
    if dir.exists() && !dir.is_dir() {
        return Err(CliError::failed(format!(
            "{} is a file, not a folder.",
            dir.display()
        )));
    }
    if !dir_is_empty(&dir)? {
        return Err(CliError::failed(format!(
            "The folder {d} is not empty. Choose an empty or new folder, for example {d}/hirz.",
            d = dir.display()
        )));
    }
    let name = device_name(ctx, name)?;
    let (vault, phrase) = match Vault::create(&dir, ctx.env.state_dir(), &name) {
        Ok(v) => v,
        Err(VaultError::AlreadyExists) => return Err(already_set_up(ctx)),
        Err(e) => return Err(e.into()),
    };
    ctx.env.record_vault_dir(&dir)?;
    drop(vault);

    let phrase_text = phrase.to_words();
    let words: Vec<&str> = phrase_text.split(' ').collect();
    if words.len() != PHRASE_WORDS {
        return Err(CliError::failed("Internal error: recovery phrase length."));
    }
    ctx.say(&format!(
        "Your new vault is ready in {}.\nThis computer is called \"{name}\".",
        dir.display()
    ))?;
    ctx.say("")?;
    ctx.say("YOUR RECOVERY PHRASE (shown only this once):")?;
    show_phrase(ctx, &words)?;
    ctx.say(
        "Write these 24 words on paper, in this order, and keep the paper somewhere safe.\n\
         - If you lose every device that uses this vault, this phrase and a copy of the vault\n  \
           folder are the only way to get your passkeys back.\n\
         - You also need it to add another computer.\n\
         - Anyone with the phrase and a copy of the folder can use your passkeys. Do not keep\n  \
           it in a photo, an email or a chat.\n\
         - hirz does not keep a copy and cannot show it again.",
    )?;
    ctx.say("")?;
    if saved {
        ctx.say("(--yes-i-saved-it was given, so hirz does not check the phrase.)")?;
    } else if !quiz(ctx, &words)? {
        return Err(CliError::cancelled(format!(
            "The recovery phrase was not confirmed. The vault was still created and works.\n\
             If you did not save the phrase and have no passkeys in it yet, start over: delete\n\
             the folder {} and the files in {}, then run `hirz init` again.",
            dir.display(),
            ctx.env.state_dir().display()
        )));
    } else {
        if ctx.out_is_terminal {
            ctx.write_raw(CLEAR_SCREEN)?;
            ctx.say(&format!("Your vault is in {}.", dir.display()))?;
        }
        ctx.say("Correct. Keep the paper safe.")?;
    }
    ctx.say("")?;
    ctx.say(&format!(
        "Next steps:\n\
         - Connect Firefox: {p} setup firefox\n\
         - To use your passkeys on another computer, sync this vault folder to it (see\n  \
           docs/sync.md), run `hirz join --vault DIR --request` there and approve it here\n  \
           with `{p} devices approve`.\n\
         - Check everything with: {p} status",
        p = ctx.program
    ))?;
    Ok(Exit::Ok)
}

/// The vault folder and device name for `join`, after the checks both join modes share.
pub(crate) fn join_target(
    ctx: &Ctx<'_>,
    name: Option<String>,
) -> CliResult<(std::path::PathBuf, String)> {
    let flag = ctx
        .vault_flag
        .clone()
        .ok_or_else(|| CliError::usage("hirz join needs --vault DIR"))?;
    let dir = ctx.env.absolute(&flag)?;
    if ctx.env.device_state_exists() {
        return Err(already_set_up(ctx));
    }
    if !Vault::exists(&dir) {
        return Err(CliError::not_set_up(format!(
            "No vault found in {} yet. If your sync tool is still copying the folder, wait \
             until it has finished, then try again.",
            dir.display()
        )));
    }
    let name = device_name(ctx, name)?;
    Ok((dir, name))
}

pub fn join(ctx: &mut Ctx<'_>, name: Option<String>, request: bool) -> CliResult<Exit> {
    if request {
        return crate::cmd_pair::join_request(ctx, name);
    }
    let (dir, name) = join_target(ctx, name)?;
    ctx.say(
        "Type the 24-word recovery phrase of this vault. Put spaces between the words; the\n\
         first four letters of each word are enough.",
    )?;
    let mut phrase = None;
    for attempt in 0..PHRASE_ATTEMPTS {
        let typed = prompt::read_secret(ctx.prompt, "Recovery phrase: ")?;
        match RecoveryPhrase::parse(&typed) {
            Ok(p) => {
                phrase = Some(p);
                break;
            }
            Err(VaultError::Phrase(p)) => {
                ctx.say(&phrase_problem(p))?;
                if attempt.saturating_add(1) < PHRASE_ATTEMPTS {
                    ctx.say("Try again.")?;
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    let Some(phrase) = phrase else {
        return Err(CliError::denied(
            "The recovery phrase was not accepted. Nothing was changed.",
        ));
    };
    let vault = match Vault::join_with_recovery(&dir, ctx.env.state_dir(), &phrase, &name) {
        Ok(v) => v,
        Err(VaultError::WrongRecoveryKey) => {
            return Err(CliError::denied(format!(
                "This recovery phrase does not open the vault in {}. Check the words. If you\n\
                 just started syncing, wait until the whole folder has been copied, then try again.",
                dir.display()
            )));
        }
        Err(VaultError::AlreadyExists) => return Err(already_set_up(ctx)),
        Err(e) => return Err(e.into()),
    };
    ctx.env.record_vault_dir(&dir)?;
    let n = vault.list_all().len();
    ctx.say(&format!(
        "Done. This computer (\"{name}\") now uses the vault in {}.\nYou have {} here.",
        dir.display(),
        count(n, "passkey")
    ))?;
    ctx.say(&format!(
        "Passkeys you add on any device appear on the others once your sync tool has copied\n\
         the files. Connect Firefox with: {} setup firefox",
        ctx.program
    ))?;
    Ok(Exit::Ok)
}

fn account_of(r: &CredentialRecord) -> Option<&str> {
    r.user_name
        .as_deref()
        .or(r.user_display_name.as_deref())
        .filter(|s| !s.is_empty())
}

fn sorted(mut v: Vec<&CredentialRecord>) -> Vec<&CredentialRecord> {
    v.sort_by(|a, b| {
        (
            a.rp_id.as_str(),
            account_of(a),
            a.created_at,
            a.credential_id.as_slice(),
        )
            .cmp(&(
                b.rp_id.as_str(),
                account_of(b),
                b.created_at,
                b.credential_id.as_slice(),
            ))
    });
    v
}

fn short_id(id: &[u8]) -> String {
    let h = hex(id);
    h.get(..ID_PREFIX_HEX).unwrap_or(&h).to_string()
}

fn algorithm_name(alg: i64) -> &'static str {
    match alg {
        hirz_core::COSE_ALG_ES256 => "ES256",
        hirz_core::COSE_ALG_EDDSA => "EdDSA",
        _ => "other",
    }
}

fn passkey_rows(records: &[&CredentialRecord]) -> Vec<Vec<String>> {
    records
        .iter()
        .map(|r| {
            vec![
                clean(&r.rp_id, 40),
                account_of(r).map_or_else(|| "(no name)".to_string(), |a| clean(a, 40)),
                ui::date(r.created_at),
                short_id(&r.credential_id),
            ]
        })
        .collect()
}

pub fn list(ctx: &mut Ctx<'_>, site: Option<String>, json_out: bool) -> CliResult<Exit> {
    let (vault, _) = ctx.open_vault()?;
    let site = site.map(|s| s.trim().to_ascii_lowercase());
    let records = sorted(
        vault
            .list_all()
            .into_iter()
            .filter(|r| site.as_deref().is_none_or(|s| r.rp_id == s))
            .collect(),
    );
    if json_out {
        let items: Vec<Value> = records
            .iter()
            .map(|r| {
                json!({
                    "site": r.rp_id,
                    "site_name": r.rp_name,
                    "user_name": r.user_name,
                    "user_display_name": r.user_display_name,
                    "created_at": r.created_at,
                    "credential_id": hirz_proto::base64url::encode(&r.credential_id),
                    "credential_id_hex": hex(&r.credential_id),
                    "algorithm": algorithm_name(r.algorithm),
                    "discoverable": r.discoverable,
                    "prf": r.hmac_secret.is_some(),
                })
            })
            .collect();
        let text = serde_json::to_string_pretty(&Value::Array(items))
            .map_err(|e| CliError::failed(e.to_string()))?;
        ctx.say(&text)?;
        return Ok(Exit::Ok);
    }
    if records.is_empty() {
        ctx.say(match site {
            Some(_) => "No passkeys for that site.",
            None => "No passkeys yet. Passkeys appear here after you create one on a website.",
        })?;
        return Ok(Exit::Ok);
    }
    let table = ui::table(
        &["SITE", "ACCOUNT", "CREATED", "ID"],
        &passkey_rows(&records),
    );
    ctx.write_raw(&table)?;
    ctx.say(&count(records.len(), "passkey"))?;
    Ok(Exit::Ok)
}

pub fn delete(ctx: &mut Ctx<'_>, target: DeleteTarget, yes: bool) -> CliResult<Exit> {
    let (mut vault, _) = ctx.open_vault()?;
    let matches: Vec<&CredentialRecord> = match &target {
        DeleteTarget::IdPrefix(p) => {
            let Some(prefix) = ui::hex_prefix(p) else {
                return Err(CliError::usage(
                    "Give at least 4 characters of the id shown by `hirz list`, or a site and an \
                     account: hirz delete SITE ACCOUNT",
                ));
            };
            let found: Vec<&CredentialRecord> = vault
                .list_all()
                .into_iter()
                .filter(|r| hex(&r.credential_id).starts_with(&prefix))
                .collect();
            // Imported ids vary in length, so a whole id can be the prefix of another.
            match found.iter().find(|r| hex(&r.credential_id) == prefix) {
                Some(exact) => vec![*exact],
                None => found,
            }
        }
        DeleteTarget::Account { site, account } => {
            let site = site.trim().to_ascii_lowercase();
            vault
                .list_all()
                .into_iter()
                .filter(|r| {
                    r.rp_id == site
                        && (r.user_name.as_deref() == Some(account.as_str())
                            || r.user_display_name.as_deref() == Some(account.as_str()))
                })
                .collect()
        }
    };
    let matches = sorted(matches);
    let chosen = match matches.as_slice() {
        [] => {
            return Err(CliError::failed(
                "No passkey matches. Run `hirz list` to see your passkeys.",
            ));
        }
        [one] => (*one).clone(),
        several => {
            let table = ui::table(
                &["SITE", "ACCOUNT", "CREATED", "ID"],
                &passkey_rows(several),
            );
            ctx.write_raw(&table)?;
            return Err(CliError::usage(format!(
                "{} match. Give a longer id prefix from the list above.",
                count(several.len(), "passkey")
            )));
        }
    };
    ctx.say(&format!(
        "Passkey: {}, created {}, id {}",
        crate::cxf::label(&chosen.rp_id, account_of(&chosen)),
        ui::date(chosen.created_at),
        short_id(&chosen.credential_id)
    ))?;
    ctx.say(
        "Deleting removes it from hirz on all your devices. The site keeps it in your account\n\
         settings: delete it there too, and make sure you have another way to sign in.",
    )?;
    if !yes && !confirm(ctx.prompt, "Delete this passkey?")? {
        return Err(CliError::cancelled("Nothing was deleted."));
    }
    if !vault.delete(&chosen.credential_id)? {
        return Err(CliError::failed("The passkey was already gone."));
    }
    ctx.say("Deleted.")?;
    Ok(Exit::Ok)
}

fn device_rows(devs: &[DeviceInfo]) -> Vec<Vec<String>> {
    devs.iter()
        .map(|d| {
            vec![
                clean(&d.name, MAX_NAME_CHARS),
                short_id(&d.id),
                ui::date(d.added_at),
                if d.removed {
                    "removed".to_string()
                } else if d.this_device {
                    "this computer".to_string()
                } else {
                    "active".to_string()
                },
            ]
        })
        .collect()
}

fn sorted_devices(vault: &Vault) -> Vec<DeviceInfo> {
    let mut devs = vault.devices();
    devs.sort_by_key(|d| (d.removed, d.added_at, d.id));
    devs
}

pub fn devices(ctx: &mut Ctx<'_>, json_out: bool) -> CliResult<Exit> {
    let (mut vault, _) = ctx.open_vault()?;
    let devs = sorted_devices(&vault);
    if json_out {
        let items: Vec<Value> = devs
            .iter()
            .map(|d| {
                json!({
                    "id": hex(&d.id),
                    "name": d.name,
                    "added_at": d.added_at,
                    "removed": d.removed,
                    "this_device": d.this_device,
                })
            })
            .collect();
        let text = serde_json::to_string_pretty(&Value::Array(items))
            .map_err(|e| CliError::failed(e.to_string()))?;
        ctx.say(&text)?;
        return Ok(Exit::Ok);
    }
    let table = ui::table(&["NAME", "ID", "ADDED", "STATUS"], &device_rows(&devs));
    ctx.write_raw(&table)?;
    let active = devs.iter().filter(|d| !d.removed).count();
    ctx.say(&format!("{} in use.", count(active, "device")))?;
    let waiting = vault.pairing_requests().map(|r| r.len()).unwrap_or(0);
    if waiting > 0 {
        ctx.say(&format!(
            "{} waiting for approval: run `{} devices approve`.",
            count(waiting, "device"),
            ctx.program
        ))?;
    } else if active == 1 {
        ctx.say(&format!(
            "Add another computer: run `hirz join --vault DIR --request` there, then\n\
             `{} devices approve` here (see docs/sync.md).",
            ctx.program
        ))?;
    }
    Ok(Exit::Ok)
}

/// Distinct sites with the number of passkeys for each, sorted by site.
pub fn sites(records: &[&CredentialRecord]) -> Vec<(String, usize)> {
    let mut map: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for r in records {
        let e = map.entry(r.rp_id.as_str()).or_insert(0);
        *e = e.saturating_add(1);
    }
    map.into_iter().map(|(s, n)| (s.to_string(), n)).collect()
}

pub fn remove_device(ctx: &mut Ctx<'_>, prefix: &str, yes: bool) -> CliResult<Exit> {
    let (mut vault, _) = ctx.open_vault()?;
    let Some(prefix) = ui::hex_prefix(prefix) else {
        return Err(CliError::usage(
            "Give at least 4 characters of the device id shown by `hirz devices`.",
        ));
    };
    let candidates: Vec<DeviceInfo> = sorted_devices(&vault)
        .into_iter()
        .filter(|d| !d.removed && hex(&d.id).starts_with(&prefix))
        .collect();
    let device = match candidates.as_slice() {
        [] => {
            return Err(CliError::failed(
                "No device in use matches. Run `hirz devices` to see the ids.",
            ));
        }
        [one] => one.clone(),
        several => {
            ctx.write_raw(&ui::table(
                &["NAME", "ID", "ADDED", "STATUS"],
                &device_rows(several),
            ))?;
            return Err(CliError::usage(
                "Several devices match. Give a longer id prefix.",
            ));
        }
    };
    if device.this_device {
        return Err(CliError::failed(
            "That is this computer. Remove it from another device that uses the vault.",
        ));
    }
    let name = clean(&device.name, MAX_NAME_CHARS);
    let exposed = sites(&vault.list_all());
    ctx.say(&format!(
        "Removing \"{name}\" (id {}):\n\
         - It will no longer be able to read passkeys that are added or changed from now on:\n  \
           hirz changes the vault key and does not give the new key to it.\n\
         - It keeps whatever it already read. Until now it could read every passkey in the\n  \
           vault, so treat those passkeys as possibly copied.\n\
         - Also stop sharing the vault folder with it in your sync tool (for example remove\n  \
           it from the Syncthing folder, or sign it out of your cloud account).",
        short_id(&device.id)
    ))?;
    if exposed.is_empty() {
        ctx.say("There are no passkeys in the vault, so nothing needs replacing.")?;
    } else {
        ctx.say(&format!(
            "Passkeys it could have copied ({}):",
            count(exposed.len(), "site")
        ))?;
        for (site, n) in &exposed {
            ctx.say(&format!(
                "  {}  ({})",
                clean(site, 60),
                count(*n, "passkey")
            ))?;
        }
    }
    if !yes && !confirm(ctx.prompt, &format!("Remove \"{name}\" now?"))? {
        return Err(CliError::cancelled("Nothing was changed."));
    }
    vault.remove_device(&device.id)?;
    ctx.say(&format!(
        "Removed \"{name}\". The vault key has been changed."
    ))?;
    if !exposed.is_empty() {
        ctx.say(
            "To be safe, replace the passkeys listed above: at each site, sign in, create a new\n\
             passkey (hirz stores it), then delete the old passkey at the site and with\n\
             `hirz delete`.",
        )?;
    }
    Ok(Exit::Ok)
}

pub fn backup_confirm(ctx: &mut Ctx<'_>, yes: bool) -> CliResult<Exit> {
    let (mut vault, _) = ctx.open_vault()?;
    if vault.backup_state() {
        ctx.say("Your passkeys already count as backed up.")?;
        return Ok(Exit::Ok);
    }
    ctx.say(
        "Sites can see whether a passkey is backed up. Answer yes only if your passkeys exist\n\
         somewhere other than this computer, for example:\n\
         - the vault folder is synced to a cloud service or another computer, or\n\
         - you exported them (`hirz export`) and moved the file off this computer.",
    )?;
    if !yes && !confirm(ctx.prompt, "Are your passkeys stored somewhere else?")? {
        return Err(CliError::cancelled("Nothing was changed."));
    }
    vault.confirm_backup()?;
    ctx.say("Done. Your passkeys now count as backed up on all your devices.")?;
    Ok(Exit::Ok)
}
