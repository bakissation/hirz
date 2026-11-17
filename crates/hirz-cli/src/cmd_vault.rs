//! Vault commands: init, join, list, delete, devices, remove-device, backup confirm.

use crate::app::Ctx;
use crate::args::DeleteTarget;
use crate::cmd_pair::{Change, check_verdict, ensure_uv_possible};
use crate::error::{CliError, CliResult, Exit, phrase_problem};
use crate::prompt::{self, confirm, confirm_word};
use crate::ui::{self, clean, count, hex, short_id};
use hirz_vault::{CredentialRecord, DeviceInfo, RecoveryPhrase, Vault, VaultError};
use serde_json::{Value, json};
use std::path::Path;

pub(crate) const PHRASE_WORDS: usize = 24;
pub(crate) const QUIZ_WORDS: usize = 3;
pub(crate) const QUIZ_ROUNDS: usize = 3;
const PHRASE_ATTEMPTS: usize = 3;
const MAX_NAME_CHARS: usize = 64;
/// The recovery phrase is shown on the terminal's alternate screen, which terminals and
/// multiplexers keep out of their scrollback and history, and wiped before the screen is left.
const ENTER_PHRASE_SCREEN: &str = "\x1b[?1049h\x1b[2J\x1b[H";
const LEAVE_PHRASE_SCREEN: &str = "\x1b[2J\x1b[3J\x1b[H\x1b[?1049l";
const PHRASE_TO_FILE: &str = "hirz: the recovery phrase is written to standard output, which is not a \
terminal.\nAnything that stores that output (a file, a log, a pipe) keeps the phrase.\n";

pub(crate) fn device_name(ctx: &Ctx<'_>, given: Option<String>) -> CliResult<String> {
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

/// `count` different word positions, in order.
pub(crate) fn random_positions(count: usize) -> CliResult<Vec<usize>> {
    let count = count.min(PHRASE_WORDS);
    let mut picked: Vec<usize> = Vec::with_capacity(count);
    let mut guard = 0u32;
    while picked.len() < count {
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

pub(crate) fn word_matches(typed: &str, word: &str) -> bool {
    let t = hirz_crypto::Zeroizing::new(typed.trim().to_lowercase());
    *t == word || (t.chars().count() >= 4 && word.starts_with(t.as_str()))
}

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
        for pos in random_positions(QUIZ_WORDS)? {
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

/// Runs `f` on the alternate screen when `alternate`, and leaves it, wiped, on every way out.
fn on_phrase_screen<T>(
    ctx: &mut Ctx<'_>,
    alternate: bool,
    f: impl FnOnce(&mut Ctx<'_>) -> CliResult<T>,
) -> CliResult<T> {
    if alternate {
        ctx.write_raw(ENTER_PHRASE_SCREEN)?;
    }
    let result = f(ctx);
    if alternate {
        let _ = ctx.write_raw(LEAVE_PHRASE_SCREEN);
    }
    result
}

/// Where `init` creates the vault and the device name, after every check that comes before
/// anything is created.
pub(crate) fn init_target(
    ctx: &Ctx<'_>,
    name: Option<String>,
) -> CliResult<(std::path::PathBuf, String)> {
    let dir = ctx.env.new_vault_dir(ctx.vault_flag.as_deref())?;
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
    Ok((dir, name))
}

pub(crate) fn create_vault(ctx: &Ctx<'_>, dir: &Path, name: &str) -> CliResult<RecoveryPhrase> {
    match Vault::create(dir, ctx.env.state_dir(), name) {
        Ok((vault, phrase)) => {
            drop(vault);
            Ok(phrase)
        }
        Err(VaultError::AlreadyExists) => Err(already_set_up(ctx)),
        Err(e) => Err(e.into()),
    }
}

/// The phrase could not be shown in full (`what` says why).
pub(crate) fn phrase_not_shown(ctx: &Ctx<'_>, dir: &Path, what: &str, init: &str) -> String {
    format!(
        "{what}\nThe vault was created in {} and the recovery phrase may not have been shown. \
         Start over: delete that folder and the files in {}, then run `{init}` again.",
        dir.display(),
        ctx.env.state_dir().display()
    )
}

/// The vault exists but its folder could not be recorded (`what` says why).
pub(crate) fn not_recorded(ctx: &Ctx<'_>, dir: &Path, what: &str) -> String {
    format!(
        "{what}\nThe vault exists in {d} and the recovery phrase shown is valid. Fix the problem, \
         then run `{p} forget-local` and `{p} join --vault {d}` with the phrase, or give \
         --vault {d} to every command.",
        d = dir.display(),
        p = ctx.program
    )
}

pub(crate) fn not_confirmed(ctx: &Ctx<'_>, dir: &Path, init: &str) -> String {
    format!(
        "The recovery phrase was not confirmed. The vault was still created and works.\n\
         If you did not save the phrase and have no passkeys in it yet, start over: delete\n\
         the folder {} and the files in {}, then run `{init}` again.",
        dir.display(),
        ctx.env.state_dir().display()
    )
}

pub fn init(ctx: &mut Ctx<'_>, name: Option<String>, saved: bool) -> CliResult<Exit> {
    let (dir, name) = init_target(ctx, name)?;
    let phrase = create_vault(ctx, &dir, &name)?;

    let phrase_text = phrase.to_words();
    let words: Vec<&str> = phrase_text.split(' ').collect();
    if words.len() != PHRASE_WORDS {
        return Err(CliError::failed("Internal error: recovery phrase length."));
    }
    if !ctx.out_is_terminal {
        ctx.prompt.notice(PHRASE_TO_FILE);
    }
    let screen = ctx.out_is_terminal && !saved;
    let mut recorded = Ok(());
    let shown = on_phrase_screen(ctx, screen, |ctx| {
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
        recorded = ctx.env.record_vault_dir(&dir);
        if saved {
            ctx.say("(--yes-i-saved-it was given, so hirz does not check the phrase.)")?;
            return Ok(true);
        }
        quiz(ctx, &words)
    });
    let confirmed = shown
        .map_err(|e| CliError::new(e.exit, phrase_not_shown(ctx, &dir, &e.message, "hirz init")))?;
    if let Err(e) = recorded {
        return Err(CliError::failed(not_recorded(ctx, &dir, &e.message)));
    }
    if !saved {
        if !confirmed {
            return Err(CliError::cancelled(not_confirmed(ctx, &dir, "hirz init")));
        }
        if screen {
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
    offer_firefox_addon(ctx);
    Ok(Exit::Ok)
}

/// The last step of `init`: offer the extension's page when Firefox is here without it. Nothing
/// that goes wrong here fails `init`.
fn offer_firefox_addon(ctx: &mut Ctx<'_>) {
    if crate::firefox::addon_state(ctx.env) != crate::firefox::AddonState::Missing {
        return;
    }
    let _ = ctx.say("");
    let open = confirm(
        ctx.prompt,
        "Firefox is installed without the hirz extension. Open its page on addons.mozilla.org \
         to add it?",
    )
    .unwrap_or(false);
    if !open {
        let _ = ctx.say(&format!(
            "To add it later, open {} in Firefox.",
            hirz_uv::first_run::ADDON_PAGE
        ));
        return;
    }
    let said = if ctx.sys.open_url(hirz_uv::first_run::ADDON_PAGE) {
        "Opened the page. Click \"Add to Firefox\" there.".to_string()
    } else {
        format!(
            "Could not open a browser. Open {} in Firefox and click \"Add to Firefox\".",
            hirz_uv::first_run::ADDON_PAGE
        )
    };
    let _ = ctx.say(&said);
}

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
    if vault.report().rotation_conflict {
        ctx.say(&format!(
            "The vault folder reports a conflict: two devices removed each other, and nothing\n\
             new is saved until it is settled. Stop sharing the folder with the device you do\n\
             not trust, then run `{p} remove-device` for it here (`{p} devices` lists them,\n\
             `{p} repair` shows the conflict).",
            p = ctx.program
        ))?;
    }
    say_sync_hint(ctx)?;
    Ok(Exit::Ok)
}

pub(crate) fn say_sync_hint(ctx: &mut Ctx<'_>) -> CliResult {
    ctx.say(&format!(
        "Passkeys you add on any device appear on the others once your sync tool has copied\n\
         the files. Connect Firefox with: {} setup firefox",
        ctx.program
    ))
}

fn account_of(r: &CredentialRecord) -> Option<&str> {
    r.user_name
        .as_deref()
        .or(r.user_display_name.as_deref())
        .filter(|s| !s.is_empty())
}

fn sorted(mut v: Vec<&CredentialRecord>) -> Vec<&CredentialRecord> {
    v.sort_by_key(|&r| {
        (
            r.rp_id.as_str(),
            account_of(r),
            r.created_at,
            r.credential_id.as_slice(),
        )
    });
    v
}

fn algorithm_name(alg: i64) -> &'static str {
    match alg {
        hirz_core::COSE_ALG_ES256 => "ES256",
        hirz_core::COSE_ALG_EDDSA => "EdDSA",
        _ => "other",
    }
}

pub(crate) fn passkey_table(records: &[&CredentialRecord]) -> String {
    passkey_table_with(records, ui::SHORT_ID_DIGITS)
}

/// The ids are `digits` hex digits long, so a list of matches shows what to type.
fn passkey_table_with(records: &[&CredentialRecord], digits: usize) -> String {
    let rows: Vec<Vec<String>> = records
        .iter()
        .map(|r| {
            vec![
                ui::site(&r.rp_id, 40),
                account_of(r).map_or_else(|| "(no name)".to_string(), |a| clean(a, 40)),
                ui::date(r.created_at),
                ui::id_prefix(&r.credential_id, digits),
            ]
        })
        .collect();
    ui::table(&["SITE", "ACCOUNT", "CREATED", "ID"], &rows)
}

pub fn list(ctx: &mut Ctx<'_>, site: Option<String>, json_out: bool) -> CliResult<Exit> {
    let (vault, _) = ctx.open_active_vault()?;
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
        ctx.say_json(&Value::Array(items))?;
        return Ok(Exit::Ok);
    }
    if records.is_empty() {
        ctx.say(match site {
            Some(_) => "No passkeys for that site.",
            None => "No passkeys yet. Passkeys appear here after you create one on a website.",
        })?;
        return Ok(Exit::Ok);
    }
    ctx.write_raw(&passkey_table(&records))?;
    ctx.say(&count(records.len(), "passkey"))?;
    Ok(Exit::Ok)
}

pub fn delete(ctx: &mut Ctx<'_>, target: DeleteTarget, yes: bool) -> CliResult<Exit> {
    let (mut vault, _) = ctx.open_active_vault()?;
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
            let ids: Vec<&[u8]> = several.iter().map(|r| r.credential_id.as_slice()).collect();
            ctx.write_raw(&passkey_table_with(several, ui::distinct_digits(&ids)))?;
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

/// Who approved a device: the name of that device, or "recovery phrase" for a device added with
/// the phrase (the first device included). `all` is every device, so the name can be looked up.
fn added_by(d: &DeviceInfo, all: &[DeviceInfo]) -> String {
    match d.added_by {
        None => "recovery phrase".to_string(),
        Some(by) => match all.iter().find(|o| o.id == by) {
            Some(o) => clean(&o.name, MAX_NAME_CHARS),
            None => format!("unknown ({})", short_id(&by)),
        },
    }
}

/// Marks the name of a device in use when another device in use has the same name.
const SAME_NAME_MARK: &str = " (*)";
const SAME_NAME_NOTE: &str = "(*) Another device in use has the same name. A device that someone else \
approved can be named like one of yours: tell them apart by ID, ADDED and ADDED BY.";

/// Whether another device in use has the same name as `d` (compared as shown).
fn shares_name(d: &DeviceInfo, all: &[DeviceInfo]) -> bool {
    let shown = clean(&d.name, MAX_NAME_CHARS);
    !d.removed
        && all
            .iter()
            .any(|o| o.id != d.id && !o.removed && clean(&o.name, MAX_NAME_CHARS) == shown)
}

fn device_table(devs: &[DeviceInfo], all: &[DeviceInfo]) -> String {
    let ids: Vec<&[u8]> = devs.iter().map(|d| d.id.as_slice()).collect();
    let digits = ui::distinct_digits(&ids);
    let rows: Vec<Vec<String>> = devs
        .iter()
        .map(|d| {
            let mut name = clean(&d.name, MAX_NAME_CHARS);
            if shares_name(d, all) {
                name.push_str(SAME_NAME_MARK);
            }
            vec![
                name,
                ui::id_prefix(&d.id, digits),
                ui::date(d.added_at),
                added_by(d, all),
                if d.removed {
                    "removed".to_string()
                } else if d.this_device {
                    "this computer".to_string()
                } else {
                    "active".to_string()
                },
            ]
        })
        .collect();
    ui::table(&["NAME", "ID", "ADDED", "ADDED BY", "STATUS"], &rows)
}

fn sorted_devices(vault: &Vault) -> Vec<DeviceInfo> {
    let mut devs = vault.devices();
    devs.sort_by_key(|d| (d.removed, d.added_at, d.id));
    devs
}

pub fn devices(ctx: &mut Ctx<'_>, json_out: bool) -> CliResult<Exit> {
    let (mut vault, _) = ctx.open_active_vault()?;
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
                    "added_by": d.added_by.map(|by| hex(&by)),
                    "same_name_as_another": shares_name(d, &devs),
                })
            })
            .collect();
        ctx.say_json(&Value::Array(items))?;
        return Ok(Exit::Ok);
    }
    ctx.write_raw(&device_table(&devs, &devs))?;
    if devs.iter().any(|d| shares_name(d, &devs)) {
        ctx.say(SAME_NAME_NOTE)?;
    }
    let active = devs.iter().filter(|d| !d.removed).count();
    ctx.say(&format!("{} in use.", count(active, "device")))?;
    let waiting = vault.pairing_requests().map(|r| r.len()).unwrap_or(0);
    if waiting > 0 {
        ctx.say(&format!(
            "{} waiting for approval: run `{} devices approve`.",
            count(waiting, "device"),
            ctx.program
        ))?;
        crate::cmd_pair::say_hidden_requests(ctx, vault.hidden_pairing_requests())?;
    } else if active == 1 {
        ctx.say(&format!(
            "Add another computer: run `hirz join --vault DIR --request` there, then\n\
             `{} devices approve` here (see docs/sync.md).",
            ctx.program
        ))?;
    }
    Ok(Exit::Ok)
}

pub fn sites(records: &[&CredentialRecord]) -> Vec<(String, usize)> {
    let mut map: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for r in records {
        let e = map.entry(r.rp_id.as_str()).or_insert(0);
        *e = e.saturating_add(1);
    }
    map.into_iter().map(|(s, n)| (s.to_string(), n)).collect()
}

pub fn remove_device(ctx: &mut Ctx<'_>, prefix: &str, yes: bool) -> CliResult<Exit> {
    let (mut vault, _) = ctx.open_active_vault()?;
    let Some(prefix) = ui::hex_prefix(prefix) else {
        return Err(CliError::usage(
            "Give at least 4 characters of the device id shown by `hirz devices`.",
        ));
    };
    let all = sorted_devices(&vault);
    let candidates: Vec<DeviceInfo> = all
        .iter()
        .filter(|d| !d.removed && hex(&d.id).starts_with(&prefix))
        .cloned()
        .collect();
    let device = match candidates.as_slice() {
        [] => {
            return Err(CliError::failed(
                "No device in use matches. Run `hirz devices` to see the ids.",
            ));
        }
        [one] => one.clone(),
        several => {
            ctx.write_raw(&device_table(several, &all))?;
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
    let id_short = short_id(&device.id);
    let change = Change {
        action: "Removing a device",
        retry: format!("{} remove-device {id_short}", ctx.program),
        unchanged: "Nothing was removed.".to_string(),
    };
    ensure_uv_possible(ctx, &change)?;
    let exposed = sites(&vault.list_all());
    let resting = vault.devices_resting_on(&device.id);
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
                ui::site(site, 60),
                count(*n, "passkey")
            ))?;
        }
    }
    if !resting.is_empty() {
        let n = resting.len();
        let (they, are) = if n == 1 {
            ("1 device in use was".to_string(), "It is")
        } else {
            (format!("{n} devices in use were"), "They are")
        };
        ctx.say(&format!(
            "\nWARNING: {they} added through \"{name}\" (it approved them, or approved the\n\
             device that did). {are} not removed with it: each keeps its access and can read\n\
             passkeys added from now on. Whoever holds \"{name}\" may have approved devices of\n\
             its own, with names like yours:"
        ))?;
        ctx.write_raw(&device_table(&resting, &all))?;
        ctx.say(&format!(
            "Remove each one you did not approve yourself, after this, with\n  \
             {} remove-device ID",
            ctx.program
        ))?;
    }
    if !yes && !confirm(ctx.prompt, &format!("Remove \"{name}\" now?"))? {
        return Err(CliError::cancelled("Nothing was changed."));
    }
    ctx.say(
        "Confirm in the hirz window: it shows the device, then asks for your system password,\n\
         your fingerprint or your hirz PIN.",
    )?;
    let removal = hirz_core::RemovalApprovalContext {
        device_name: &device.name,
        device_id_short: &id_short,
    };
    let sys = ctx.sys;
    let verdict = sys.pairing_approver(ctx.env).confirm_removal(&removal);
    check_verdict(ctx, verdict, &change)?;
    vault.remove_device(&device.id)?;
    ctx.say(&format!(
        "Removed \"{name}\". The vault key has been changed."
    ))?;
    if !resting.is_empty() {
        let ids: Vec<String> = resting.iter().map(|d| short_id(&d.id)).collect();
        ctx.say(&format!(
            "Still in use, added through \"{name}\": {}. Remove the ones you do not know with\n  \
             {} remove-device ID",
            ids.join(", "),
            ctx.program
        ))?;
    }
    if !exposed.is_empty() {
        ctx.say(
            "To be safe, replace the passkeys listed above: at each site, sign in, create a new\n\
             passkey (hirz stores it), then delete the old passkey at the site and with\n\
             `hirz delete`.",
        )?;
    }
    Ok(Exit::Ok)
}

pub fn forget_local(ctx: &mut Ctx<'_>) -> CliResult<Exit> {
    let state = ctx.env.state_dir().to_path_buf();
    if !ctx.env.device_state_exists() {
        ctx.say("hirz has no keys for a vault on this computer, so there is nothing to forget.")?;
        return Ok(Exit::Ok);
    }
    let removed = ctx
        .vault_dir()
        .ok()
        .filter(|d| Vault::exists(d))
        .and_then(|d| Vault::open(&d, &state).ok())
        .is_some_and(|v| v.report().this_device_removed);
    ctx.say(&format!(
        "This deletes this computer's hirz keys from {}.\n\
         The vault folder and the other devices are not changed, and your hirz PIN is kept.",
        state.display()
    ))?;
    let go = if removed {
        ctx.say(crate::app::REMOVED)?;
        confirm(ctx.prompt, "Delete this computer's hirz keys?")?
    } else {
        ctx.say(&format!(
            "This computer still uses the vault. Afterwards it cannot use your passkeys until\n\
             it joins again (`{} join --vault DIR --request`, approved on another device, or\n\
             with the recovery phrase). If it is the only device, make sure you have the\n\
             recovery phrase first.",
            ctx.program
        ))?;
        confirm_word(ctx.prompt, "Forget the keys on this computer?", "forget")?
    };
    if !go {
        return Err(CliError::cancelled("Nothing was deleted."));
    }
    Vault::forget_local(&state)?;
    match std::fs::remove_file(state.join(hirz_vault::VAULT_POINTER_FILE)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(CliError::io(
                "Could not remove the recorded vault location",
                &e,
            ));
        }
    }
    ctx.say(&format!(
        "Done. This computer no longer has hirz keys. To use hirz here again, run\n\
         `{} join --vault DIR --request` (or `{} init` for a new vault).",
        ctx.program, ctx.program
    ))?;
    Ok(Exit::Ok)
}

pub fn backup_confirm(ctx: &mut Ctx<'_>, yes: bool) -> CliResult<Exit> {
    let (mut vault, _) = ctx.open_active_vault()?;
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
