//! `hirz export` and `hirz import`: FIDO CXF files, encrypted by default, and imports from
//! Bitwarden and KeePassXC exports.

use crate::app::Ctx;
use crate::args::ImportFormat;
use crate::cxf::{self, Candidate};
use crate::envelope::{self, EnvelopeError};
use crate::error::{CliError, CliResult, Exit};
use crate::foreign::{self, Found, bitwarden, keepassxc};
use crate::prompt::{self, confirm, confirm_word};
use crate::ui::{clean, count};
use hirz_crypto::{Secret, Zeroizing};
use hirz_vault::Vault;
use std::io::Read;
use std::path::{Path, PathBuf};

const PASSPHRASE_ATTEMPTS: usize = 3;

fn new_passphrase(ctx: &mut Ctx<'_>) -> CliResult<Zeroizing<String>> {
    ctx.say(&format!(
        "Choose a passphrase for the file (at least {} characters). You need it to import\n\
         the file later. hirz cannot recover it for you.",
        envelope::MIN_PASSPHRASE_CHARS
    ))?;
    for _ in 0..3 {
        let first = prompt::read_secret(ctx.prompt, "Passphrase: ")?;
        if let Some(problem) = envelope::passphrase_problem(&first) {
            ctx.say(&problem)?;
            continue;
        }
        let second = prompt::read_secret(ctx.prompt, "Type the passphrase again: ")?;
        if hirz_crypto::ct_eq(first.as_bytes(), second.as_bytes()) {
            return Ok(first);
        }
        ctx.say("The two passphrases are different. Try again.")?;
    }
    Err(CliError::cancelled("No file was written."))
}

pub fn export(ctx: &mut Ctx<'_>, file: &Path, plain: bool) -> CliResult<Exit> {
    let file = ctx.env.absolute(file)?;
    if file.exists() {
        return Err(CliError::failed(format!(
            "{} already exists. Choose a new file name.",
            file.display()
        )));
    }
    let (mut vault, _) = ctx.open_vault()?;
    let n = vault.list_all().len();
    if n == 0 {
        return Err(CliError::failed("There are no passkeys to export."));
    }
    if plain {
        ctx.say(
            "WARNING: --plain writes your private keys without encryption. Anyone who gets\n\
             this file, or a copy of it, can sign in to your accounts. Use it only to import\n\
             into another passkey manager right away, then delete the file.",
        )?;
        if !confirm_word(ctx.prompt, "Write an unencrypted file?", "yes")? {
            return Err(CliError::cancelled("No file was written."));
        }
    }
    let passphrase = if plain {
        None
    } else {
        Some(new_passphrase(ctx)?)
    };
    let mut account_id = [0u8; 16];
    hirz_crypto::random_fill(&mut account_id)
        .map_err(|_| CliError::failed("The system random generator failed."))?;
    let json = {
        let records = vault.list_all();
        cxf::export_json(&records, crate::ui::now(), &account_id)
            .map_err(|e| CliError::failed(format!("Could not build the export: {e}")))?
    };
    let bytes: Zeroizing<Vec<u8>> = match &passphrase {
        Some(p) => {
            ctx.say("Encrypting (this takes a moment)...")?;
            Zeroizing::new(
                envelope::seal(p.as_bytes(), &json, ctx.kdf)
                    .map_err(|_| CliError::failed("Could not encrypt the export."))?,
            )
        }
        None => json,
    };
    crate::env::create_new_private(&file, &bytes)
        .map_err(|e| CliError::io(&format!("Could not write {}", file.display()), &e))?;
    ctx.say(&format!(
        "Saved {} to {}{}.",
        count(n, "passkey"),
        file.display(),
        if plain { " (not encrypted)" } else { "" }
    ))?;
    if vault.backup_state() {
        return Ok(Exit::Ok);
    }
    ctx.say(
        "An export is a backup once it is stored somewhere other than this computer (for\n\
         example a USB drive). Then sites can see that your passkeys are backed up.",
    )?;
    if confirm(
        ctx.prompt,
        "Have you already stored this file somewhere else? (If not, run `hirz backup confirm` later.)",
    )? {
        vault.confirm_backup()?;
        ctx.say("Noted: your passkeys now count as backed up.")?;
    }
    Ok(Exit::Ok)
}

fn len64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn read_capped(path: &Path, max: u64) -> CliResult<Zeroizing<Vec<u8>>> {
    let f = std::fs::File::open(path)
        .map_err(|e| CliError::io(&format!("Could not open {}", path.display()), &e))?;
    let mut buf = Zeroizing::new(Vec::new());
    f.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| CliError::io(&format!("Could not read {}", path.display()), &e))?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max {
        return Err(CliError::failed(
            "The file is too large to be a passkey export.",
        ));
    }
    Ok(buf)
}

fn decrypt(ctx: &mut Ctx<'_>, data: &[u8]) -> CliResult<Zeroizing<Vec<u8>>> {
    match envelope::params(data) {
        Ok(_) => {}
        Err(EnvelopeError::UnsupportedVersion) => {
            return Err(CliError::failed(
                "This encrypted export was made by a newer version of hirz.",
            ));
        }
        Err(EnvelopeError::TooCostly) => {
            return Err(CliError::failed(
                "This encrypted export asks for more memory or time than hirz allows.",
            ));
        }
        Err(_) => return Err(CliError::failed("The encrypted export is damaged.")),
    }
    ctx.say("This export is encrypted.")?;
    for attempt in 0..PASSPHRASE_ATTEMPTS {
        let p = prompt::read_secret(ctx.prompt, "Passphrase: ")?;
        match envelope::open(p.as_bytes(), data) {
            Ok(plain) => return Ok(plain),
            Err(EnvelopeError::WrongPassphrase) => {
                if attempt.saturating_add(1) < PASSPHRASE_ATTEMPTS {
                    ctx.say("Wrong passphrase (or the file was changed). Try again.")?;
                }
            }
            Err(_) => return Err(CliError::failed("The encrypted export is damaged.")),
        }
    }
    Err(CliError::denied(
        "Wrong passphrase, or the file was changed after it was written. Nothing was imported.",
    ))
}

pub fn import(ctx: &mut Ctx<'_>, format: ImportFormat, file: &Path) -> CliResult<Exit> {
    let file = ctx.env.absolute(file)?;
    let (mut vault, _) = ctx.open_vault()?;
    match format {
        ImportFormat::Cxf => import_cxf(ctx, &mut vault, &file),
        ImportFormat::Bitwarden => import_bitwarden(ctx, &mut vault, &file),
        ImportFormat::KeePassXc => import_keepassxc(ctx, &mut vault, &file),
    }
}

fn import_cxf(ctx: &mut Ctx<'_>, vault: &mut Vault, file: &Path) -> CliResult<Exit> {
    let raw = read_capped(file, envelope::MAX_FILE_LEN)?;
    let json = if envelope::is_envelope(&raw) {
        decrypt(ctx, &raw)?
    } else {
        raw
    };
    let parsed = cxf::parse(&json, crate::ui::now()).map_err(CliError::failed)?;
    drop(json);
    if !parsed.exporter.is_empty() {
        ctx.say(&format!("Export made by: {}", parsed.exporter))?;
    }
    store(ctx, vault, parsed.passkeys, parsed.other_credentials)
}

fn candidate(found: Found) -> Candidate {
    match found {
        Found::Ready(record) => Candidate::Ready {
            record,
            dropped: Vec::new(),
        },
        Found::Skipped {
            site,
            account,
            reason,
        } => Candidate::Skipped {
            label: cxf::label(&site, account.as_deref()),
            reason,
        },
    }
}

fn bitwarden_password(ctx: &mut Ctx<'_>, file: &bitwarden::Protected) -> CliResult<Secret> {
    ctx.say("This Bitwarden export is password protected.")?;
    for attempt in 0..PASSPHRASE_ATTEMPTS {
        let p = prompt::read_secret(ctx.prompt, "File password: ")?;
        match file.decrypt(p.as_bytes()) {
            Ok(plain) => return Ok(plain),
            Err(bitwarden::OpenError::WrongPassword) => {
                if attempt.saturating_add(1) < PASSPHRASE_ATTEMPTS {
                    ctx.say("Wrong password (or the file was changed). Try again.")?;
                }
            }
            Err(bitwarden::OpenError::Damaged) => {
                return Err(CliError::failed(
                    "The password protected export is damaged.",
                ));
            }
        }
    }
    Err(CliError::denied(
        "Wrong password, or the file was changed after it was written. Nothing was imported.",
    ))
}

fn import_bitwarden(ctx: &mut Ctx<'_>, vault: &mut Vault, file: &Path) -> CliResult<Exit> {
    let now = crate::ui::now();
    let raw = read_capped(file, len64(foreign::MAX_FILE_LEN))?;
    let parsed = match bitwarden::read(&raw, now).map_err(CliError::failed)? {
        bitwarden::Export::Plain(parsed) => parsed,
        bitwarden::Export::Protected(protected) => {
            drop(raw);
            let inner = bitwarden_password(ctx, &protected)?;
            bitwarden::read_decrypted(&inner, now).map_err(CliError::failed)?
        }
    };
    store(
        ctx,
        vault,
        parsed.passkeys.into_iter().map(candidate).collect(),
        parsed.other_items,
    )
}

fn passkey_files(dir: &Path) -> CliResult<Vec<PathBuf>> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| CliError::io(&format!("Could not read {}", dir.display()), &e))?;
    let mut files = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| CliError::io(&format!("Could not read {}", dir.display()), &e))?
            .path();
        if path.extension().is_some_and(|x| x == keepassxc::EXTENSION) && path.is_file() {
            if files.len() >= foreign::MAX_PASSKEYS {
                return Err(CliError::failed(format!(
                    "The folder holds more than {} passkey files; hirz will not read it.",
                    foreign::MAX_PASSKEYS
                )));
            }
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn import_keepassxc(ctx: &mut Ctx<'_>, vault: &mut Vault, path: &Path) -> CliResult<Exit> {
    let now = crate::ui::now();
    let read_one = |file: &Path| -> CliResult<Found> {
        let raw = read_capped(file, len64(keepassxc::MAX_PASSKEY_FILE_LEN))?;
        keepassxc::read(&raw, now).map_err(CliError::failed)
    };
    if !path.is_dir() {
        let found = read_one(path)?;
        return store(ctx, vault, vec![candidate(found)], 0);
    }
    let files = passkey_files(path)?;
    if files.is_empty() {
        return Err(CliError::failed(format!(
            "{} holds no .{} files.",
            path.display(),
            keepassxc::EXTENSION
        )));
    }
    let mut found = Vec::with_capacity(files.len());
    for file in &files {
        found.push(match read_one(file) {
            Ok(f) => candidate(f),
            Err(e) => Candidate::Skipped {
                label: clean(
                    &file
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    60,
                ),
                reason: e.message,
            },
        });
    }
    store(ctx, vault, found, 0)
}

/// Adds the ready passkeys that are not in the vault yet and reports the rest.
fn store(
    ctx: &mut Ctx<'_>,
    vault: &mut Vault,
    passkeys: Vec<Candidate>,
    other_items: usize,
) -> CliResult<Exit> {
    if passkeys.is_empty() {
        ctx.say("The file holds no passkeys.")?;
    }
    let mut imported = 0usize;
    let mut already = 0usize;
    let mut skipped: Vec<(String, String)> = Vec::new();
    let mut dropped_notes: Vec<(String, Vec<&'static str>)> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for c in passkeys {
        match c {
            Candidate::Skipped { label, reason } => skipped.push((label, reason)),
            Candidate::Ready { record, dropped } => {
                let label = cxf::label(&record.rp_id, record.user_name.as_deref());
                if !seen.insert(record.credential_id.clone()) {
                    skipped.push((label, "it appears twice in the file".into()));
                    continue;
                }
                if let Some(existing) = vault.get(&record.credential_id) {
                    if hirz_crypto::ct_eq(&existing.private_key_pkcs8, &record.private_key_pkcs8)
                        && existing.rp_id == record.rp_id
                    {
                        already = already.saturating_add(1);
                    } else {
                        skipped.push((
                            label,
                            "a different passkey with the same id is already in hirz; it was \
                             not replaced"
                                .into(),
                        ));
                    }
                    continue;
                }
                vault.put(*record)?;
                imported = imported.saturating_add(1);
                if !dropped.is_empty() {
                    dropped_notes.push((label, dropped));
                }
            }
        }
    }
    ctx.say(&format!("Imported {}.", count(imported, "passkey")))?;
    if already > 0 {
        ctx.say(&format!(
            "{} were already in hirz and were left as they are.",
            count(already, "passkey")
        ))?;
    }
    if other_items > 0 {
        ctx.say(&format!(
            "{} of other kinds (passwords, notes, cards...) were ignored: hirz stores passkeys only.",
            count(other_items, "item")
        ))?;
    }
    for (label, what) in &dropped_notes {
        ctx.say(&format!(
            "Note: {label}: hirz does not support {} and did not keep it.",
            what.join(" and ")
        ))?;
    }
    if skipped.is_empty() {
        return Ok(Exit::Ok);
    }
    ctx.say(&format!("Skipped {}:", count(skipped.len(), "passkey")))?;
    for (label, reason) in &skipped {
        ctx.say(&format!("  {}: {}", clean(label, 100), reason))?;
    }
    ctx.say("Skipped passkeys stay usable in the program you exported them from.")?;
    Ok(Exit::Partial)
}
