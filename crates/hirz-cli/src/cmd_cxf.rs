//! `hirz export` and `hirz import`: FIDO CXF files, encrypted by default, and imports from
//! Bitwarden and KeePassXC exports.

use crate::app::Ctx;
use crate::args::ImportFormat;
use crate::cmd_pair::{Change, check_verdict, ensure_uv_possible};
use crate::cmd_vault::passkey_table;
use crate::cxf::{self, Candidate};
use crate::envelope::{self, EnvelopeError};
use crate::error::{CliError, CliResult, Exit};
use crate::foreign::{self, Found, bitwarden, keepassxc};
use crate::prompt::{self, confirm, confirm_word};
use crate::ui::{clean, count, path_text};
use hirz_core::ExportApprovalContext;
use hirz_crypto::{Secret, Zeroizing};
use hirz_vault::{CredentialRecord, Vault};
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

const NOT_REIMPORTABLE_SHOWN: usize = 10;

fn export_change(ctx: &Ctx<'_>) -> Change<'static> {
    Change {
        action: "Exporting your passkeys",
        retry: format!("{} export --cxf FILE", ctx.program),
        unchanged: "No file was written.".to_string(),
    }
}

/// User verification before the export is built, as for approving and removing a device.
fn verify_export(
    ctx: &mut Ctx<'_>,
    passkeys: usize,
    plain: bool,
    change: &Change<'_>,
) -> CliResult {
    ctx.say(
        "Confirm in the hirz window: it asks for your system password, your fingerprint or\n\
         your hirz PIN. Without it nothing is exported.",
    )?;
    let export = ExportApprovalContext { passkeys, plain };
    let sys = ctx.sys;
    let verdict = sys.pairing_approver(ctx.env).confirm_export(&export);
    check_verdict(ctx, verdict, change)
}

fn warn_not_reimportable(ctx: &mut Ctx<'_>, lost: &[String]) -> CliResult {
    if lost.is_empty() {
        return Ok(());
    }
    ctx.say(
        "Warning: some passkeys have a site id that `hirz import` cannot read back (it must be\n\
         plain printable text). They are written to the file, but hirz skips them when you\n\
         import it:",
    )?;
    for label in lost.iter().take(NOT_REIMPORTABLE_SHOWN) {
        ctx.say(&format!("  {label}"))?;
    }
    if lost.len() > NOT_REIMPORTABLE_SHOWN {
        ctx.say(&format!(
            "  and {} more",
            lost.len().saturating_sub(NOT_REIMPORTABLE_SHOWN)
        ))?;
    }
    Ok(())
}

pub fn export(ctx: &mut Ctx<'_>, file: &Path, plain: bool) -> CliResult<Exit> {
    let file = ctx.env.absolute(file)?;
    if file.exists() {
        return Err(CliError::failed(format!(
            "{} already exists. Choose a new file name.",
            path_text(&file)
        )));
    }
    let (mut vault, _) = ctx.open_active_vault()?;
    let (n, lost) = {
        let records = vault.list_all();
        let lost: Vec<String> = cxf::not_reimportable(&records)
            .iter()
            .map(|r| cxf::label(&r.rp_id, r.user_name.as_deref()))
            .collect();
        (records.len(), lost)
    };
    if n == 0 {
        return Err(CliError::failed("There are no passkeys to export."));
    }
    let change = export_change(ctx);
    ensure_uv_possible(ctx, &change)?;
    warn_not_reimportable(ctx, &lost)?;
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
    verify_export(ctx, n, plain, &change)?;
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
        .map_err(|e| CliError::io(&format!("Could not write {}", path_text(&file)), &e))?;
    ctx.say(&format!(
        "Saved {} to {}{}.",
        count(n, "passkey"),
        path_text(&file),
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

/// The whole file, at most `max` bytes. The buffer is sized from the file's length, so a regular
/// file is read without any growth; a pipe or a file that grows moves to a bigger buffer, and the
/// old one is wiped as it is dropped. The passkeys in the file are never left in freed memory.
fn read_capped(path: &Path, max: u64) -> CliResult<Zeroizing<Vec<u8>>> {
    let mut f = std::fs::File::open(path)
        .map_err(|e| CliError::io(&format!("Could not open {}", path_text(path)), &e))?;
    let read_error =
        |e: std::io::Error| CliError::io(&format!("Could not read {}", path_text(path)), &e);
    let too_large = || CliError::failed("The file is too large to be a passkey export.");
    let limit = usize::try_from(max).unwrap_or(usize::MAX).saturating_add(1);
    let known = usize::try_from(f.metadata().map_err(read_error)?.len()).unwrap_or(limit);
    let mut buf = Zeroizing::new(vec![0u8; known.saturating_add(1).clamp(1, limit)]);
    let mut have = 0usize;
    loop {
        if have == buf.len() {
            if buf.len() >= limit {
                return Err(too_large());
            }
            let bigger = buf.len().saturating_mul(2).clamp(4096, limit);
            let mut next = Zeroizing::new(vec![0u8; bigger]);
            next.get_mut(..have)
                .ok_or_else(too_large)?
                .copy_from_slice(buf.get(..have).ok_or_else(too_large)?);
            buf = next;
        }
        let room = buf.get_mut(have..).ok_or_else(too_large)?;
        match f.read(room).map_err(read_error)? {
            0 => break,
            n => have = have.saturating_add(n),
        }
    }
    buf.truncate(have);
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

pub fn import(ctx: &mut Ctx<'_>, format: ImportFormat, file: &Path, yes: bool) -> CliResult<Exit> {
    let file = ctx.env.absolute(file)?;
    let (mut vault, _) = ctx.open_active_vault()?;
    match format {
        ImportFormat::Cxf => import_cxf(ctx, &mut vault, &file, yes),
        ImportFormat::Bitwarden => import_bitwarden(ctx, &mut vault, &file, yes),
        ImportFormat::KeePassXc => import_keepassxc(ctx, &mut vault, &file, yes),
    }
}

fn import_cxf(ctx: &mut Ctx<'_>, vault: &mut Vault, file: &Path, yes: bool) -> CliResult<Exit> {
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
    store(ctx, vault, parsed.passkeys, parsed.other_credentials, yes)
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

fn import_bitwarden(
    ctx: &mut Ctx<'_>,
    vault: &mut Vault,
    file: &Path,
    yes: bool,
) -> CliResult<Exit> {
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
        yes,
    )
}

fn passkey_files(dir: &Path) -> CliResult<Vec<PathBuf>> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| CliError::io(&format!("Could not read {}", path_text(dir)), &e))?;
    let mut files = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| CliError::io(&format!("Could not read {}", path_text(dir)), &e))?
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

fn import_keepassxc(
    ctx: &mut Ctx<'_>,
    vault: &mut Vault,
    path: &Path,
    yes: bool,
) -> CliResult<Exit> {
    let now = crate::ui::now();
    let read_one = |file: &Path| -> CliResult<Found> {
        let raw = read_capped(file, len64(keepassxc::MAX_PASSKEY_FILE_LEN))?;
        keepassxc::read(&raw, now).map_err(CliError::failed)
    };
    if !path.is_dir() {
        let found = read_one(path)?;
        return store(ctx, vault, vec![candidate(found)], 0, yes);
    }
    let files = passkey_files(path)?;
    if files.is_empty() {
        return Err(CliError::failed(format!(
            "{} holds no .{} files.",
            path_text(path),
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
    store(ctx, vault, found, 0, yes)
}

/// What an import would do, worked out before anything is written.
#[derive(Default)]
struct Plan {
    add: Vec<(Box<CredentialRecord>, Vec<&'static str>)>,
    already: usize,
    skipped: Vec<(String, String)>,
    shares_account: Vec<String>,
}

fn plan(vault: &Vault, passkeys: Vec<Candidate>) -> Plan {
    let mut plan = Plan::default();
    let mut seen = std::collections::BTreeSet::new();
    for c in passkeys {
        match c {
            Candidate::Skipped { label, reason } => plan.skipped.push((label, reason)),
            Candidate::Ready { record, dropped } => {
                let label = cxf::label(&record.rp_id, record.user_name.as_deref());
                if !seen.insert(record.credential_id.clone()) {
                    plan.skipped
                        .push((label, "it appears twice in the file".into()));
                    continue;
                }
                if let Some(existing) = vault.get(&record.credential_id) {
                    if hirz_crypto::ct_eq(&existing.private_key_pkcs8, &record.private_key_pkcs8)
                        && existing.rp_id == record.rp_id
                    {
                        plan.already = plan.already.saturating_add(1);
                    } else {
                        plan.skipped.push((
                            label,
                            "a different passkey with the same id is already in hirz; it was \
                             not replaced"
                                .into(),
                        ));
                    }
                    continue;
                }
                let same_account = !record.user_id.is_empty()
                    && vault
                        .credentials_for_rp(&record.rp_id)
                        .iter()
                        .any(|r| r.user_id == record.user_id);
                if same_account {
                    plan.shares_account.push(label);
                }
                plan.add.push((record, dropped));
            }
        }
    }
    plan
}

fn show_preview(ctx: &mut Ctx<'_>, plan: &Plan, asking: bool) -> CliResult {
    let records: Vec<&CredentialRecord> = plan.add.iter().map(|(r, _)| &**r).collect();
    ctx.say(&format!(
        "Passkeys to add: {}. An imported passkey signs in to the account it names, and a file\n\
         you did not make yourself can name someone else's account.{}",
        records.len(),
        if asking { " Check the list:" } else { "" }
    ))?;
    ctx.write_raw(&passkey_table(&records))?;
    for label in &plan.shares_account {
        ctx.say(&format!(
            "Warning: {}: hirz already has a passkey for this account. After the import it has\n\
             two, and a site may offer the imported one first.",
            clean(label, 100)
        ))?;
    }
    Ok(())
}

/// Adds the ready passkeys that are not in the vault yet, after the user has seen what they
/// are, and reports the rest.
fn store(
    ctx: &mut Ctx<'_>,
    vault: &mut Vault,
    passkeys: Vec<Candidate>,
    other_items: usize,
    yes: bool,
) -> CliResult<Exit> {
    if passkeys.is_empty() {
        ctx.say("The file holds no passkeys.")?;
    }
    let plan = plan(vault, passkeys);
    if !plan.add.is_empty() {
        show_preview(ctx, &plan, !yes)?;
        if !yes
            && !confirm(
                ctx.prompt,
                &format!("Add {} to hirz?", count(plan.add.len(), "passkey")),
            )?
        {
            return Err(CliError::cancelled(
                "Nothing was imported. A script that has checked the file can pass --yes.",
            ));
        }
    }
    let Plan {
        add,
        already,
        skipped,
        ..
    } = plan;
    let mut imported: Vec<String> = Vec::new();
    let mut dropped_notes: Vec<(String, Vec<&'static str>)> = Vec::new();
    for (record, dropped) in add {
        let label = cxf::label(&record.rp_id, record.user_name.as_deref());
        if let Err(e) = vault.put(*record) {
            if !imported.is_empty() {
                ctx.say(&format!(
                    "The import stopped. These {} were added before the error:",
                    count(imported.len(), "passkey")
                ))?;
                for l in &imported {
                    ctx.say(&format!("  {}", clean(l, 100)))?;
                }
            }
            return Err(e.into());
        }
        if !dropped.is_empty() {
            dropped_notes.push((label.clone(), dropped));
        }
        imported.push(label);
    }
    ctx.say(&format!("Imported {}.", count(imported.len(), "passkey")))?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn file_with(name: &str, bytes: &[u8]) -> PathBuf {
        let mut r = [0u8; 8];
        hirz_crypto::random_fill(&mut r).unwrap();
        let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("hirz-read-capped-{hex}-{name}"));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn a_file_is_read_into_a_buffer_that_never_grew() {
        let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let path = file_with("whole", &data);
        let buf = read_capped(&path, 1 << 20).unwrap();
        assert_eq!(&buf[..], &data[..]);
        assert_eq!(
            buf.capacity(),
            data.len() + 1,
            "sized from the file, so no copy was left behind by growing"
        );
        std::fs::remove_file(&path).unwrap();

        let path = file_with("empty", b"");
        assert!(read_capped(&path, 100).unwrap().is_empty());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_file_over_the_cap_is_refused_and_one_at_the_cap_is_not() {
        let path = file_with("cap", &[7u8; 1000]);
        assert_eq!(read_capped(&path, 1000).unwrap().len(), 1000);
        let err = read_capped(&path, 999).unwrap_err();
        assert!(err.message.contains("too large"), "{}", err.message);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_stream_with_no_length_is_read_up_to_the_cap() {
        let err = read_capped(Path::new("/dev/zero"), 10_000).unwrap_err();
        assert!(err.message.contains("too large"), "{}", err.message);
        let missing = read_capped(Path::new("/nonexistent/hirz-file"), 10).unwrap_err();
        assert!(
            missing.message.contains("Could not open"),
            "{}",
            missing.message
        );
    }
}
