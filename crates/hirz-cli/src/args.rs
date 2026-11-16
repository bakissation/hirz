//! Command line parsing with the standard library only.

use crate::error::{CliError, CliResult};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteTarget {
    /// Leading hex digits of the credential id.
    IdPrefix(String),
    Account {
        site: String,
        account: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinAction {
    Set,
    Change,
    Reset,
    Status,
}

/// File formats `hirz import` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    Cxf,
    Bitwarden,
    KeePassXc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help(Option<String>),
    Version,
    Init {
        name: Option<String>,
        saved: bool,
    },
    Join {
        name: Option<String>,
        /// Ask an existing device for approval instead of typing the recovery phrase.
        request: bool,
    },
    Status {
        json: bool,
    },
    List {
        site: Option<String>,
        json: bool,
    },
    Delete {
        target: DeleteTarget,
        yes: bool,
    },
    Devices {
        json: bool,
    },
    DevicesApprove {
        /// Leading hex digits of the request id.
        request: Option<String>,
    },
    DevicesDeny {
        request: String,
    },
    RemoveDevice {
        prefix: String,
        yes: bool,
    },
    ForgetLocal,
    Pin(PinAction),
    Export {
        file: PathBuf,
        plain: bool,
    },
    Import {
        format: ImportFormat,
        file: PathBuf,
    },
    BackupConfirm {
        yes: bool,
    },
    SetupFirefox {
        nmh_path: Option<PathBuf>,
        force: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub vault: Option<PathBuf>,
    pub command: Command,
}

const MAX_ARG_LEN: usize = 4096;

#[derive(Debug, Default)]
struct Raw {
    vault: Option<PathBuf>,
    positionals: Vec<String>,
    flags: Vec<String>,
    values: Vec<(String, OsString)>,
    help: bool,
    version: bool,
}

/// Options that take a value, so `--opt value` and `--opt=value` both work.
const VALUE_OPTS: &[&str] = &[
    "--vault",
    "--name",
    "--site",
    "--cxf",
    "--bitwarden",
    "--keepassxc",
    "--nmh-path",
];
const BOOL_OPTS: &[&str] = &[
    "--json",
    "--yes",
    "--yes-i-saved-it",
    "--plain",
    "--force",
    "--request",
];

fn split_raw(args: &[OsString]) -> CliResult<Raw> {
    let mut raw = Raw::default();
    let mut iter = args.iter();
    let mut only_positional = false;
    while let Some(arg) = iter.next() {
        if arg.len() > MAX_ARG_LEN {
            return Err(CliError::usage("An argument is too long."));
        }
        let text = arg.to_str();
        if only_positional {
            raw.positionals.push(utf8(arg)?);
            continue;
        }
        match text {
            Some("--") => only_positional = true,
            Some("-h") | Some("--help") => raw.help = true,
            Some("-V") | Some("--version") => raw.version = true,
            Some(t) if t.starts_with("--") => {
                let (name, inline) = match t.split_once('=') {
                    Some((n, v)) => (n, Some(OsString::from(v))),
                    None => (t, None),
                };
                if VALUE_OPTS.contains(&name) {
                    let value = match inline {
                        Some(v) => v,
                        None => iter
                            .next()
                            .cloned()
                            .ok_or_else(|| CliError::usage(format!("{name} needs a value.")))?,
                    };
                    if value.is_empty() {
                        return Err(CliError::usage(format!("{name} needs a value.")));
                    }
                    if value.len() > MAX_ARG_LEN {
                        return Err(CliError::usage("An argument is too long."));
                    }
                    if name == "--vault" {
                        if raw.vault.is_some() {
                            return Err(CliError::usage("--vault is given twice."));
                        }
                        raw.vault = Some(PathBuf::from(value));
                    } else {
                        if raw.values.iter().any(|(n, _)| n == name) {
                            return Err(CliError::usage(format!("{name} is given twice.")));
                        }
                        raw.values.push((name.to_string(), value));
                    }
                } else if BOOL_OPTS.contains(&name) {
                    if inline.is_some() {
                        return Err(CliError::usage(format!("{name} does not take a value.")));
                    }
                    if !raw.flags.iter().any(|f| f == name) {
                        raw.flags.push(name.to_string());
                    }
                } else {
                    return Err(CliError::usage(format!("Unknown option {name}.")));
                }
            }
            Some(t) if t.starts_with('-') && t.len() > 1 => {
                return Err(CliError::usage(format!("Unknown option {t}.")));
            }
            _ => raw.positionals.push(utf8(arg)?),
        }
    }
    Ok(raw)
}

fn utf8(arg: &OsString) -> CliResult<String> {
    arg.to_str()
        .map(str::to_string)
        .ok_or_else(|| CliError::usage("Arguments must be valid UTF-8 text."))
}

impl Raw {
    fn flag(&mut self, name: &str) -> bool {
        match self.flags.iter().position(|f| f == name) {
            Some(i) => {
                self.flags.remove(i);
                true
            }
            None => false,
        }
    }

    fn value(&mut self, name: &str) -> Option<OsString> {
        let i = self.values.iter().position(|(n, _)| n == name)?;
        Some(self.values.remove(i).1)
    }

    fn string_value(&mut self, name: &str) -> CliResult<Option<String>> {
        self.value(name).map(|v| utf8(&v)).transpose()
    }

    /// Every option must have been consumed by the command.
    fn finish(self, command: &str) -> CliResult<()> {
        if let Some(f) = self.flags.first() {
            return Err(CliError::usage(format!(
                "`hirz {command}` does not accept {f}."
            )));
        }
        if let Some((n, _)) = self.values.first() {
            return Err(CliError::usage(format!(
                "`hirz {command}` does not accept {n}."
            )));
        }
        Ok(())
    }
}

fn expect_args(rest: &[String], n: usize, command: &str) -> CliResult<()> {
    if rest.len() > n {
        return Err(CliError::usage(format!(
            "Too many arguments for `hirz {command}`."
        )));
    }
    if rest.len() < n {
        return Err(CliError::usage(format!(
            "Missing argument for `hirz {command}`. See `hirz help {command}`."
        )));
    }
    Ok(())
}

/// Parses the arguments after the program name.
pub fn parse(args: &[OsString]) -> CliResult<Invocation> {
    let mut raw = split_raw(args)?;
    let vault = raw.vault.take();
    let positionals = core::mem::take(&mut raw.positionals);
    if raw.version && !raw.help {
        return Ok(Invocation {
            vault,
            command: Command::Version,
        });
    }
    let Some((first, rest)) = positionals.split_first() else {
        return Ok(Invocation {
            vault,
            command: Command::Help(None),
        });
    };
    let name = first.as_str();
    if raw.help {
        return Ok(Invocation {
            vault,
            command: Command::Help(Some(name.to_string())),
        });
    }
    let command = match name {
        "help" => Command::Help(rest.first().cloned()),
        "version" => {
            expect_args(rest, 0, "version")?;
            Command::Version
        }
        "init" => {
            expect_args(rest, 0, "init")?;
            let name = raw.string_value("--name")?;
            let saved = raw.flag("--yes-i-saved-it");
            raw.finish("init")?;
            Command::Init { name, saved }
        }
        "join" => {
            expect_args(rest, 0, "join")?;
            let name = raw.string_value("--name")?;
            let request = raw.flag("--request");
            raw.finish("join")?;
            if vault.is_none() {
                return Err(CliError::usage(
                    "`hirz join` needs the synced vault folder: hirz join --vault DIR",
                ));
            }
            Command::Join { name, request }
        }
        "status" => {
            expect_args(rest, 0, "status")?;
            let json = raw.flag("--json");
            raw.finish("status")?;
            Command::Status { json }
        }
        "list" => {
            expect_args(rest, 0, "list")?;
            let site = raw.string_value("--site")?;
            let json = raw.flag("--json");
            raw.finish("list")?;
            Command::List { site, json }
        }
        "delete" => {
            let yes = raw.flag("--yes");
            raw.finish("delete")?;
            let target = match rest {
                [prefix] => DeleteTarget::IdPrefix(prefix.clone()),
                [site, account] => DeleteTarget::Account {
                    site: site.clone(),
                    account: account.clone(),
                },
                [] => {
                    return Err(CliError::usage(
                        "Say which passkey to delete: hirz delete ID-PREFIX, or hirz delete SITE ACCOUNT. \
                         `hirz list` shows both.",
                    ));
                }
                _ => return Err(CliError::usage("Too many arguments for `hirz delete`.")),
            };
            Command::Delete { target, yes }
        }
        "devices" => match rest {
            [] => {
                let json = raw.flag("--json");
                raw.finish("devices")?;
                Command::Devices { json }
            }
            [action, more @ ..] if action == "approve" => {
                raw.finish("devices approve")?;
                match more {
                    [] => Command::DevicesApprove { request: None },
                    [id] => Command::DevicesApprove {
                        request: Some(id.clone()),
                    },
                    _ => {
                        return Err(CliError::usage(
                            "Too many arguments for `hirz devices approve`.",
                        ));
                    }
                }
            }
            [action, more @ ..] if action == "deny" => {
                raw.finish("devices deny")?;
                match more {
                    [id] => Command::DevicesDeny {
                        request: id.clone(),
                    },
                    [] => {
                        return Err(CliError::usage(
                            "Say which request to deny: hirz devices deny REQUEST. \
                             `hirz devices approve` lists them.",
                        ));
                    }
                    _ => {
                        return Err(CliError::usage(
                            "Too many arguments for `hirz devices deny`.",
                        ));
                    }
                }
            }
            _ => {
                return Err(CliError::usage(
                    "Use: hirz devices, hirz devices approve [REQUEST] or hirz devices deny REQUEST.",
                ));
            }
        },
        "remove-device" => {
            expect_args(rest, 1, "remove-device")?;
            let yes = raw.flag("--yes");
            raw.finish("remove-device")?;
            let prefix = rest.first().cloned().unwrap_or_default();
            Command::RemoveDevice { prefix, yes }
        }
        "forget-local" => {
            expect_args(rest, 0, "forget-local")?;
            raw.finish("forget-local")?;
            Command::ForgetLocal
        }
        "pin" => {
            expect_args(rest, 1, "pin")?;
            raw.finish("pin")?;
            let action = match rest.first().map(String::as_str) {
                Some("set") => PinAction::Set,
                Some("change") => PinAction::Change,
                Some("reset") => PinAction::Reset,
                Some("status") => PinAction::Status,
                _ => {
                    return Err(CliError::usage(
                        "Use one of: hirz pin set, hirz pin change, hirz pin reset, hirz pin status.",
                    ));
                }
            };
            Command::Pin(action)
        }
        "export" => {
            expect_args(rest, 0, "export")?;
            let file = raw
                .value("--cxf")
                .ok_or_else(|| CliError::usage("Say where to write: hirz export --cxf FILE"))?;
            let plain = raw.flag("--plain");
            raw.finish("export")?;
            Command::Export {
                file: PathBuf::from(file),
                plain,
            }
        }
        "import" => {
            expect_args(rest, 0, "import")?;
            let mut given = [
                (ImportFormat::Cxf, raw.value("--cxf")),
                (ImportFormat::Bitwarden, raw.value("--bitwarden")),
                (ImportFormat::KeePassXc, raw.value("--keepassxc")),
            ]
            .into_iter()
            .filter_map(|(f, v)| Some((f, v?)));
            raw.finish("import")?;
            let (format, file) = given.next().ok_or_else(|| {
                CliError::usage(
                    "Say which file to read: hirz import --cxf FILE, --bitwarden FILE or \
                     --keepassxc PATH",
                )
            })?;
            if given.next().is_some() {
                return Err(CliError::usage("Import one file at a time."));
            }
            Command::Import {
                format,
                file: PathBuf::from(file),
            }
        }
        "backup" => {
            expect_args(rest, 1, "backup")?;
            if rest.first().map(String::as_str) != Some("confirm") {
                return Err(CliError::usage("Use: hirz backup confirm"));
            }
            let yes = raw.flag("--yes");
            raw.finish("backup confirm")?;
            Command::BackupConfirm { yes }
        }
        "setup" => {
            expect_args(rest, 1, "setup")?;
            if rest.first().map(String::as_str) != Some("firefox") {
                return Err(CliError::usage("Use: hirz setup firefox"));
            }
            let nmh_path = raw.value("--nmh-path").map(PathBuf::from);
            let force = raw.flag("--force");
            raw.finish("setup firefox")?;
            Command::SetupFirefox { nmh_path, force }
        }
        other => {
            return Err(CliError::usage(format!(
                "Unknown command `{}`. Run `hirz help` to see the commands.",
                crate::ui::clean(other, 40)
            )));
        }
    };
    Ok(Invocation { vault, command })
}
