//! Relying party ids that mean "log in to this computer" or "unlock this disk". A synced software
//! key must never be that factor: every device in the sync folder holds it, and a lock screen or
//! initrd cannot show hirz's approval prompt (docs/threat-model.md, "Logging in to the computer").

/// `pam-u2f` asks for `pam://HOSTNAME` unless the administrator sets `origin=` and `appid=`.
const PREFIX: &str = "pam://";

/// systemd-homed (FIDO2 home directory unlock) and systemd-cryptenroll / systemd-cryptsetup (LUKS
/// volume unlock) use fixed ids of their own.
const EXACT: [&str; 2] = ["io.systemd.home", "io.systemd.cryptsetup"];

/// Compared without regard to ASCII case. A custom pam-u2f `origin=` that is a plain host name
/// cannot be told from a web site and is not covered.
pub fn is_machine_login_rp_id(rp_id: &str) -> bool {
    rp_id
        .get(..PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(PREFIX))
        || EXACT.iter().any(|id| rp_id.eq_ignore_ascii_case(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_pam_systemd_home_and_cryptsetup() {
        for id in [
            "pam://laptop",
            "PAM://laptop",
            "pam://",
            "io.systemd.home",
            "IO.systemd.Home",
            "io.systemd.cryptsetup",
        ] {
            assert!(is_machine_login_rp_id(id), "{id}");
        }
    }

    #[test]
    fn leaves_everything_else_alone() {
        for id in [
            "pam:",
            "pam.example.com",
            "ssh:",
            "example.com",
            "systemd.home",
            "io.systemd.home.example.com",
            "myio.systemd.cryptsetup",
            "io.systemd.cryptsetup.",
            "io.systemd",
            "p\u{00E4}m://x",
            "\u{00E9}\u{00E9}\u{00E9}://",
            "",
        ] {
            assert!(!is_machine_login_rp_id(id), "{id:?}");
        }
    }
}
