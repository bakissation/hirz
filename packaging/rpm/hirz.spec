# hirz for Fedora. Builds offline from the two source tarballs of each GitHub Release, sources and
# vendored crates (docs/release.md); scripts/package-rpm.sh writes the same two from a checkout.
#   rpmbuild -ba hirz.spec                   plain cargo build (COPR, local)
#   rpmbuild -ba --with auditable hirz.spec  cargo auditable build (release workflow)

%global upstream_version 0.1.0
# AWS-LC is C code built by aws-lc-sys; Fedora's LTO flags are not meant for it.
%global _lto_cflags %{nil}
# The release profile strips the binaries, so there is no debug information to package.
%global debug_package %{nil}
# cargo-auditable embeds the dependency list in each binary; not packaged in Fedora, so off by default.
%bcond auditable 0

Name:           hirz
Version:        %{lua: print((string.gsub(rpm.expand("%{upstream_version}"), "-", "~")))}
Release:        1%{?dist}
Summary:        Passkey authenticator for Linux

# hirz is MIT OR Apache-2.0. The binaries statically link Rust crates: AWS-LC (aws-lc-sys)
# adds ISC, Apache-2.0, MIT and BSD-3-Clause parts, memchr is MIT OR Unlicense. They also embed
# the Public Suffix List (MPL-2.0) and the BIP-39 word list (MIT).
License:        (MIT OR Apache-2.0) AND Apache-2.0 AND BSD-3-Clause AND ISC AND MIT AND (MIT OR Unlicense) AND MPL-2.0
URL:            https://github.com/bakissation/hirz
Source0:        %{url}/releases/download/v%{upstream_version}/hirz-%{upstream_version}.tar.gz
Source1:        %{url}/releases/download/v%{upstream_version}/hirz-%{upstream_version}-vendor.tar.xz

ExclusiveArch:  x86_64 aarch64

BuildRequires:  cargo >= 1.88
BuildRequires:  rust >= 1.88
BuildRequires:  gcc
BuildRequires:  cmake
BuildRequires:  systemd-rpm-macros

Requires:       polkit
Requires:       zenity >= 4
Requires:       mozilla-filesystem
Recommends:     fprintd
Suggests:       xdg-native-messaging-proxy

%description
hirz keeps your passkeys (WebAuthn / FIDO2) in an encrypted vault folder that
your own folder sync can copy between your computers. It appears to browsers
as a USB security key, so it works in Firefox and Chromium, and offers a
Firefox extension as a second path. Every signature needs your approval: your
account password through polkit, your fingerprint through fprintd, or a hirz
PIN.

%prep
%autosetup -n hirz-%{upstream_version} -a 1
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

%build
# rust-toolchain.toml pins a rustup toolchain; the distribution compiler is used instead.
rm -f rust-toolchain.toml
export CARGO_HOME=$PWD/.cargo-home
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_STRIP=symbols
export RUSTFLAGS="--remap-path-prefix=$PWD=/build/hirz"
%if %{with auditable}
cargo auditable build --release --locked --frozen --offline \
  -p hirz-cli -p hirzd -p hirz-nmh -p hirz-uhid-broker
%else
cargo build --release --locked --frozen --offline \
  -p hirz-cli -p hirzd -p hirz-nmh -p hirz-uhid-broker
%endif

%install
install -Dm0755 target/release/hirz %{buildroot}%{_bindir}/hirz
install -Dm0755 target/release/hirzd %{buildroot}%{_bindir}/hirzd
install -Dm0755 target/release/hirz-nmh %{buildroot}%{_prefix}/lib/hirz/hirz-nmh
install -Dm0755 target/release/hirz-uhid-broker %{buildroot}%{_libexecdir}/hirz/hirz-uhid-broker

install -d %{buildroot}%{_unitdir} %{buildroot}%{_userunitdir}
sed -E 's#^ExecStart=[^ ]*/hirz-uhid-broker( |$)#ExecStart=%{_libexecdir}/hirz/hirz-uhid-broker\1#' \
  packaging/systemd/hirz-uhid-broker.service > %{buildroot}%{_unitdir}/hirz-uhid-broker.service
grep -qx 'ExecStart=%{_libexecdir}/hirz/hirz-uhid-broker' %{buildroot}%{_unitdir}/hirz-uhid-broker.service
install -m0644 packaging/systemd/hirz-uhid-broker.socket %{buildroot}%{_unitdir}/
sed -E 's#^ExecStart=[^ ]*/hirzd( |$)#ExecStart=%{_bindir}/hirzd\1#' \
  packaging/systemd/hirzd.service > %{buildroot}%{_userunitdir}/hirzd.service
grep -Eq '^ExecStart=%{_bindir}/hirzd( |$)' %{buildroot}%{_userunitdir}/hirzd.service

# Third-party package: presets enable the broker socket and, for every user, hirzd on install. A
# package inside Fedora would ask for entries in the distribution presets instead.
install -d %{buildroot}%{_presetdir} %{buildroot}%{_userpresetdir}
echo 'enable hirz-uhid-broker.socket' > %{buildroot}%{_presetdir}/80-hirz.preset
echo 'enable hirzd.service' > %{buildroot}%{_userpresetdir}/80-hirz.preset

install -Dm0644 packaging/udev/70-hirz.rules %{buildroot}%{_udevrulesdir}/70-hirz.rules
install -Dm0644 packaging/udev/72-hirz.rules %{buildroot}%{_udevrulesdir}/72-hirz.rules
install -Dm0644 packaging/udev/99-zzz-hirz.rules %{buildroot}%{_udevrulesdir}/99-zzz-hirz.rules
install -Dm0644 packaging/polkit/dev.hirz.authenticate.policy \
  %{buildroot}%{_datadir}/polkit-1/actions/dev.hirz.authenticate.policy
install -Dm0644 assets/brand/hirz-app-icon.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/hirz.svg
install -Dm0644 assets/brand/app-icon-256.png %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/hirz.png
install -d %{buildroot}%{_modulesloaddir}
echo uhid > %{buildroot}%{_modulesloaddir}/hirz.conf

# Firefox on Fedora reads /usr/lib64/mozilla; the portal and proxy also read /usr/lib. The second
# path is a relative symlink: rpmbuild would hardlink identical files across file systems.
manifest_dir=%{_prefix}/lib/mozilla/native-messaging-hosts
install -d %{buildroot}$manifest_dir
sed 's#@HIRZ_NMH_PATH@#%{_prefix}/lib/hirz/hirz-nmh#' packaging/native-messaging/hirz.json \
  > %{buildroot}$manifest_dir/hirz.json
grep -q '"path": "%{_prefix}/lib/hirz/hirz-nmh"' %{buildroot}$manifest_dir/hirz.json
%if "%{_libdir}" != "%{_prefix}/lib"
install -d %{buildroot}%{_libdir}/mozilla/native-messaging-hosts
ln -s ../../../lib/mozilla/native-messaging-hosts/hirz.json \
  %{buildroot}%{_libdir}/mozilla/native-messaging-hosts/hirz.json
%endif

install -Dm0644 -t %{buildroot}%{_mandir}/man1 docs/man/hirz.1 docs/man/hirzd.1 docs/man/hirz-nmh.1
install -Dm0644 -t %{buildroot}%{_mandir}/man8 docs/man/hirz-uhid-broker.8

%check
cargo test --release --locked --frozen --offline --workspace

%post
%systemd_post hirz-uhid-broker.socket hirz-uhid-broker.service
%systemd_user_post hirzd.service
%udev_rules_update
modprobe uhid >/dev/null 2>&1 || :
if [ $1 -eq 1 ] && [ -d /run/systemd/system ]; then
  if systemctl is-enabled --quiet hirz-uhid-broker.socket; then
    systemctl start hirz-uhid-broker.socket || :
  fi
  # hirzd has Requisite=graphical-session.target, so it starts only in a graphical session.
  for dir in /run/user/*; do
    [ -d "$dir" ] || continue
    user=$(getent passwd "${dir##*/}" | cut -d: -f1)
    [ -n "$user" ] || continue
    systemctl --user --machine="$user@.host" daemon-reload >/dev/null 2>&1 || continue
    state=$(systemctl --user --machine="$user@.host" is-enabled hirzd.service 2>/dev/null || :)
    if [ "$state" = enabled ]; then
      systemctl --user --machine="$user@.host" start --no-block hirzd.service >/dev/null 2>&1 || :
    fi
  done
  echo "hirz is installed and starts with every desktop session."
  echo "The first time a site asks for a passkey, hirz opens a setup window."
  echo "To set it up in a terminal instead, run: hirz init"
fi

%preun
%systemd_preun hirz-uhid-broker.socket hirz-uhid-broker.service
%systemd_user_preun hirzd.service

%postun
%systemd_postun_with_restart hirz-uhid-broker.service
%systemd_user_postun_with_restart hirzd.service
%udev_rules_update

%files
%license LICENSE-MIT LICENSE-APACHE LICENSES/MPL-2.0.txt crates/hirz-vault/data/LICENSE-BIP39
%doc README.md SECURITY.md docs/install.md
%{_bindir}/hirz
%{_bindir}/hirzd
%dir %{_prefix}/lib/hirz
%{_prefix}/lib/hirz/hirz-nmh
%dir %{_libexecdir}/hirz
%{_libexecdir}/hirz/hirz-uhid-broker
%{_unitdir}/hirz-uhid-broker.service
%{_unitdir}/hirz-uhid-broker.socket
%{_userunitdir}/hirzd.service
%{_presetdir}/80-hirz.preset
%{_userpresetdir}/80-hirz.preset
%{_udevrulesdir}/70-hirz.rules
%{_udevrulesdir}/72-hirz.rules
%{_udevrulesdir}/99-zzz-hirz.rules
%{_datadir}/polkit-1/actions/dev.hirz.authenticate.policy
%{_datadir}/icons/hicolor/scalable/apps/hirz.svg
%{_datadir}/icons/hicolor/256x256/apps/hirz.png
%{_modulesloaddir}/hirz.conf
%{_mandir}/man1/hirz.1*
%{_mandir}/man1/hirzd.1*
%{_mandir}/man1/hirz-nmh.1*
%{_mandir}/man8/hirz-uhid-broker.8*
%{_prefix}/lib/mozilla/native-messaging-hosts/hirz.json
%if "%{_libdir}" != "%{_prefix}/lib"
%{_libdir}/mozilla/native-messaging-hosts/hirz.json
%endif

%changelog
* Mon Nov 16 2026 Abdelbaki Berkati <bakissation@users.noreply.github.com> - 0.1.0~dev-1
- First package
