<p align="center">
  <img src="assets/gaze-fido-icon.svg" alt="Gaze FIDO icon" width="144">
</p>

# gaze-fido — Linux virtual FIDO2 authenticator for WebAuthn passkeys

<p align="center">
  <strong>TPM-backed passkeys with Gaze face verification</strong><br>
  A local Linux security key for WebAuthn and CTAP2
</p>

<p align="center">
  <a href="https://github.com/ifloppy/gaze-fido/actions/workflows/release.yml"><img src="https://github.com/ifloppy/gaze-fido/actions/workflows/release.yml/badge.svg" alt="Linux release packages"></a>
  <a href="https://github.com/ifloppy/gaze-fido/releases"><img src="https://img.shields.io/github/v/release/ifloppy/gaze-fido?include_prereleases&sort=semver" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="AGPL-3.0 license"></a>
</p>

gaze-fido is an experimental Linux virtual FIDO2 authenticator and WebAuthn
security key. It exposes a CTAP2 authenticator over UHID, uses Gaze face
verification for user presence and verification, and keeps WebAuthn passkey
credentials protected by TPM 2.0 P-256 keys. The daemon and Qt desktop
companion are written in Rust and integrate with KDE and other Linux desktops.

Download an x86_64 package from the [GitHub Releases](https://github.com/ifloppy/gaze-fido/releases)
page, or build from this repository.

## Project status

| | |
| --- | --- |
| Current release | `v0.1.0` — experimental, x86_64 Linux packages |
| Tested end to end | Firefox registration and authentication on [webauthn.io](https://webauthn.io) |
| Desktop integration | Qt companion with tray manager and separate topmost Gaze prompt |
| Security boundary | TPM 2.0 protected keys, Gaze-gated signatures, fail-closed errors |
| License | [AGPL-3.0-only](LICENSE) |

The project is under active development. See the
[architecture](docs/ARCHITECTURE.md) and [threat model](docs/THREAT_MODEL.md)
before using it for important accounts.

## Features

- Linux UHID virtual FIDO HID device and CTAP HID framing.
- CTAP2 `getInfo`, passkey registration, and assertion handling through the CTAP implementation.
- Discoverable credentials, so browsers can use the authenticator as a passkey.
- TPM-generated ES256 keys; userspace stores only the TPM-wrapped private blob and public credential metadata.
- Fresh Gaze verification is required for registration and every assertion signature. UV grants are one-shot; CTAP continuation signatures perform a new Gaze check.
- Local CBOR credential store under `$XDG_DATA_HOME/gaze-fido/credentials.cbor` or `~/.local/share/gaze-fido/credentials.cbor`, with a private directory and file mode.
- Linux desktop companion with a foreground Gaze verification prompt and local passkey listing/deletion.

## Current limitations

The browser sees a cross-platform/security-key authenticator. It is not exposed
as a native Linux platform authenticator, and credentials do not synchronize to
other devices. The companion must be running for authentication; the daemon
fails closed when the desktop confirmation UI is disconnected. When several
accounts exist for one relying party, the daemon asks for a selection in its
controlling terminal.

## Requirements

- Linux with the UHID kernel interface available at `/dev/uhid`.
- A TPM 2.0 device reachable through `/dev/tpmrm0`.
- The Gaze D-Bus service running and the current Linux account enrolled in Gaze.
- Rust 1.91 or newer.
- Qt 6 with Qt Quick Controls 2 development files and a C++ compiler for the Rust desktop companion. KDE Plasma uses the installed KDE Qt Quick style when available.
- When running directly from the checkout, the account needs access to `/dev/tpmrm0` and `/dev/uhid`. The Arch package installs a udev `uaccess` rule that grants this access only to the active local desktop session.

## Binary packages

The GitHub Releases page provides x86_64 packages for these build targets:

| Distribution family | Build target | Package |
| --- | --- | --- |
| Arch Linux and compatible distributions such as CachyOS | Arch rolling | `.pkg.tar.zst` |
| Debian | Debian 13 (Trixie) | `.deb` |
| Ubuntu | Ubuntu 26.04 LTS | `.deb` |
| Fedora | Fedora 44 | `.rpm` |

Download the matching package from [Releases](https://github.com/ifloppy/gaze-fido/releases) and verify it against `SHA256SUMS`. These packages install the daemon, desktop companion, user systemd unit, autostart entry, and udev rule. They do not install Gaze itself. A working Gaze D-Bus service and TPM 2.0 device are required. After installation, enable the daemon for the current user with:

```sh
systemctl --user enable --now gaze-fido.service
```

The Arch PKGBUILD is for building from a source checkout; it is not currently an AUR recipe.

## Run

### Install the local Arch package

The repository includes a PKGBUILD for building a package from this checkout:

```sh
cargo fetch --locked
cd packaging/arch
makepkg -si
systemctl --user enable --now gaze-fido.service
```

The package installs the daemon, Qt companion, a desktop launcher, a desktop
autostart entry, and a user systemd service. Its udev rule grants the active
local desktop session access to `/dev/tpmrm0` and `/dev/uhid`. The companion
opens on desktop login; the daemon starts with `graphical-session.target`.

### Run from the checkout

Start the daemon as the enrolled desktop user:

```sh
cargo run --release
```

In another terminal, start the desktop companion:

```sh
cargo run --release -p gaze-fido-ui
```

Keep the companion open while using the authenticator. It displays the requesting website and Gaze result, lets you cancel a pending check, and lists/deletes credentials stored on this computer. Deleting a local credential does not remove its corresponding entry from the website account. The Unix control socket is restricted to the current user and lives at `$XDG_RUNTIME_DIR/gaze-fido/control.sock`.

Configuration:

- `GAZE_FIDO_TCTI` selects the TPM TCTI string; defaults to `device:/dev/tpmrm0`.
- `GAZE_FIDO_DATA_DIR` selects the directory for `credentials.cbor`.
- `XDG_DATA_HOME` selects the normal data root when `GAZE_FIDO_DATA_DIR` is not set.

The daemon fails closed if it cannot reach Gaze, open the TPM, create and sign with a TPM P-256 probe key, open UHID, or load the credential store. There is no software-key fallback or authenticator PIN fallback.

To try it, open [webauthn.io](https://webauthn.io), choose a security key/external authenticator, and complete the Gaze prompt during registration or sign-in.

## Compatibility

| Component | Current coverage |
| --- | --- |
| Browser | Firefox registration and authentication tested on webauthn.io; Chromium and additional relying parties still need validation |
| Transport | Linux UHID virtual authenticator exposed as an external security key |
| Desktop | Qt 6 companion; KDE Plasma styling is supported when the KDE Qt style is installed |
| Distribution | x86_64 packages for Arch Linux, Debian 13, Ubuntu 26.04, and Fedora 44 |

## Security boundary

TPM credential private scalars are created and used inside the TPM. Credential files contain public metadata and TPM-wrapped key blobs, not plaintext private scalars. Gaze verification gates signing but is not hardware-attested, and this design does not claim resistance to a compromised kernel or local root.

The project is experimental and is not yet suitable for irreplaceable production credentials. See [the threat model](docs/THREAT_MODEL.md) for details.

## Dependency license

Gaze FIDO is distributed under [AGPL-3.0](LICENSE), matching the license of its CTAP2 implementation dependency [`soft-fido2`](https://github.com/pando85/soft-fido2). Release packages include the license and a source archive with the locked Cargo dependencies vendored.

## Development

```sh
cargo fmt --check
cargo check
cargo test
```

## Reporting issues

For compatibility and bug reports, include the desktop environment, browser
version, relying party, package version, and relevant redacted service logs.
Never post credential IDs, TPM blobs, face data, or other sensitive material.
The repository does not currently have a private vulnerability reporting
channel. Do not publish unpatched vulnerability details in a public issue.

## Repository layout

```text
assets/
  gaze-fido-icon.svg
src/
  authenticator/  CTAP configuration and persistent credential callbacks
  companion.rs    Per-user desktop UI socket and verification prompt broker
  transport/      Linux UHID device and CTAP HID loop
  uv/             Gaze D-Bus verification and one-shot signing gate
  tpm/            TPM P-256 key lifecycle and signature provider
docs/
  ARCHITECTURE.md
  THREAT_MODEL.md
ui/
  src/qml/Main.qml  Qt Quick desktop verification prompt and local credential manager
```
