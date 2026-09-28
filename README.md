# gaze-fido

Experimental Linux CTAP2 authenticator that exposes a virtual FIDO2 security key over UHID. It uses Gaze face verification for user presence and verification, and TPM 2.0 protected P-256 keys for WebAuthn credentials.

## What works

- Linux UHID virtual FIDO HID device and CTAP HID framing.
- CTAP2 `getInfo`, passkey registration, and assertion handling through the CTAP implementation.
- Discoverable credentials, so browsers can use the authenticator as a passkey.
- TPM-generated ES256 keys; userspace stores only the TPM-wrapped private blob and public credential metadata.
- Fresh Gaze verification is required for registration and every assertion signature. UV grants are one-shot; CTAP continuation signatures perform a new Gaze check.
- Local CBOR credential store under `$XDG_DATA_HOME/gaze-fido/credentials.cbor` or `~/.local/share/gaze-fido/credentials.cbor`, with a private directory and file mode.
- Linux desktop companion with a foreground Gaze verification prompt and local passkey listing/deletion.

The browser sees a cross-platform/security-key authenticator. It is not exposed as a native Linux platform authenticator, and credentials do not sync to other devices. The companion must be running for authentication; the daemon fails closed when the desktop confirmation UI is disconnected. When several accounts exist for one relying party, the daemon asks for a selection in its controlling terminal.

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

Open a WebAuthn test site such as [webauthn.io](https://webauthn.io), choose a security key/external authenticator, then complete the Gaze check to register or use a passkey. Firefox registration and authentication have been exercised on webauthn.io. Support across browsers, relying parties, and desktop environments still needs broader validation.

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

## Repository layout

```text
src/
  authenticator/  CTAP configuration and persistent credential callbacks
  companion.rs    Per-user desktop UI socket and verification prompt broker
  transport/      Linux UHID device and CTAP HID loop
  uv/             Gaze D-Bus verification and one-shot signing gate
  tpm/            TPM P-256 key lifecycle and signature provider
docs/
  ARCHITECTURE.md
  THREAT_MODEL.md
  ROADMAP.md
ui/
  src/qml/Main.qml  Qt Quick desktop verification prompt and local credential manager
```
