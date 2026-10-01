Gaze FIDO v0.1.1 is an experimental maintenance release. It requires a TPM 2.0 device and the Gaze D-Bus service. The project is not suitable for irreplaceable credentials; see the included threat model.

### What's changed

- Add a tray menu to show the management window or quit the desktop companion.
- Add a persistent setting to hide the tray icon while keeping the companion running.
- Prevent duplicate companion windows when the application is launched more than once.
- Keep a new verification request from being canceled by the previous prompt's auto-close timer.

### x86_64 packages

- Arch Linux and compatible distributions: `gaze-fido-0.1.1-1-x86_64.pkg.tar.zst`
- Debian 13: `.deb` package
- Ubuntu 26.04 LTS: `.deb` package
- Fedora 44: `.rpm` package

The source archive includes all locked Cargo dependencies. Verify downloaded files with `SHA256SUMS`.

After installing any package, enable the daemon for the current user:

```sh
systemctl --user enable --now gaze-fido.service
```

The packages install a udev rule for the active desktop session. Gaze itself is a separate system dependency and must already be installed and enrolled for the current user.
