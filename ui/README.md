# Gaze FIDO desktop companion

The companion is written in Rust and uses Qt Quick Controls through CXX-Qt. It
connects to the daemon over the user-only Unix socket at
`$XDG_RUNTIME_DIR/gaze-fido/control.sock`, manages passkeys in the local
credential store, and normally stays in the desktop system tray. Close the
management window to hide it to the tray; click the tray icon to show it again.
Use the exit action in the management window to quit the companion. During Gaze verification, a separate topmost window appears
without opening or raising the management window. If the desktop has no system
tray, the management window opens as a fallback. Controls follow Qt's active
desktop style; KDE Plasma uses the KDE Qt Quick style when installed.

Run it as the same desktop user as the daemon:

```sh
cargo run --release -p gaze-fido-ui
```

Build requirements are Rust 1.91+, Qt 6 with Qt Quick Controls 2 development
files, and a C++ compiler. If the Qt build tool is not auto-detected, set
`QMAKE` to the path of `qmake6` (for example, `QMAKE=/usr/bin/qmake6`).

The daemon and companion must both be running before a WebAuthn operation. If
the companion is disconnected, user verification fails closed. The management
page only deletes the local credential; remove its remote registration from
the website's account settings separately.
