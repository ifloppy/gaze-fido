# Roadmap

## Current status

The Linux daemon, CTAP2/UHID path, mandatory Gaze UV callbacks, TPM P-256 provider, local discoverable-credential store, and Qt desktop companion are implemented. Firefox registration and authentication have succeeded on webauthn.io. The companion has a tray manager and a separate topmost Gaze prompt; support across desktop environments and relying parties still needs broader validation.

## M0 — Project skeleton

Complete: Rust module boundaries, threat model, local Gaze D-Bus verifier, and backend interfaces.

## M1 — Local capability integration

- [x] Inspect and implement the Gaze D-Bus verifier.
- [x] Add a TPM P-256 create/sign/verify startup probe.
- [x] Add Linux UHID device creation and CTAP HID packet handling.
- [ ] Live-run the TPM probe and virtual device with the intended user permissions.

## M2 — Minimal CTAP2 authenticator

- [x] CTAP HID initialization and packet framing.
- [x] `authenticatorGetInfo`, `makeCredential`, and `getAssertion` through the CTAP implementation.
- [x] ES256 COSE public keys and TPM DER signatures.
- [x] User-presence/user-verification flags gated by fresh Gaze checks.
- [x] Discoverable passkey metadata persistence.
- [x] Register and authenticate a passkey in Firefox with webauthn.io.
- [ ] Validate registration and authentication in Chromium and other relying parties.

## M3 — Passkey usability

- [x] Discoverable credentials and resident-key metadata.
- [x] Terminal account selection when a relying party has multiple passkeys.
- [x] Cancel an active Gaze check from the desktop companion.
- [x] Local credential listing and deletion tooling.
- [x] User systemd service and udev permissions for the active desktop session.
- [ ] Concurrent request handling and suspend/resume.
- [ ] Validate behavior across Chromium and Firefox versions.

## M4 — Hardening

- [ ] Fuzz CTAP/CBOR parsing and run protocol conformance checks.
- [ ] Negative checks for stale/replayed UV and failure-path credential persistence.
- [x] Atomic metadata updates and restricted file permissions.
- [x] Arch package recipe for local builds.
- [ ] Rate limits, lockout policy, AUR publication, and independent security review.

## Deferred

- Browser-native platform authenticator integration.
- Attestation beyond self/none.
- ClientPIN fallback; Gaze is the required UV method.
- Credential sync between devices.
