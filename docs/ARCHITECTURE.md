# Architecture

## Scope

The first release is a local Linux software authenticator exposed to browsers as a virtual USB/HID FIDO2 security key. It does not attempt browser-specific native platform-authenticator integration.

## Request flow

```text
WebAuthn request
      |
Browser FIDO stack
      |
/dev/uhid virtual HID device
      |
CTAP HID framing
      |
CTAP2 implementation
      |
validate request + select credential
      |
Gaze D-Bus -> face detection -> liveness -> identity match
      |
one-sign UV grant
      |
TPM 2.0 credential key sign/create
      |
CTAP2 response -> HID -> browser
```

## Components

### transport

Owns Linux UHID interaction and CTAP HID packet framing. It clears any unused UV grant before dispatching each CTAP CBOR command.

### authenticator

Uses `soft-fido2` for CTAP2 command handling, RP/user/credential validation, authenticator-data construction, counters, and response encoding. It supports ES256, advertises discoverable credentials and built-in UV, requires `alwaysUv`, disables ClientPIN, and disables credential-management commands.

### uv

Talks directly to the Gaze system D-Bus service. PAM is not part of the FIDO path. Each verification uses a strict timeout and returns a bounded result. A successful `request_uv` authorizes exactly one following TPM signature. `getNextAssertion` does not invoke the UV callback, so its signature path performs another Gaze check.

### tpm

Creates and loads credential P-256 keys and performs ECDSA signing. A dedicated worker thread owns the TPM context and serializes requests through one TCTI connection. It creates one probe key and verifies one signature before the UHID device starts.

- TPM primary parent is under the owner hierarchy.
- Each passkey gets a TPM child key with a fixed parent and non-exportable private scalar.
- Per-credential TPM public/private blobs are persisted; the private blob remains TPM-wrapped and unusable without its parent TPM.
- Userspace receives the public COSE key and DER-encoded TPM signatures, never the private scalar.

The implementation uses `tss-esapi` through `/dev/tpmrm0` by default. Clearing or replacing the TPM hierarchy makes the stored child key blobs unusable.

### credential metadata

Discoverable credentials require RP ID/name, user handle/name, credential ID, public key, signature counter, and TPM-wrapped key material. Records are stored as CBOR in `credentials.cbor` under the user's data directory. The directory is mode `0700`, the file is mode `0600`, and updates use a synced temporary file followed by atomic rename. Metadata is not encrypted; file permissions protect it from other unprivileged accounts.

## User-verification semantics

A Gaze success must not become an open-ended login session. The authenticator clears any unused grant at every CTAP command boundary; signing consumes a grant once. If a CTAP command reaches signing without invoking the built-in UV callback, the TPM provider performs fresh Gaze verification before signing.

## Browser-visible authenticator type

UHID exposes the normal CTAP HID path, so browsers classify this device as a security key / cross-platform authenticator. It is not a native Linux platform authenticator. Credentials remain on this TPM and do not sync to other devices.
