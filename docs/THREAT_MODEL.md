# Threat model

## Assets

- FIDO credential private keys
- RP/user-to-credential bindings
- authenticator state and credential metadata
- validity of the user-verification result
- integrity of CTAP requests and responses

## Initial attacker model

### Remote attacker / phishing site

WebAuthn RP ID and client-data validation performed by the browser plus authenticator credential binding should prevent a remote site from obtaining a valid assertion for a different RP.

### Local unprivileged process running as another account

Must not be able to invoke signing as though Gaze succeeded or tamper with credential state. Credential files are kept in a user-only directory. Processes running as the same user remain inside the user's trust boundary and may read or modify that user's files and control its processes.

### Local root / compromised kernel

The MVP does not claim to remain trustworthy against a fully compromised OS. TPM can keep raw private key material non-exportable, but privileged malware may still drive legitimate signing operations, replace the daemon, fake D-Bus responses, capture camera input, or alter userspace policy.

This limitation must remain explicit in documentation and marketing.

## Gaze-specific risks

- presentation/spoof attacks against face recognition;
- replay or substitution of camera frames;
- stale success reused for a later operation;
- another local service spoofing or proxying an expected D-Bus interface;
- TOCTOU between UV success and signing.

Mitigations:

- rely on Gaze liveness checks but treat them as a policy layer, not hardware attestation;
- validate the expected D-Bus destination/interface where available;
- bounded timeout and cancellation;
- one verification per signature; a one-shot UV grant is cleared at each CTAP command boundary;
- continuation assertion signatures trigger a fresh Gaze check because CTAP does not repeat its UV callback for `getNextAssertion`;
- no persistent UV cache;
- minimum practical delay between UV success and TPM operation.

## TPM-specific risks

- incorrect hierarchy/parent configuration makes keys less protected than intended;
- weak filesystem permissions expose metadata or wrapped blobs to tampering;
- TPM clear/reset destroys credential availability;
- a signing API accidentally becomes a generic attacker-controlled signing oracle.

The TPM provider is only wired into the authenticator's CTAP command path; it is not a general local signing service. The CTAP implementation is a third-party dependency and has not been independently audited as part of this project.
