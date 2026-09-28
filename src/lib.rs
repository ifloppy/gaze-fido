//! Core interfaces for gaze-fido.
//!
//! The MVP deliberately keeps CTAP transport, user verification, and TPM signing
//! behind separate interfaces so security-sensitive boundaries stay explicit.

pub mod authenticator;
pub mod companion;
pub mod tpm;
pub mod transport;
pub mod uv;
