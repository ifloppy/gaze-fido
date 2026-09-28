//! TPM-backed ES256 credential keys.
//!
//! TPM contexts stay on a dedicated worker thread. CTAP receives only a
//! versioned opaque encoding of TPM-wrapped key material and never sees a
//! credential private scalar.

use crate::uv::{UvError, VerificationGate};
use sha2::{Digest as _, Sha256};
use soft_fido2::{
    CredentialKey, CredentialKeyError, CredentialKeyProvider, CredentialKeyProviderId,
    GeneratedCredentialKey,
};
use soft_fido2_ctap::SecBytes;
use std::{
    fmt,
    str::FromStr,
    sync::{Arc, mpsc},
    thread,
};
use tss_esapi::{
    TctiNameConf,
    abstraction::transient::{KeyMaterial, KeyParams, TransientKeyContext},
    interface_types::{algorithm::HashingAlgorithm, ecc::EccCurve},
    structures::{Digest, EccScheme, HashScheme, Signature},
    utils::PublicKey,
};

const PROVIDER_ID: &[u8] = b"gaze-tpm-p256-v1";
const KEY_FORMAT_VERSION: u16 = 1;
const MAX_KEY_BLOB_SIZE: usize = 8192;

type WorkerResult<T> = Result<T, TpmError>;
type KeyMaterialReply = mpsc::Sender<WorkerResult<(Vec<u8>, Vec<u8>)>>;
type SignatureReply = mpsc::Sender<WorkerResult<Vec<u8>>>;

enum TpmRequest {
    Generate(KeyMaterialReply),
    Sign {
        key_blob: Vec<u8>,
        message: Vec<u8>,
        reply: SignatureReply,
    },
    Shutdown,
}

/// Opaque credential-key handle used by the small orchestration API.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialKeyHandle(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmError {
    KeyNotFound,
    SigningFailed(String),
    BackendUnavailable(String),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotFound => write!(f, "credential key not found"),
            Self::SigningFailed(reason) => write!(f, "TPM signing failed: {reason}"),
            Self::BackendUnavailable(reason) => write!(f, "TPM backend unavailable: {reason}"),
        }
    }
}

impl std::error::Error for TpmError {}

/// Signing interface for callers that need a narrow TPM boundary.
pub trait CredentialSigner {
    fn sign_p256(&self, key: &CredentialKeyHandle, message: &[u8]) -> Result<Vec<u8>, TpmError>;
}

/// A credential-key provider whose signing keys are generated and used by TPM 2.0.
pub struct TpmCredentialKeyProvider {
    sender: mpsc::Sender<TpmRequest>,
    verification_gate: Arc<VerificationGate>,
}

impl TpmCredentialKeyProvider {
    /// Start the TPM worker, open the configured TCTI, and verify P-256 signing.
    pub fn new(
        tcti: impl Into<String>,
        verification_gate: Arc<VerificationGate>,
    ) -> WorkerResult<Self> {
        let tcti = tcti.into();
        let (sender, receiver) = mpsc::channel();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);

        thread::Builder::new()
            .name("gaze-fido-tpm".into())
            .spawn(move || {
                let context_result = open_context(&tcti).and_then(|mut context| {
                    probe_signing(&mut context)?;
                    Ok(context)
                });

                let mut context = match context_result {
                    Ok(context) => {
                        let _ = ready_sender.send(Ok(()));
                        context
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(error.to_string()));
                        return;
                    }
                };

                while let Ok(request) = receiver.recv() {
                    match request {
                        TpmRequest::Generate(reply) => {
                            let _ = reply.send(generate_key(&mut context));
                        }
                        TpmRequest::Sign {
                            key_blob,
                            message,
                            reply,
                        } => {
                            let _ = reply.send(sign_message(&mut context, &key_blob, &message));
                        }
                        TpmRequest::Shutdown => break,
                    }
                }
            })
            .map_err(|error| TpmError::BackendUnavailable(format!("start TPM worker: {error}")))?;

        match ready_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                sender,
                verification_gate,
            }),
            Ok(Err(reason)) => Err(TpmError::BackendUnavailable(reason)),
            Err(error) => Err(TpmError::BackendUnavailable(format!(
                "TPM worker exited during startup: {error}"
            ))),
        }
    }

    fn generate_from_tpm(&self) -> WorkerResult<(Vec<u8>, Vec<u8>)> {
        let (reply, result) = mpsc::channel();
        self.sender
            .send(TpmRequest::Generate(reply))
            .map_err(|error| TpmError::BackendUnavailable(format!("send TPM request: {error}")))?;
        result
            .recv()
            .map_err(|error| TpmError::BackendUnavailable(format!("receive TPM result: {error}")))?
    }

    fn sign_with_tpm(&self, key_blob: &[u8], message: &[u8]) -> WorkerResult<Vec<u8>> {
        let (reply, result) = mpsc::channel();
        self.sender
            .send(TpmRequest::Sign {
                key_blob: key_blob.to_vec(),
                message: message.to_vec(),
                reply,
            })
            .map_err(|error| TpmError::BackendUnavailable(format!("send TPM request: {error}")))?;
        result
            .recv()
            .map_err(|error| TpmError::BackendUnavailable(format!("receive TPM result: {error}")))?
    }
}

impl Drop for TpmCredentialKeyProvider {
    fn drop(&mut self) {
        let _ = self.sender.send(TpmRequest::Shutdown);
    }
}

impl CredentialKeyProvider for TpmCredentialKeyProvider {
    fn provider_id(&self) -> CredentialKeyProviderId {
        CredentialKeyProviderId::new(PROVIDER_ID)
    }

    fn supports_algorithm(&self, algorithm: i32) -> bool {
        algorithm == -7
    }

    fn generate(&self, algorithm: i32) -> Result<GeneratedCredentialKey, CredentialKeyError> {
        if !self.supports_algorithm(algorithm) {
            return Err(CredentialKeyError::UnsupportedAlgorithm);
        }

        let (key_blob, public_key) = self.generate_from_tpm().map_err(map_tpm_error)?;
        if key_blob.len() > MAX_KEY_BLOB_SIZE {
            return Err(CredentialKeyError::InvalidKeyMaterial);
        }

        Ok(GeneratedCredentialKey {
            key: CredentialKey::new(
                self.provider_id(),
                KEY_FORMAT_VERSION,
                SecBytes::from_slice(&key_blob),
            ),
            // soft-fido2 0.17.0's makeCredential path expects uncompressed
            // SEC1 bytes here and constructs the COSE_Key response itself.
            cose_public_key: public_key,
        })
    }

    fn sign(
        &self,
        key: &CredentialKey,
        algorithm: i32,
        message: &[u8],
    ) -> Result<Vec<u8>, CredentialKeyError> {
        if algorithm != -7 {
            return Err(CredentialKeyError::UnsupportedAlgorithm);
        }
        if key.provider.as_bytes() != PROVIDER_ID {
            return Err(CredentialKeyError::UnsupportedProvider);
        }
        if key.format_version != KEY_FORMAT_VERSION {
            return Err(CredentialKeyError::UnsupportedFormatVersion);
        }

        let key_blob = key.material.as_slice();
        if key_blob.is_empty() || key_blob.len() > MAX_KEY_BLOB_SIZE {
            return Err(CredentialKeyError::InvalidKeyMaterial);
        }

        self.verification_gate
            .authorize_signature()
            .map_err(map_uv_error)?;

        match self.sign_with_tpm(key_blob, message) {
            Ok(signature) => {
                eprintln!("TPM ES256 credential signature completed");
                Ok(signature)
            }
            Err(error) => {
                eprintln!("TPM ES256 credential signature failed: {error}");
                Err(map_tpm_error(error))
            }
        }
    }
}

fn key_params() -> KeyParams {
    KeyParams::Ecc {
        curve: EccCurve::NistP256,
        scheme: EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
    }
}

fn open_context(tcti: &str) -> WorkerResult<TransientKeyContext> {
    let tcti = TctiNameConf::from_str(tcti)
        .map_err(|error| TpmError::BackendUnavailable(format!("parse TCTI: {error}")))?;
    TransientKeyContext::builder()
        .with_tcti(tcti)
        .build()
        .map_err(|error| TpmError::BackendUnavailable(format!("initialize TPM context: {error}")))
}

fn probe_signing(context: &mut TransientKeyContext) -> WorkerResult<()> {
    let (material, auth) = context.create_key(key_params(), 0).map_err(|error| {
        TpmError::BackendUnavailable(format!("create TPM P-256 probe key: {error}"))
    })?;
    let message = b"gaze-fido TPM startup probe";
    let digest = Digest::try_from(Sha256::digest(message).to_vec()).map_err(|error| {
        TpmError::BackendUnavailable(format!("prepare TPM probe digest: {error}"))
    })?;
    let signature = context
        .sign(material.clone(), key_params(), auth, digest.clone())
        .map_err(|error| {
            TpmError::BackendUnavailable(format!("TPM P-256 signing probe: {error}"))
        })?;
    context
        .verify_signature(material, key_params(), digest, signature)
        .map_err(|error| {
            TpmError::BackendUnavailable(format!("verify TPM P-256 probe: {error}"))
        })?;
    Ok(())
}

fn generate_key(context: &mut TransientKeyContext) -> WorkerResult<(Vec<u8>, Vec<u8>)> {
    let (material, _auth) = context.create_key(key_params(), 0).map_err(|error| {
        TpmError::BackendUnavailable(format!("create TPM credential key: {error}"))
    })?;
    let public_key = sec1_es256_public_key(material.public())?;
    let key_blob = serde_json::to_vec(&material)
        .map_err(|error| TpmError::BackendUnavailable(format!("encode TPM key blob: {error}")))?;
    Ok((key_blob, public_key))
}

fn sign_message(
    context: &mut TransientKeyContext,
    key_blob: &[u8],
    message: &[u8],
) -> WorkerResult<Vec<u8>> {
    let material: KeyMaterial =
        serde_json::from_slice(key_blob).map_err(|_| TpmError::KeyNotFound)?;
    let digest = Digest::try_from(Sha256::digest(message).to_vec())
        .map_err(|error| TpmError::SigningFailed(format!("prepare signature digest: {error}")))?;
    let signature = context
        .sign(material, key_params(), None, digest)
        .map_err(|error| TpmError::SigningFailed(error.to_string()))?;
    match signature {
        Signature::EcDsa(signature) => der_ecdsa_signature(
            signature.signature_r().value(),
            signature.signature_s().value(),
        ),
        other => Err(TpmError::SigningFailed(format!(
            "unexpected TPM signature type: {other:?}"
        ))),
    }
}

fn sec1_es256_public_key(public: &PublicKey) -> WorkerResult<Vec<u8>> {
    let (x, y) = match public {
        PublicKey::Ecc { x, y } => (p256_coordinate(x)?, p256_coordinate(y)?),
        PublicKey::Rsa(_) => {
            return Err(TpmError::BackendUnavailable(
                "TPM returned RSA for a P-256 credential".into(),
            ));
        }
    };

    // soft-fido2 converts this uncompressed SEC1 point into a COSE_Key.
    let mut encoded = Vec::with_capacity(65);
    encoded.push(0x04);
    encoded.extend_from_slice(&x);
    encoded.extend_from_slice(&y);
    Ok(encoded)
}

fn p256_coordinate(value: &[u8]) -> WorkerResult<[u8; 32]> {
    if value.is_empty() || value.len() > 32 {
        return Err(TpmError::BackendUnavailable(format!(
            "TPM returned a P-256 coordinate with invalid length {}",
            value.len()
        )));
    }
    let mut coordinate = [0; 32];
    coordinate[32 - value.len()..].copy_from_slice(value);
    Ok(coordinate)
}

fn der_ecdsa_signature(r: &[u8], s: &[u8]) -> WorkerResult<Vec<u8>> {
    let r = der_integer(r)?;
    let s = der_integer(s)?;
    let body_len = r.len() + s.len();
    if body_len > 127 {
        return Err(TpmError::SigningFailed(
            "ECDSA signature is too large for DER encoding".into(),
        ));
    }
    let mut encoded = Vec::with_capacity(body_len + 2);
    encoded.extend_from_slice(&[0x30, body_len as u8]);
    encoded.extend_from_slice(&r);
    encoded.extend_from_slice(&s);
    Ok(encoded)
}

fn der_integer(value: &[u8]) -> WorkerResult<Vec<u8>> {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .ok_or_else(|| TpmError::SigningFailed("TPM returned a zero ECDSA scalar".into()))?;
    let value = &value[first_nonzero..];
    let needs_positive_prefix = value[0] & 0x80 != 0;
    let length = value.len() + usize::from(needs_positive_prefix);
    if length > 127 {
        return Err(TpmError::SigningFailed(
            "ECDSA scalar is too large for DER encoding".into(),
        ));
    }

    let mut encoded = Vec::with_capacity(length + 2);
    encoded.extend_from_slice(&[0x02, length as u8]);
    if needs_positive_prefix {
        encoded.push(0);
    }
    encoded.extend_from_slice(value);
    Ok(encoded)
}

fn map_uv_error(error: UvError) -> CredentialKeyError {
    match error {
        UvError::Rejected | UvError::Cancelled => CredentialKeyError::AuthorizationDenied,
        UvError::Timeout => CredentialKeyError::Timeout,
        UvError::BackendUnavailable(reason) => CredentialKeyError::TransientFailure(reason),
    }
}

fn map_tpm_error(error: TpmError) -> CredentialKeyError {
    match error {
        TpmError::KeyNotFound => CredentialKeyError::KeyNotFound,
        TpmError::SigningFailed(reason) | TpmError::BackendUnavailable(reason) => {
            CredentialKeyError::TransientFailure(reason)
        }
    }
}
