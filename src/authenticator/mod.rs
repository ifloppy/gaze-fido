//! Authenticator orchestration.
//!
//! Intended ordering: request validation -> fresh UV -> TPM operation -> response.

pub mod store;

use crate::tpm::{CredentialKeyHandle, CredentialSigner, TpmError};
use crate::uv::{UserVerifier, UvError, VerificationGate};
use crate::{authenticator::store::CredentialStore, tpm::TpmCredentialKeyProvider};
use soft_fido2::{Authenticator as CtapAuthenticator, AuthenticatorConfig, AuthenticatorOptions};
use soft_fido2_ctap::cbor::{self, MapParser, Value};
use soft_fido2_transport::{Cmd, CommandHandler, Error as TransportError};
use std::{collections::BTreeMap, sync::Arc};

/// CTAP command adapter that connects Linux UHID to the CTAP2 authenticator.
pub struct CtapCommandHandler {
    authenticator: CtapAuthenticator<CredentialStore, TpmCredentialKeyProvider>,
    credential_store: CredentialStore,
    verification_gate: Arc<VerificationGate>,
}

impl CtapCommandHandler {
    pub fn new(
        credential_store: CredentialStore,
        key_provider: TpmCredentialKeyProvider,
        verification_gate: Arc<VerificationGate>,
    ) -> Result<Self, soft_fido2::Error> {
        let options = AuthenticatorOptions::new()
            .with_user_verification(Some(true))
            .with_client_pin(None)
            .with_pin_uv_auth_token(Some(false))
            .with_always_uv(Some(true))
            .with_make_cred_uv_not_required(Some(false))
            .with_credential_management(Some(false))
            .with_biometric_enrollment(Some(false))
            .with_large_blobs(Some(false));
        let config = AuthenticatorConfig::builder()
            .aaguid([
                0x47, 0x41, 0x5a, 0x45, 0x2d, 0x46, 0x49, 0x44, 0x4f, 0x2d, 0x54, 0x50, 0x4d, 0x2d,
                0x30, 0x31,
            ])
            .algorithms(vec![-7])
            .max_credentials(100)
            .force_resident_keys(true)
            .device_name("Gaze FIDO2 TPM authenticator".into())
            .options(options)
            .build();
        let policy_store = credential_store.clone();
        let mut authenticator = CtapAuthenticator::with_config_and_key_provider(
            credential_store,
            config,
            key_provider,
        )?;
        authenticator.set_built_in_uv_configured(true)?;

        Ok(Self {
            authenticator,
            credential_store: policy_store,
            verification_gate,
        })
    }
}

impl CommandHandler for CtapCommandHandler {
    fn handle_command(&mut self, cmd: Cmd, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        if cmd != Cmd::Cbor {
            return Err(TransportError::InvalidCommand);
        }

        self.verification_gate.begin_command();
        let command = data.first().copied().unwrap_or(0xff);
        let mut adjusted_data = None;
        if command == 0x02 {
            let request = MapParser::from_bytes(data.get(1..).unwrap_or_default());
            match request {
                Ok(request) => {
                    let rp_id = request
                        .get_opt::<String>(1)
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let allow_list = match request.get_raw(3) {
                        None => "absent".to_owned(),
                        Some(Value::Array(entries)) => entries.len().to_string(),
                        Some(_) => "invalid".to_owned(),
                    };
                    let options = request
                        .get_opt::<std::collections::BTreeMap<String, bool>>(5)
                        .ok()
                        .flatten();
                    let up = options
                        .as_ref()
                        .and_then(|options| options.get("up"))
                        .copied()
                        .unwrap_or(true);
                    let uv = options
                        .as_ref()
                        .and_then(|options| options.get("uv"))
                        .copied()
                        .unwrap_or(false);
                    let allow_list_ids = match request.get_raw(3) {
                        None => None,
                        Some(Value::Array(entries)) => Some(
                            entries
                                .iter()
                                .filter_map(|entry| match entry {
                                    Value::Map(fields) => fields.iter().find_map(|(key, value)| {
                                        if matches!(key, Value::Text(name) if name == "id") {
                                            match value {
                                                Value::Bytes(id) => Some(id.clone()),
                                                _ => None,
                                            }
                                        } else {
                                            None
                                        }
                                    }),
                                    _ => None,
                                })
                                .collect::<Vec<_>>(),
                        ),
                        Some(_) => Some(Vec::new()),
                    };
                    let preflight_uv = !up
                        && !uv
                        && self
                            .credential_store
                            .preflight_requires_uv(&rp_id, allow_list_ids.as_deref());
                    if preflight_uv {
                        adjusted_data = promote_preflight_to_uv(data);
                        if adjusted_data.is_none() {
                            eprintln!(
                                "Could not set UV on matching CTAP preflight; forwarding original request"
                            );
                        }
                    }
                    eprintln!(
                        "GetAssertion request: rp_id={rp_id}, allow_list={allow_list} credential(s), up={up}, uv={uv}, preflight_uv_promoted={preflight_uv}",
                    );
                }
                Err(_) => eprintln!("GetAssertion request: could not decode CBOR parameters"),
            }
        }
        let mut response = Vec::new();
        match self
            .authenticator
            .handle(adjusted_data.as_deref().unwrap_or(data), &mut response)
        {
            Ok(_) => {
                let status = response.first().copied().unwrap_or(0xff);
                eprintln!("CTAP CBOR 0x{command:02x} returned status 0x{status:02x}");
                Ok(response)
            }
            Err(error) => {
                eprintln!("CTAP CBOR 0x{command:02x} failed: {error}");
                Err(TransportError::Other(format!(
                    "CTAP command failed: {error}"
                )))
            }
        }
    }
}

fn promote_preflight_to_uv(data: &[u8]) -> Option<Vec<u8>> {
    let (&command, encoded_parameters) = data.split_first()?;
    if command != 0x02 {
        return None;
    }

    let mut parameters: BTreeMap<i32, Value> = cbor::decode(encoded_parameters).ok()?;
    let options = parameters
        .entry(5)
        .or_insert_with(|| Value::Map(Vec::new()));
    let Value::Map(options) = options else {
        return None;
    };

    if let Some((_, value)) = options
        .iter_mut()
        .find(|(key, _)| matches!(key, Value::Text(name) if name == "uv"))
    {
        *value = Value::Bool(true);
    } else {
        options.push((Value::Text("uv".into()), Value::Bool(true)));
    }

    let mut adjusted = vec![command];
    cbor::into_writer(&parameters, &mut adjusted).ok()?;
    Some(adjusted)
}

#[derive(Debug)]
pub enum AuthenticatorError {
    Verification(UvError),
    Tpm(TpmError),
}

impl From<UvError> for AuthenticatorError {
    fn from(value: UvError) -> Self {
        Self::Verification(value)
    }
}

impl From<TpmError> for AuthenticatorError {
    fn from(value: TpmError) -> Self {
        Self::Tpm(value)
    }
}

pub struct Authenticator<U, S> {
    verifier: U,
    signer: S,
}

impl<U, S> Authenticator<U, S>
where
    U: UserVerifier,
    S: CredentialSigner,
{
    pub fn new(verifier: U, signer: S) -> Self {
        Self { verifier, signer }
    }

    /// Minimal security-ordering prototype.
    pub async fn verify_then_sign(
        &self,
        key: &CredentialKeyHandle,
        message: &[u8],
    ) -> Result<Vec<u8>, AuthenticatorError> {
        let verification = self.verifier.verify().await?;
        if !verification.verified {
            return Err(AuthenticatorError::Verification(UvError::Rejected));
        }

        Ok(self.signer.sign_p256(key, message)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uv::Verification;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct FakeVerifier {
        result: Result<Verification, UvError>,
    }

    impl UserVerifier for FakeVerifier {
        async fn verify(&self) -> Result<Verification, UvError> {
            self.result.clone()
        }
    }

    struct CountingSigner {
        calls: Arc<AtomicUsize>,
    }

    impl CredentialSigner for CountingSigner {
        fn sign_p256(
            &self,
            _key: &CredentialKeyHandle,
            _message: &[u8],
        ) -> Result<Vec<u8>, TpmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![0x30, 0x00])
        }
    }

    #[tokio::test]
    async fn rejected_uv_never_reaches_the_signer() {
        let calls = Arc::new(AtomicUsize::new(0));
        let authenticator = Authenticator::new(
            FakeVerifier {
                result: Err(UvError::Rejected),
            },
            CountingSigner {
                calls: Arc::clone(&calls),
            },
        );

        let result = authenticator
            .verify_then_sign(&CredentialKeyHandle(vec![1]), b"challenge")
            .await;

        assert!(matches!(
            result,
            Err(AuthenticatorError::Verification(UvError::Rejected))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn successful_uv_is_followed_by_exactly_one_sign() {
        let calls = Arc::new(AtomicUsize::new(0));
        let authenticator = Authenticator::new(
            FakeVerifier {
                result: Ok(Verification {
                    verified: true,
                    method: "test",
                }),
            },
            CountingSigner {
                calls: Arc::clone(&calls),
            },
        );

        let signature = authenticator
            .verify_then_sign(&CredentialKeyHandle(vec![1]), b"challenge")
            .await
            .expect("verified operation should sign");

        assert_eq!(signature, vec![0x30, 0x00]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
