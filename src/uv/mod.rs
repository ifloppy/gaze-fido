//! User-verification boundary.

use crate::companion::{PromptBroker, PromptContext};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::oneshot;
use zbus::{proxy, zvariant::Type};

const DEFAULT_VERIFY_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub verified: bool,
    pub method: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UvError {
    Rejected,
    Cancelled,
    Timeout,
    BackendUnavailable(String),
}

impl fmt::Display for UvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => write!(f, "user verification rejected"),
            Self::Cancelled => write!(f, "user verification cancelled"),
            Self::Timeout => write!(f, "user verification timed out"),
            Self::BackendUnavailable(reason) => {
                write!(f, "user verification backend unavailable: {reason}")
            }
        }
    }
}

impl std::error::Error for UvError {}

#[allow(async_fn_in_trait)]
pub trait UserVerifier {
    /// Perform a fresh user-verification ceremony for exactly one authenticator operation.
    /// Implementations must not turn a previous success into an unbounded session-wide cache.
    async fn verify(&self) -> Result<Verification, UvError>;
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Type, PartialEq, Eq)]
#[zvariant(signature = "s")]
#[serde(rename_all = "kebab-case")]
enum VerifyResult {
    VerifyMatch,
    VerifyNoMatch,
}

#[proxy(
    interface = "com.gundulabs.Gaze",
    default_service = "com.gundulabs.Gaze",
    default_path = "/com/gundulabs/Gaze"
)]
trait Gaze {
    async fn claim(&self, username: &str) -> zbus::Result<()>;
    async fn release(&self) -> zbus::Result<()>;
    async fn verify_start(&self, face_name: &str) -> zbus::Result<()>;
    async fn verify_stop(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn verify_status(
        &self,
        result: VerifyResult,
        faces: Vec<(String, f64, f64, bool, f64, f64, bool)>,
        rgb_status: String,
        ir_status: String,
    ) -> zbus::Result<()>;
}

#[derive(Debug, Clone)]
pub struct GazeVerifier {
    username: String,
    timeout: Duration,
}

impl GazeVerifier {
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            timeout: DEFAULT_VERIFY_TIMEOUT,
        }
    }

    pub fn with_timeout(username: impl Into<String>, timeout: Duration) -> Self {
        Self {
            username: username.into(),
            timeout,
        }
    }

    async fn stop_and_release(proxy: &GazeProxy<'_>) {
        let _ = proxy.verify_stop().await;
        let _ = proxy.release().await;
    }

    fn backend_error(context: &str, error: impl fmt::Display) -> UvError {
        UvError::BackendUnavailable(format!("{context}: {error}"))
    }
}

impl UserVerifier for GazeVerifier {
    async fn verify(&self) -> Result<Verification, UvError> {
        self.verify_with_cancel(None).await
    }
}

impl GazeVerifier {
    async fn verify_with_cancel(
        &self,
        cancelled: Option<oneshot::Receiver<()>>,
    ) -> Result<Verification, UvError> {
        let connection = zbus::Connection::system()
            .await
            .map_err(|error| Self::backend_error("connect to system D-Bus", error))?;
        let proxy = GazeProxy::new(&connection)
            .await
            .map_err(|error| Self::backend_error("connect to Gaze", error))?;

        proxy
            .claim(&self.username)
            .await
            .map_err(|error| Self::backend_error("claim Gaze verifier", error))?;

        let mut status_stream = match proxy.receive_verify_status().await {
            Ok(stream) => stream,
            Err(error) => {
                let _ = proxy.release().await;
                return Err(Self::backend_error(
                    "subscribe to Gaze verification status",
                    error,
                ));
            }
        };

        if let Err(error) = proxy.verify_start("any").await {
            let _ = proxy.release().await;
            return Err(Self::backend_error("start Gaze verification", error));
        }

        let status_wait = async {
            let signal = status_stream.next().await.ok_or_else(|| {
                UvError::BackendUnavailable(
                    "Gaze verification status stream closed before a verdict".into(),
                )
            })?;
            let args = signal
                .args()
                .map_err(|error| Self::backend_error("decode Gaze verification status", error))?;
            Ok::<VerifyResult, UvError>(*args.result())
        };
        let cancel_wait = async move {
            if let Some(cancelled) = cancelled {
                let _ = cancelled.await;
                Err(UvError::Cancelled)
            } else {
                std::future::pending::<Result<VerifyResult, UvError>>().await
            }
        };
        tokio::pin!(cancel_wait);
        let verdict = tokio::time::timeout(self.timeout, async {
            tokio::select! {
                result = status_wait => result,
                result = &mut cancel_wait => result,
            }
        })
        .await;

        let result = match verdict {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                Self::stop_and_release(&proxy).await;
                return Err(error);
            }
            Err(_) => {
                Self::stop_and_release(&proxy).await;
                return Err(UvError::Timeout);
            }
        };

        if let Err(error) = proxy.release().await {
            return Err(Self::backend_error("release Gaze verifier", error));
        }

        match result {
            VerifyResult::VerifyMatch => Ok(Verification {
                verified: true,
                method: "gaze-face",
            }),
            VerifyResult::VerifyNoMatch => Err(UvError::Rejected),
        }
    }
}

/// Bridges the asynchronous Gaze service to the synchronous CTAP callbacks.
///
/// A successful callback grants at most one following TPM signature. The CTAP
/// command handler clears the grant at the start of every command, and the TPM
/// provider consumes it before signing. Continuation commands such as
/// `getNextAssertion`, which do not invoke the UV callback again, perform a new
/// Gaze verification in the signing path.
pub struct VerificationGate {
    verifier: GazeVerifier,
    runtime: tokio::runtime::Runtime,
    prompts: Arc<PromptBroker>,
    signing_grant: AtomicBool,
}

impl VerificationGate {
    pub fn new(
        username: impl Into<String>,
        runtime: tokio::runtime::Runtime,
        prompts: Arc<PromptBroker>,
    ) -> Self {
        Self {
            verifier: GazeVerifier::new(username),
            runtime,
            prompts,
            signing_grant: AtomicBool::new(false),
        }
    }

    /// Clear any unfinished one-shot grant before a new CTAP command starts.
    pub fn begin_command(&self) {
        self.signing_grant.store(false, Ordering::SeqCst);
    }

    /// Perform a fresh Gaze check for user presence.
    pub fn verify_presence(&self) -> Result<(), UvError> {
        self.verify_presence_for("Verify", None, None)
    }

    pub fn verify_presence_for(
        &self,
        operation: &str,
        rp_id: Option<&str>,
        account: Option<&str>,
    ) -> Result<(), UvError> {
        self.verify_fresh(operation, rp_id, account).map(|_| ())
    }

    /// Perform a fresh Gaze check and grant one immediately following sign.
    pub fn verify_for_operation(&self) -> Result<(), UvError> {
        self.verify_for_operation_for("Verify and sign", None, None)
    }

    pub fn verify_for_operation_for(
        &self,
        operation: &str,
        rp_id: Option<&str>,
        account: Option<&str>,
    ) -> Result<(), UvError> {
        self.verify_fresh(operation, rp_id, account)?;
        self.signing_grant.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Consume a fresh verification or perform one when CTAP uses a continuation command.
    pub fn authorize_signature(&self) -> Result<(), UvError> {
        if self.signing_grant.swap(false, Ordering::SeqCst) {
            Ok(())
        } else {
            self.verify_fresh("Authorize TPM signature", None, None)
                .map(|_| ())
        }
    }

    fn verify_fresh(
        &self,
        operation: &str,
        rp_id: Option<&str>,
        account: Option<&str>,
    ) -> Result<Verification, UvError> {
        let context = PromptContext {
            operation: operation.to_owned(),
            rp_id: rp_id.map(str::to_owned),
            account: account.map(str::to_owned),
        };
        let verifier = &self.verifier;
        let prompts = &self.prompts;
        let verification = self.runtime.block_on(async move {
            let lease = prompts
                .begin(context)
                .await
                .map_err(UvError::BackendUnavailable)?;
            let result = verifier.verify_with_cancel(Some(lease.cancelled)).await;
            let result_name = match &result {
                Ok(_) => "verified",
                Err(UvError::Rejected) => "rejected",
                Err(UvError::Cancelled) => "cancelled",
                Err(UvError::Timeout) => "timeout",
                Err(UvError::BackendUnavailable(_)) => "error",
            };
            prompts.finish(&lease.request_id, result_name).await;
            result
        });

        match verification {
            Ok(verification) if verification.verified => {
                eprintln!("Gaze verification accepted ({})", verification.method);
                Ok(verification)
            }
            Ok(_) => {
                eprintln!("Gaze verification rejected the face match");
                Err(UvError::Rejected)
            }
            Err(error) => {
                eprintln!("Gaze verification failed: {error}");
                Err(error)
            }
        }
    }
}
