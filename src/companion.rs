//! Per-user companion UI control socket and verification prompt broker.

use crate::authenticator::store::{CredentialManagementRecord, CredentialStore};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf},
    net::{UnixListener, UnixStream},
    sync::{Mutex, broadcast, oneshot},
};

const MAX_CONTROL_LINE: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct PromptContext {
    pub operation: String,
    pub rp_id: Option<String>,
    pub account: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum CompanionEvent {
    Ready,
    VerificationRequested {
        request_id: String,
        operation: String,
        rp_id: Option<String>,
        account: Option<String>,
    },
    VerificationFinished {
        request_id: String,
        result: String,
    },
}

pub struct PromptLease {
    pub request_id: String,
    pub cancelled: oneshot::Receiver<()>,
}

pub struct PromptBroker {
    events: broadcast::Sender<CompanionEvent>,
    active: Mutex<HashMap<String, oneshot::Sender<()>>>,
    next_id: AtomicU64,
}

impl PromptBroker {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(32);
        Self {
            events,
            active: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    pub async fn begin(&self, context: PromptContext) -> Result<PromptLease, String> {
        if self.events.receiver_count() == 0 {
            return Err("Gaze FIDO desktop companion is not connected".into());
        }

        let request_id = format!("{:016x}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let (cancel_sender, cancelled) = oneshot::channel();
        self.active
            .lock()
            .await
            .insert(request_id.clone(), cancel_sender);

        let event = CompanionEvent::VerificationRequested {
            request_id: request_id.clone(),
            operation: context.operation,
            rp_id: context.rp_id,
            account: context.account,
        };
        if self.events.send(event).is_err() {
            self.active.lock().await.remove(&request_id);
            return Err("Gaze FIDO desktop companion disconnected".into());
        }

        Ok(PromptLease {
            request_id,
            cancelled,
        })
    }

    pub async fn finish(&self, request_id: &str, result: &str) {
        self.active.lock().await.remove(request_id);
        let _ = self.events.send(CompanionEvent::VerificationFinished {
            request_id: request_id.to_owned(),
            result: result.to_owned(),
        });
    }

    async fn cancel(&self, request_id: &str) -> bool {
        let sender = self.active.lock().await.remove(request_id);
        sender.is_some_and(|sender| sender.send(()).is_ok())
    }

    async fn cancel_all(&self) {
        let active = std::mem::take(&mut *self.active.lock().await);
        for (_, sender) in active {
            let _ = sender.send(());
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<CompanionEvent> {
        self.events.subscribe()
    }
}

impl Default for PromptBroker {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CompanionServer {
    socket_path: PathBuf,
    credential_store: CredentialStore,
    prompts: Arc<PromptBroker>,
}

impl CompanionServer {
    pub fn from_environment(
        credential_store: CredentialStore,
        prompts: Arc<PromptBroker>,
    ) -> io::Result<Self> {
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "XDG_RUNTIME_DIR is required for the desktop companion socket",
                )
            })?;
        Ok(Self {
            socket_path: runtime_dir.join("gaze-fido").join("control.sock"),
            credential_store,
            prompts,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn serve(self: Arc<Self>) -> io::Result<()> {
        let parent = self
            .socket_path
            .parent()
            .ok_or_else(|| io::Error::other("control socket has no parent directory"))?;
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;

        match std::fs::symlink_metadata(&self.socket_path) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                if UnixStream::connect(&self.socket_path).await.is_ok() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "another gaze-fido control socket is active",
                    ));
                }
                std::fs::remove_file(&self.socket_path)?;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing to replace a non-socket control path",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600))?;
        eprintln!(
            "Desktop companion control socket ready at {}",
            self.socket_path.display()
        );

        loop {
            let (stream, _) = listener.accept().await?;
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(error) = server.handle(stream).await {
                    eprintln!("Desktop companion request failed: {error}");
                }
            });
        }
    }

    async fn handle(&self, stream: UnixStream) -> io::Result<()> {
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let request = read_request(&mut reader).await?;

        match request {
            ControlRequest::Subscribe => self.subscribe(reader, write_half).await,
            ControlRequest::ListCredentials => {
                let credentials = self
                    .credential_store
                    .management_records()
                    .map_err(|error| io::Error::other(error.to_string()))?;
                write_json_line(
                    &mut write_half,
                    &CredentialsResponse {
                        ok: true,
                        credentials,
                    },
                )
                .await
            }
            ControlRequest::DeleteCredential { token } => {
                let deleted = self
                    .credential_store
                    .delete_by_management_token(&token)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                write_json_line(&mut write_half, &DeleteResponse { ok: true, deleted }).await
            }
            ControlRequest::Cancel { request_id } => {
                let cancelled = self.prompts.cancel(&request_id).await;
                write_json_line(
                    &mut write_half,
                    &CancelResponse {
                        ok: true,
                        cancelled,
                    },
                )
                .await
            }
        }
    }

    async fn subscribe(
        &self,
        mut reader: BufReader<ReadHalf<UnixStream>>,
        mut writer: WriteHalf<UnixStream>,
    ) -> io::Result<()> {
        let mut events = self.prompts.subscribe();
        write_json_line(&mut writer, &CompanionEvent::Ready).await?;

        loop {
            let mut line = String::new();
            tokio::select! {
                event = events.recv() => match event {
                    Ok(event) => write_json_line(&mut writer, &event).await?,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                read = reader.read_line(&mut line) => {
                    match read {
                        Ok(0) => break,
                        Ok(_) if line.len() > MAX_CONTROL_LINE => break,
                        Ok(_) => match serde_json::from_str::<ControlRequest>(&line) {
                            Ok(ControlRequest::Cancel { request_id }) => {
                                let cancelled = self.prompts.cancel(&request_id).await;
                                write_json_line(&mut writer, &CancelResponse { ok: true, cancelled }).await?;
                            }
                            _ => write_json_line(&mut writer, &ErrorResponse {
                                ok: false,
                                error: "unsupported request on event stream".into(),
                            }).await?,
                        },
                        Err(error) => return Err(error),
                    }
                }
            }
        }

        self.prompts.cancel_all().await;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ControlRequest {
    Subscribe,
    ListCredentials,
    DeleteCredential { token: String },
    Cancel { request_id: String },
}

#[derive(Serialize)]
struct CredentialsResponse {
    ok: bool,
    credentials: Vec<CredentialManagementRecord>,
}

#[derive(Serialize)]
struct DeleteResponse {
    ok: bool,
    deleted: bool,
}

#[derive(Serialize)]
struct CancelResponse {
    ok: bool,
    cancelled: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    ok: bool,
    error: String,
}

async fn read_request<R>(reader: &mut BufReader<R>) -> io::Result<ControlRequest>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line = String::new();
    let bytes = reader
        .take(MAX_CONTROL_LINE as u64)
        .read_line(&mut line)
        .await?;
    if bytes == 0 || bytes > MAX_CONTROL_LINE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty or oversized control request",
        ));
    }
    serde_json::from_str(&line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

async fn write_json_line<W, T>(writer: &mut W, value: &T) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await
}
