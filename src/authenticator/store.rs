//! Permission-restricted persistence for discoverable passkeys.

use crate::uv::{UvError, VerificationGate};
use serde::Serialize;
use sha2::{Digest, Sha256};
use soft_fido2::{Credential, CredentialRef, Error, Result, UpResult, UvResult};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_CREDENTIALS: usize = 100;
const TPM_PROVIDER_ID: &[u8] = b"gaze-tpm-p256-v1";

#[derive(Debug, Clone, Serialize)]
pub struct CredentialManagementRecord {
    /// Opaque SHA-256 selector; the credential ID itself never leaves the daemon.
    pub token: String,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub created: i64,
    pub discoverable: bool,
    pub cred_protect: Option<u8>,
}

/// Credential records are user data; TPM-wrapped key blobs are not private scalars.
#[derive(Clone)]
pub struct CredentialStore {
    path: PathBuf,
    credentials: Arc<Mutex<BTreeMap<Vec<u8>, Credential>>>,
    verification_gate: Arc<VerificationGate>,
}

impl CredentialStore {
    pub fn open(
        path: impl Into<PathBuf>,
        verification_gate: Arc<VerificationGate>,
    ) -> Result<Self> {
        let path = path.into();
        let parent = path.parent().ok_or(Error::InitializationFailed)?;
        fs::create_dir_all(parent).map_err(Error::from)?;
        ensure_private_directory(parent)?;

        let credentials = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(Error::InitializationFailed);
                }
                set_mode(&path, 0o600)?;
                let bytes = fs::read(&path).map_err(Error::from)?;
                let records: Vec<Credential> =
                    soft_fido2_ctap::cbor::decode(&bytes).map_err(|_| Error::Other)?;
                let mut credentials = BTreeMap::new();
                for credential in records {
                    if credential.id.is_empty()
                        || credential.key.provider.as_bytes() != TPM_PROVIDER_ID
                        || credential.key.format_version != 1
                        || credentials
                            .insert(credential.id.clone(), credential)
                            .is_some()
                    {
                        return Err(Error::InitializationFailed);
                    }
                }
                if credentials.len() > MAX_CREDENTIALS {
                    return Err(Error::InitializationFailed);
                }
                credentials
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(Error::from(error)),
        };

        Ok(Self {
            path,
            credentials: Arc::new(Mutex::new(credentials)),
            verification_gate,
        })
    }

    /// Whether a silent CTAP preflight can only find credentials that require UV.
    ///
    /// Browsers may send GetAssertion with up=false and uv=false while checking
    /// whether an allow list contains a credential. Such a request cannot reveal
    /// a credProtect=3 credential, so perform Gaze UV before forwarding it.
    pub fn preflight_requires_uv(&self, rp_id: &str, allow_list: Option<&[Vec<u8>]>) -> bool {
        let Ok(credentials) = self.credentials.lock() else {
            // Fail closed if the local credential state cannot be inspected.
            return true;
        };

        let mut matches = credentials.values().filter(|credential| {
            credential.rp.id == rp_id
                && match allow_list {
                    Some(ids) => ids.iter().any(|id| id == &credential.id),
                    None => credential.discoverable,
                }
        });

        let Some(first) = matches.next() else {
            return false;
        };
        first.extensions.cred_protect == Some(3)
            && matches.all(|credential| credential.extensions.cred_protect == Some(3))
    }

    pub fn management_records(&self) -> Result<Vec<CredentialManagementRecord>> {
        let credentials = self.credentials.lock().map_err(|_| Error::Other)?;
        Ok(credentials
            .values()
            .map(|credential| CredentialManagementRecord {
                token: management_token(&credential.id),
                rp_id: credential.rp.id.clone(),
                rp_name: credential.rp.name.clone(),
                username: credential.user.name.clone(),
                display_name: credential.user.display_name.clone(),
                created: credential.created,
                discoverable: credential.discoverable,
                cred_protect: credential.extensions.cred_protect,
            })
            .collect())
    }

    pub fn delete_by_management_token(&self, token: &str) -> Result<bool> {
        if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(false);
        }

        let mut credentials = self.credentials.lock().map_err(|_| Error::Other)?;
        let Some(credential_id) = credentials
            .keys()
            .find(|credential_id| management_token(credential_id) == token)
            .cloned()
        else {
            return Ok(false);
        };
        let Some(removed) = credentials.remove(&credential_id) else {
            return Ok(false);
        };
        if let Err(error) = self.persist(&credentials) {
            credentials.insert(credential_id, removed);
            return Err(error);
        }
        eprintln!(
            "Deleted passkey for RP {} via desktop manager",
            removed.rp.id
        );
        Ok(true)
    }

    fn persist(&self, credentials: &BTreeMap<Vec<u8>, Credential>) -> Result<()> {
        let parent = self.path.parent().ok_or(Error::InitializationFailed)?;
        let records: Vec<&Credential> = credentials.values().collect();
        let mut encoded = Vec::new();
        soft_fido2_ctap::cbor::into_writer(&records, &mut encoded).map_err(|_| Error::Other)?;
        let mut last_error = None;

        for attempt in 0..8u32 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let temporary = parent.join(format!(
                ".credentials-{}-{nanos}-{attempt}.tmp",
                std::process::id()
            ));
            let mut file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    last_error = Some(error);
                    continue;
                }
                Err(error) => return Err(Error::from(error)),
            };

            let result = (|| {
                file.write_all(&encoded).map_err(Error::from)?;
                file.flush().map_err(Error::from)?;
                file.sync_all().map_err(Error::from)?;
                fs::rename(&temporary, &self.path).map_err(Error::from)?;
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(Error::from)?;
                Ok(())
            })();

            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            return result;
        }

        Err(Error::IoError(
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "could not allocate a temporary credential file".into()),
        ))
    }
}

fn management_token(credential_id: &[u8]) -> String {
    Sha256::digest(credential_id)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl soft_fido2::AuthenticatorCallbacks for CredentialStore {
    fn request_up(&self, info: &str, user_name: Option<&str>, rp_id: &str) -> Result<UpResult> {
        eprintln!("Gaze verification requested: {info} ({rp_id})");
        let operation = if user_name.is_some() {
            "注册通行密钥"
        } else {
            "确认安全密钥操作"
        };
        match self
            .verification_gate
            .verify_presence_for(operation, Some(rp_id), user_name)
        {
            Ok(()) => Ok(UpResult::Accepted),
            Err(UvError::Timeout) => Ok(UpResult::Timeout),
            Err(_) => Ok(UpResult::Denied),
        }
    }

    fn request_uv(&self, info: &str, user_name: Option<&str>, rp_id: &str) -> Result<UvResult> {
        eprintln!("Gaze user verification requested: {info} ({rp_id})");
        let operation = if user_name.is_some() {
            "注册通行密钥"
        } else {
            "登录并签名"
        };
        match self
            .verification_gate
            .verify_for_operation_for(operation, Some(rp_id), user_name)
        {
            Ok(()) => Ok(UvResult::AcceptedWithUp),
            Err(UvError::Timeout) => Ok(UvResult::Timeout),
            Err(_) => Ok(UvResult::Denied),
        }
    }

    fn write_credential(&self, credential: &CredentialRef) -> Result<()> {
        let credential = credential.to_owned();
        if credential.id.is_empty()
            || credential.key.provider.as_bytes() != TPM_PROVIDER_ID
            || credential.key.format_version != 1
        {
            return Err(Error::InvalidCallbackResult);
        }

        let rp_id = credential.rp.id.clone();
        let mut credentials = self.credentials.lock().map_err(|_| Error::Other)?;
        if !credentials.contains_key(&credential.id) && credentials.len() >= MAX_CREDENTIALS {
            return Err(Error::KeyStoreFull);
        }
        let id = credential.id.clone();
        let previous = credentials.insert(id.clone(), credential);
        if let Err(error) = self.persist(&credentials) {
            match previous {
                Some(previous) => {
                    credentials.insert(id, previous);
                }
                None => {
                    credentials.remove(&id);
                }
            }
            return Err(error);
        }
        eprintln!("Stored discoverable credential for RP {rp_id}");
        Ok(())
    }

    fn read_credential(&self, cred_id: &[u8]) -> Result<Option<Credential>> {
        let credentials = self.credentials.lock().map_err(|_| Error::Other)?;
        let credential = credentials.get(cred_id).cloned();
        match &credential {
            Some(credential) => eprintln!(
                "Credential ID lookup hit: rp_id={}, discoverable={}",
                credential.rp.id, credential.discoverable
            ),
            None => eprintln!("Credential ID lookup miss"),
        }
        Ok(credential)
    }

    fn delete_credential(&self, cred_id: &[u8]) -> Result<()> {
        let mut credentials = self.credentials.lock().map_err(|_| Error::Other)?;
        let Some(removed) = credentials.remove(cred_id) else {
            return Ok(());
        };
        if let Err(error) = self.persist(&credentials) {
            credentials.insert(cred_id.to_vec(), removed);
            return Err(error);
        }
        Ok(())
    }

    fn list_credentials(&self, rp_id: &str, user_id: Option<&[u8]>) -> Result<Vec<Credential>> {
        let credentials = self.credentials.lock().map_err(|_| Error::Other)?;
        let matching: Vec<Credential> = credentials
            .values()
            .filter(|credential| {
                credential.discoverable
                    && credential.rp.id == rp_id
                    && user_id.is_none_or(|id| credential.user.id.as_slice() == id)
            })
            .cloned()
            .collect();
        eprintln!(
            "Credential lookup for RP {rp_id}: {} discoverable match(es)",
            matching.len()
        );
        Ok(matching)
    }

    fn select_credential(&self, rp_id: &str, credentials: &[Credential]) -> Result<usize> {
        if credentials.len() == 1 {
            return Ok(0);
        }
        select_credential_from_terminal(rp_id, credentials)
    }

    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
        let credentials = self.credentials.lock().map_err(|_| Error::Other)?;
        let mut relying_parties: BTreeMap<String, (Option<String>, usize)> = BTreeMap::new();
        for credential in credentials
            .values()
            .filter(|credential| credential.discoverable)
        {
            let entry = relying_parties
                .entry(credential.rp.id.clone())
                .or_insert_with(|| (credential.rp.name.clone(), 0));
            entry.1 += 1;
        }
        Ok(relying_parties
            .into_iter()
            .map(|(rp_id, (rp_name, count))| (rp_id, rp_name, count))
            .collect())
    }

    fn credential_count(&self) -> Result<usize> {
        let credentials = self.credentials.lock().map_err(|_| Error::Other)?;
        Ok(credentials
            .values()
            .filter(|credential| credential.discoverable)
            .count())
    }

    fn get_timestamp_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64
    }
}

fn select_credential_from_terminal(rp_id: &str, credentials: &[Credential]) -> Result<usize> {
    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Error::InvalidCallbackResult)?;
    writeln!(terminal, "Choose a passkey for {rp_id}:").map_err(Error::from)?;
    for (index, credential) in credentials.iter().enumerate() {
        let name = credential
            .user
            .display_name
            .as_deref()
            .or(credential.user.name.as_deref())
            .unwrap_or("Unnamed account");
        writeln!(terminal, "  {}. {name}", index + 1).map_err(Error::from)?;
    }
    write!(terminal, "Selection: ").map_err(Error::from)?;
    terminal.flush().map_err(Error::from)?;

    let mut selection = String::new();
    io::BufReader::new(terminal)
        .read_line(&mut selection)
        .map_err(Error::from)?;
    let index = selection
        .trim()
        .parse::<usize>()
        .map_err(|_| Error::InvalidCallbackResult)?;
    if index == 0 || index > credentials.len() {
        return Err(Error::InvalidCallbackResult);
    }
    Ok(index - 1)
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(Error::from)?;
    if !metadata.file_type().is_dir() {
        return Err(Error::InitializationFailed);
    }
    set_mode(path, 0o700)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions).map_err(Error::from)
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Err(Error::InitializationFailed)
}
