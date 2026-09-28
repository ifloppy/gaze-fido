#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use gaze_fido::{
        authenticator::{CtapCommandHandler, store::CredentialStore},
        companion::{CompanionServer, PromptBroker},
        tpm::TpmCredentialKeyProvider,
        transport::serve_virtual_fido,
        uv::VerificationGate,
    };
    use std::{env, sync::Arc};

    let username = env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .map_err(|_| "USER must name the account configured in Gaze")?;
    let tcti = env::var("GAZE_FIDO_TCTI").unwrap_or_else(|_| "device:/dev/tpmrm0".into());
    let data_dir = data_directory()?;
    let credentials_path = data_dir.join("credentials.cbor");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let runtime_handle = runtime.handle().clone();
    let prompts = Arc::new(PromptBroker::new());
    let verification_gate = Arc::new(VerificationGate::new(
        username,
        runtime,
        Arc::clone(&prompts),
    ));
    let credential_store = CredentialStore::open(credentials_path, Arc::clone(&verification_gate))?;
    let companion = Arc::new(CompanionServer::from_environment(
        credential_store.clone(),
        prompts,
    )?);
    let socket_path = companion.socket_path().to_owned();
    runtime_handle.spawn(async move {
        if let Err(error) = companion.serve().await {
            eprintln!("Desktop companion server stopped: {error}");
        }
    });
    let key_provider = TpmCredentialKeyProvider::new(tcti, Arc::clone(&verification_gate))?;
    let handler = CtapCommandHandler::new(credential_store, key_provider, verification_gate)?;

    eprintln!(
        "Starting Gaze FIDO2 authenticator; TPM and Gaze checks are required; desktop UI socket: {}",
        socket_path.display()
    );
    serve_virtual_fido(handler)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn data_directory() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use std::{env, path::PathBuf};

    if let Some(path) = env::var_os("GAZE_FIDO_DATA_DIR") {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("XDG_DATA_HOME").map(PathBuf::from)
        && path.is_absolute()
    {
        return Ok(path.join("gaze-fido"));
    }
    let home = env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/share/gaze-fido"))
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("gaze-fido currently requires Linux UHID and TPM 2.0 support");
    std::process::exit(1);
}
