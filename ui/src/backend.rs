use cxx_qt::CxxQtType;
use cxx_qt_lib::QString;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    pin::Pin,
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    thread,
    time::Duration,
};

const MAX_CONTROL_RESPONSE: usize = 1024 * 1024;

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qproperty(QString, app_version)]
        #[qproperty(QString, credentials_json)]
        #[qproperty(bool, service_available)]
        #[qproperty(QString, status_message)]
        #[qproperty(QString, prompt_requested_json)]
        #[qproperty(QString, prompt_finished_json)]
        type Backend = super::BackendRust;

        #[qinvokable]
        #[cxx_name = "start"]
        fn start(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "refreshCredentials"]
        fn refresh_credentials(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "pollEvents"]
        fn poll_events(self: Pin<&mut Self>);

        #[qinvokable]
        #[cxx_name = "deleteCredential"]
        fn delete_credential(self: Pin<&mut Self>, token: &QString);

        #[qinvokable]
        #[cxx_name = "cancelPrompt"]
        fn cancel_prompt(self: Pin<&mut Self>, request_id: &QString);
    }
}

#[derive(Default)]
pub struct BackendRust {
    app_version: QString,
    credentials_json: QString,
    service_available: bool,
    status_message: QString,
    prompt_requested_json: QString,
    prompt_finished_json: QString,
    event_receiver: Option<Receiver<Value>>,
    event_writer: Option<Arc<Mutex<Option<UnixStream>>>>,
    started: bool,
}

impl qobject::Backend {
    pub fn start(mut self: Pin<&mut Self>) {
        if self.as_ref().rust().started {
            return;
        }
        self.as_mut()
            .set_app_version(QString::from(env!("CARGO_PKG_VERSION")));

        let (sender, receiver) = mpsc::channel();
        let writer = Arc::new(Mutex::new(None));
        {
            let state = self.as_mut().rust_mut().get_mut();
            state.started = true;
            state.event_receiver = Some(receiver);
            state.event_writer = Some(Arc::clone(&writer));
        }

        thread::Builder::new()
            .name("gaze-fido-control-events".into())
            .spawn(move || subscribe_loop(sender, writer))
            .ok();

        self.as_mut().refresh_credentials();
    }

    pub fn refresh_credentials(mut self: Pin<&mut Self>) {
        let result = control_request(&json!({"op": "list_credentials"}));
        match result {
            Ok(response) if response.get("ok").and_then(Value::as_bool) == Some(true) => {
                let credentials = response
                    .get("credentials")
                    .cloned()
                    .unwrap_or_else(|| Value::Array(Vec::new()));
                self.as_mut()
                    .set_credentials_json(QString::from(credentials.to_string()));
                self.as_mut().set_service_available(true);
                self.as_mut().set_status_message(QString::default());
            }
            Ok(response) => {
                let error = response
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("读取本机通行密钥失败");
                self.as_mut().set_status_message(QString::from(error));
            }
            Err(error) => {
                self.as_mut().set_service_available(false);
                self.as_mut().set_status_message(QString::from(error));
            }
        }
    }

    pub fn poll_events(mut self: Pin<&mut Self>) {
        let pending = {
            let state = self.as_mut().rust_mut().get_mut();
            let Some(receiver) = state.event_receiver.as_ref() else {
                return;
            };
            let mut pending = Vec::new();
            loop {
                match receiver.try_recv() {
                    Ok(event) => pending.push(event),
                    Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                }
            }
            pending
        };

        for event in pending {
            match event.get("event").and_then(Value::as_str) {
                Some("ready") => {
                    self.as_mut().set_service_available(true);
                    self.as_mut().set_status_message(QString::default());
                }
                Some("connection_error") => {
                    self.as_mut().set_service_available(false);
                    let message = event
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("等待 Gaze FIDO 服务");
                    self.as_mut().set_status_message(QString::from(message));
                }
                Some("disconnected") => {
                    self.as_mut().set_service_available(false);
                    self.as_mut()
                        .set_status_message(QString::from("Gaze FIDO 服务连接已断开"));
                }
                Some("verification_requested") => {
                    self.as_mut()
                        .set_prompt_requested_json(QString::from(event.to_string()));
                }
                Some("verification_finished") => {
                    self.as_mut()
                        .set_prompt_finished_json(QString::from(event.to_string()));
                    self.as_mut().refresh_credentials();
                }
                _ => {}
            }
        }
    }

    pub fn delete_credential(mut self: Pin<&mut Self>, token: &QString) {
        let token = token.to_string();
        let result = control_request(&json!({"op": "delete_credential", "token": token}));
        match result {
            Ok(response) if response.get("deleted").and_then(Value::as_bool) == Some(true) => {
                self.as_mut().set_status_message(QString::default());
                self.as_mut().refresh_credentials();
            }
            Ok(_) => self
                .as_mut()
                .set_status_message(QString::from("凭据已不存在或删除失败")),
            Err(error) => self.as_mut().set_status_message(QString::from(error)),
        }
    }

    pub fn cancel_prompt(self: Pin<&mut Self>, request_id: &QString) {
        let writer = self.as_ref().rust().event_writer.as_ref().cloned();
        let Some(writer) = writer else {
            return;
        };
        let Ok(mut guard) = writer.lock() else {
            return;
        };
        let Some(stream) = guard.as_mut() else {
            return;
        };
        let request = json!({"op": "cancel", "request_id": request_id.to_string()});
        let _ = stream.write_all(request.to_string().as_bytes());
        let _ = stream.write_all(b"\n");
    }
}

fn subscribe_loop(sender: Sender<Value>, writer: Arc<Mutex<Option<UnixStream>>>) {
    loop {
        let Some(path) = control_socket_path() else {
            send_connection_error(&sender, "XDG_RUNTIME_DIR 未配置");
            thread::sleep(Duration::from_secs(2));
            continue;
        };

        match UnixStream::connect(path) {
            Ok(mut reader_stream) => {
                if reader_stream
                    .write_all(b"{\"op\":\"subscribe\"}\n")
                    .is_err()
                {
                    send_connection_error(&sender, "无法订阅认证提示");
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
                let write_stream = match reader_stream.try_clone() {
                    Ok(stream) => stream,
                    Err(error) => {
                        send_connection_error(&sender, &error.to_string());
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };
                if let Ok(mut target) = writer.lock() {
                    *target = Some(write_stream);
                }

                let mut reader = BufReader::new(reader_stream);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(length) if length <= MAX_CONTROL_RESPONSE => {
                            if let Ok(event) = serde_json::from_str::<Value>(&line)
                                && event.get("event").is_some()
                            {
                                let _ = sender.send(event);
                            }
                        }
                        Ok(_) => break,
                        Err(_) => break,
                    }
                }

                if let Ok(mut target) = writer.lock() {
                    *target = None;
                }
                let _ = sender.send(json!({"event": "disconnected"}));
            }
            Err(error) => send_connection_error(&sender, &error.to_string()),
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn send_connection_error(sender: &Sender<Value>, message: &str) {
    let _ = sender.send(json!({"event": "connection_error", "message": message}));
}

fn control_socket_path() -> Option<std::path::PathBuf> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")?;
    let runtime_dir = std::path::PathBuf::from(runtime_dir);
    runtime_dir
        .is_absolute()
        .then(|| runtime_dir.join("gaze-fido/control.sock"))
}

fn control_request(request: &Value) -> Result<Value, String> {
    let path = control_socket_path().ok_or_else(|| "XDG_RUNTIME_DIR 未配置".to_owned())?;
    let stream = UnixStream::connect(path).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    let mut request_bytes = request.to_string().into_bytes();
    request_bytes.push(b'\n');
    let mut stream = stream;
    stream
        .write_all(&request_bytes)
        .map_err(|error| error.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut response = Vec::new();
    reader
        .by_ref()
        .take((MAX_CONTROL_RESPONSE + 1) as u64)
        .read_until(b'\n', &mut response)
        .map_err(|error| error.to_string())?;
    if response.is_empty() || response.len() > MAX_CONTROL_RESPONSE {
        return Err("Gaze FIDO 返回了无效响应".into());
    }
    serde_json::from_slice(&response).map_err(|error| error.to_string())
}
