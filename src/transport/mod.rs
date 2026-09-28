//! CTAP HID transport boundary.

use crate::authenticator::CtapCommandHandler;

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Io(String),
    MalformedPacket,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(reason) => write!(f, "transport I/O error: {reason}"),
            Self::MalformedPacket => write!(f, "malformed CTAP HID packet"),
        }
    }
}

impl std::error::Error for TransportError {}

pub trait CtapTransport {
    fn recv(&mut self) -> Result<Vec<u8>, TransportError>;
    fn send(&mut self, packet: &[u8]) -> Result<(), TransportError>;
}

/// Expose the CTAP2 command handler as a Linux virtual FIDO HID device.
#[cfg(target_os = "linux")]
pub fn serve_virtual_fido(handler: CtapCommandHandler) -> Result<(), TransportError> {
    use soft_fido2_transport::{CtapHidHandler, Packet, UhidDevice};
    use std::{thread, time::Duration};

    let device = UhidDevice::create_fido_device_with_ids(
        Some("Gaze FIDO2 TPM authenticator"),
        Some(0x15d9),
        Some(0x0a37),
        Some(0x0001),
    )
    .map_err(|error| TransportError::Io(error.to_string()))?;
    let mut hid_handler = CtapHidHandler::new(handler);
    eprintln!("Gaze FIDO2 authenticator is ready on Linux UHID");

    loop {
        let mut bytes = [0u8; 64];
        match device.read_packet(&mut bytes) {
            Ok(Some(64)) => {
                let packet = Packet::from_bytes(bytes);
                let responses = hid_handler
                    .process_packet(packet)
                    .map_err(|error| TransportError::Io(error.to_string()))?;
                for response in responses {
                    device
                        .write_packet(response.as_bytes())
                        .map_err(|error| TransportError::Io(error.to_string()))?;
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(error) => return Err(TransportError::Io(error.to_string())),
        }
    }
}
