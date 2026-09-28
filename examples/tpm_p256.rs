use sha2::{Digest as _, Sha256};
use std::{error::Error, str::FromStr};
use tss_esapi::{
    TctiNameConf,
    abstraction::transient::{KeyParams, TransientKeyContext},
    interface_types::{algorithm::HashingAlgorithm, ecc::EccCurve},
    structures::{Digest, EccScheme, HashScheme, Signature},
    utils::PublicKey,
};

fn main() -> Result<(), Box<dyn Error>> {
    let tcti = TctiNameConf::from_str("device:/dev/tpmrm0")?;
    let mut tpm = TransientKeyContext::builder().with_tcti(tcti).build()?;

    let params = KeyParams::Ecc {
        curve: EccCurve::NistP256,
        scheme: EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
    };

    // A zero-length auth value keeps this probe non-interactive. Production credential
    // authorization policy will be decided separately from this capability test.
    let (material, auth) = tpm.create_key(params, 0)?;

    let (x_len, y_len) = match material.public() {
        PublicKey::Ecc { x, y } => (x.len(), y.len()),
        PublicKey::Rsa(_) => return Err("TPM returned an RSA key for an ECC request".into()),
    };

    let message = b"gaze-fido TPM P-256 signing probe";
    let digest = Digest::try_from(Sha256::digest(message).to_vec())?;

    let signature = tpm.sign(material.clone(), params, auth, digest.clone())?;
    tpm.verify_signature(material.clone(), params, digest, signature.clone())?;

    let (r_len, s_len) = match signature {
        Signature::EcDsa(sig) => (sig.signature_r().len(), sig.signature_s().len()),
        other => return Err(format!("unexpected TPM signature type: {other:?}").into()),
    };

    println!("TPM P-256 key created and signature verified");
    println!("public coordinates: x={x_len} bytes y={y_len} bytes");
    println!(
        "TPM-wrapped private blob: {} bytes",
        material.private().len()
    );
    println!("ECDSA signature: r={r_len} bytes s={s_len} bytes");

    Ok(())
}
