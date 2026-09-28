use gaze_fido::uv::{GazeVerifier, UserVerifier};

#[tokio::main]
async fn main() {
    let username = std::env::var("USER").expect("USER must be set");
    eprintln!("Requesting fresh Gaze verification for {username}...");

    match GazeVerifier::new(username).verify().await {
        Ok(verification) => {
            println!(
                "verified={} method={}",
                verification.verified, verification.method
            );
        }
        Err(error) => {
            eprintln!("verification failed: {error}");
            std::process::exit(1);
        }
    }
}
