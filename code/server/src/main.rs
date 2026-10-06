//! The relay binary: see the library (src/lib.rs) for what it does.

use anyhow::{Result, bail};
use server::{bind_endpoint, link::Relay, run, site::Site, spawn_sweeping_task, tls};
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // `--print-pubkey` and `--print-access-key` print what clients are
    // built with and exit (see `relay_config` in
    // code/frontend/src-tauri/src/commands.rs). No logging then, so stdout
    // is just the value.
    let arg = std::env::args().nth(1);
    if arg.is_none() {
        tracing_subscriber::fmt().with_env_filter("info").init();
    }

    let identity = tls::load_or_create_identity()?;
    let access_key = tls::load_or_create_access_key()?;
    match arg.as_deref() {
        None => {}
        Some("--print-pubkey") => {
            println!("{}", hex::encode(identity.pin));
            return Ok(());
        }
        Some("--print-access-key") => {
            println!("{}", hex::encode(access_key));
            return Ok(());
        }
        Some(other) => bail!("Unknown argument {other} (try --print-pubkey or --print-access-key)"),
    }

    // Defaults to 127.0.0.1:4430 for local testing without sudo. Override
    // with BIND_ADDR (e.g. "0.0.0.0:443" when running in Docker).
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:4430".to_string());
    let pin = identity.pin;
    let endpoint = bind_endpoint(bind_addr.parse()?, tls::server_config(identity)?)?;
    info!("QUIC relay listening on UDP {}", endpoint.local_addr()?);
    // What clients pin (SERVER_PUBKEY). The access key isn't logged: print
    // it with --print-access-key.
    info!("Server Static Pubkey: {}", hex::encode(pin));

    let relay = Arc::new(Relay::new(access_key));
    spawn_sweeping_task(Arc::clone(&relay));
    run(endpoint, relay, Site::load()?).await;
    Ok(())
}
