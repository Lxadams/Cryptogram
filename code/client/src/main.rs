// CLI entry point for the `client` crate.
//
// The protocol itself lives in `lib.rs` so it can be reused as a library
// (the Tauri desktop/Android shell in code/frontend/src-tauri runs the exact
// same Client and link); this file only holds what's specific to the
// terminal REPL: configuration, and the stdin command loop. Everything to
// and from the relay goes through `link::RelayLink`, which keeps a QUIC
// connection to it and the constant-rate cell stream running.
use anyhow::{Result, anyhow};
use std::{sync::Arc, time::Duration};
use tokio::{io::AsyncBufReadExt, sync::Mutex};

use client::{
    Client, ClientStateDto,
    link::{RelayConfig, RelayLink, client_handler},
    parse_routing_token, parse_verifying_key, state_file_path,
};

/// How long to wait for the relay to accept us before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    // The relay's key pin (`server --print-pubkey`), as the one argument or
    // SERVER_PUBKEY, and its access key (`server --print-access-key`) as
    // SERVER_ACCESS_KEY: the app ships with both rather than asking the
    // relay, which anyone on the network path could answer.
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let server_pub = std::env::args()
        .nth(1)
        .filter(|arg| !arg.is_empty())
        .or_else(|| env("SERVER_PUBKEY"))
        .ok_or_else(|| {
            anyhow!("Usage: client <server_pubkey_hex> (or set SERVER_PUBKEY), with SERVER_ACCESS_KEY set")
        })?;
    let access_key = env("SERVER_ACCESS_KEY").ok_or_else(|| {
        anyhow!("Set SERVER_ACCESS_KEY to the relay's access key (`server --print-access-key`)")
    })?;

    // Defaults to 127.0.0.1:4430 to match the relay's local-dev default.
    // An IP address is used as is; a name is looked up over
    // DNS-over-HTTPS, never plaintext DNS. SERVER_NAME is the name the
    // relay's certificate is for, if SERVER_ADDR is an IP address.
    let server_addr = env("SERVER_ADDR").unwrap_or_else(|| "127.0.0.1:4430".to_string());
    let server_name = env("SERVER_NAME");
    let config = RelayConfig::from_settings(
        &server_addr,
        server_name.as_deref(),
        &server_pub,
        &access_key,
    )
    .await?;

    // Resume a previous identity/session set if one was persisted to disk,
    // otherwise mint a fresh identity.
    let client = match ClientStateDto::load(&state_file_path()) {
        Ok(c) => {
            println!("Loaded client state from disk.");
            c
        }
        Err(_) => Client::new(),
    };
    client.save();
    println!("=== MY IDENTITY ===");
    println!("Token:   {}", hex::encode(client.identity.routing_token));
    println!(
        "Ed25519: {}",
        hex::encode(client.identity.ed25519_public.as_bytes())
    );
    println!("===================");

    let token_secret = client.identity.token_secret.clone();
    let client = Arc::new(Mutex::new(client));
    // Everything the relay delivers goes to the client state machine; its
    // replies (e.g. a KeyExchange response) go back out on the link.
    let link = RelayLink::start(config, token_secret, client_handler(Arc::clone(&client)))?;
    link.wait_until_up(CONNECT_TIMEOUT).await?;
    println!("Connected to the relay.");

    println!("Commands:");
    println!("  connect <routing_token_hex> <ed25519_pub_hex>");
    println!("  msg <routing_token_hex> <text...>");

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = stdin.next_line().await {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "connect" => {
                if parts.len() != 3 {
                    println!("Usage: connect <token> <ed25519>");
                    continue;
                }
                let (token, bob_ed25519) =
                    match (parse_routing_token(parts[1]), parse_verifying_key(parts[2])) {
                        (Ok(token), Ok(key)) => (token, key),
                        (Err(e), _) | (_, Err(e)) => {
                            println!("Error: {e}");
                            continue;
                        }
                    };
                // Trust is asserted here from the (assumed) QR-scanned key;
                // the reply's signature is checked against this on receipt.
                let request = client.lock().await.add_contact(token, bob_ed25519);
                link.send(request);
                println!("Sending connection request. They need to connect to you too.");
            }
            "msg" => {
                if parts.len() < 3 {
                    println!("Usage: msg <token> <text...>");
                    continue;
                }
                let token = match parse_routing_token(parts[1]) {
                    Ok(token) => token,
                    Err(e) => {
                        println!("Error: {e}");
                        continue;
                    }
                };
                let text = parts[2..].join(" ");
                // One FEC object (with any PQ ratchet injection bundled
                // inside), sent a cell at a time on the link's clock.
                match client.lock().await.create_message(token, text.as_bytes()) {
                    Ok(message) => {
                        link.send(message);
                        println!(
                            "Sending msg ({:.0}% uplink loss).",
                            link.stats().uplink_loss * 100.0
                        );
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
            _ => println!("Unknown command"),
        }
    }

    Ok(())
}
