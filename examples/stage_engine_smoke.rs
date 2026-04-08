//! Small host-side smoke test for the public std transport API.
//!
//! Run:
//! `cargo run --example stage_engine_smoke --features std`

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::{Transport, TransportConfig};

#[tokio::main]
async fn main() {
    let mut transport = Transport::new(TransportConfig::default());
    let private_id = PrivateIdentity::new_from_rand(OsRng);
    let destination = transport
        .add_destination(private_id, DestinationName::new("stage", "smoke"))
        .await;

    // With no interfaces attached, this should still be safe to call and should not panic.
    transport.send_announce(&destination, None).await;

    println!("stage_engine_smoke: OK");
}
