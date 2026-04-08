//! Small host-side smoke test for identity/signature basics.
//!
//! This mirrors the cryptographic part that beacon verification depends on.
//!
//! Run:
//! `cargo run --example identity_signature_smoke --features std`

use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;

fn main() {
    let private_id = PrivateIdentity::new_from_rand(OsRng);
    let public_id = private_id.as_identity();

    let msg = b"reticulum-embedded-smoke";
    let sig = private_id.sign(msg);
    public_id
        .verify(msg, &sig)
        .expect("signature must verify for matching key/message");

    let tampered = b"reticulum-embedded-smoke!";
    assert!(
        public_id.verify(tampered, &sig).is_err(),
        "signature must fail for tampered message"
    );

    println!("identity_signature_smoke: OK");
}
