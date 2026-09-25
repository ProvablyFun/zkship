//! Regenerates `vectors/setup_message_v1.txt`; refuses to write if the digest
//! pinned in `setup.rs` tests drifted.

use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha512_256};
use std::fmt::Write as _;
use zkb_core::fleet::{Fleet, SHIP_BITS};
use zkb_core::params::{Parameters, Rules};
use zkb_core::setup;

const PROVER_ID: [u8; 32] = [0xA1; 32];
const SID: [u8; 32] = [0x5D; 32];
/// Cells 0-4, 20-23, 40-42, 50-52, 70-71.
const FLEET: [u8; 15] = [0, 0, 0, 2, 0, 0, 4, 0, 0, 5, 0, 0, 7, 0, 0];
const BLINDERS_SEED: [u8; 32] = [0x42; 32];
const FINALIZE_SEED: [u8; 32] = [0x77; 32];
const PINNED_DIGEST: &str = "0080ba7f74eaf6c8e425032324a57540094b5722ab9650cc02609d90ffce4c85";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let params = Parameters::standard();
    let fleet = Fleet::from_bytes(&FLEET, Rules::Standard).expect("legal fleet");
    let mut rng = ChaCha20Rng::from_seed(BLINDERS_SEED);
    let rho: Vec<Scalar> = (0..SHIP_BITS).map(|_| Scalar::random(&mut rng)).collect();
    let msg = setup::prove_with_rng(
        params,
        &PROVER_ID,
        &SID,
        &fleet,
        &rho,
        ChaCha20Rng::from_seed(FINALIZE_SEED),
    )
    .expect("legal witness");
    let bytes = msg.encode();
    let digest = hex(&Sha512_256::digest(&bytes));
    assert_eq!(
        digest, PINNED_DIGEST,
        "construction drifted from the digest pinned in setup.rs tests"
    );

    let mut out = String::new();
    writeln!(out, "# zkbattleship deterministic setup-message vector v1").unwrap();
    writeln!(
        out,
        "# regenerate: cargo run -p zkb-core --example generate_setup_vector"
    )
    .unwrap();
    writeln!(out, "profile = zkbattleship/paper/v1").unwrap();
    writeln!(out, "params_id = {}", hex(params.params_id())).unwrap();
    writeln!(out, "prover_id = {}", hex(&PROVER_ID)).unwrap();
    writeln!(out, "sid = {}", hex(&SID)).unwrap();
    writeln!(out, "fleet = {}", hex(&FLEET)).unwrap();
    writeln!(
        out,
        "blinders_rng = chacha20rng(seed={})",
        hex(&BLINDERS_SEED)
    )
    .unwrap();
    writeln!(
        out,
        "proof_finalize_rng = chacha20rng(seed={})",
        hex(&FINALIZE_SEED)
    )
    .unwrap();
    writeln!(out, "setup_len = {}", bytes.len()).unwrap();
    writeln!(out, "setup_sha512_256 = {digest}").unwrap();
    writeln!(out, "setup_hex = {}", hex(&bytes)).unwrap();

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors");
    std::fs::create_dir_all(&dir).expect("create vectors dir");
    let path = dir.join("setup_message_v1.txt");
    std::fs::write(&path, out).expect("write vector file");
    println!(
        "wrote {} ({} bytes)",
        path.display(),
        std::fs::metadata(&path).unwrap().len()
    );
}
