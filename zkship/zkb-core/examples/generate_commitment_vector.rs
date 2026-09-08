//! Regenerates `vectors/commitment_proof_v1.txt`; refuses to write if the
//! digest pinned in `wf.rs` tests drifted.

use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha512_256};
use std::fmt::Write as _;
use zkb_core::params::{Parameters, P};
use zkb_core::wf;

const PROVER_ID: [u8; 32] = [0xA1; 32];
const SID: [u8; 32] = [0x5D; 32];
const BLINDERS_SEED: [u8; 32] = [0x42; 32];
const FINALIZE_SEED: [u8; 32] = [0x77; 32];
const PINNED_DIGEST: &str = "6e3ef00a8bf9108596929e80f14530a83c1fd23842e417c42e83f9e767861a71";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha512_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn main() {
    let params = Parameters::standard_v1();

    let mut e = vec![0u8; P];
    e[0] = 1; // block 0, cells 0-4
    e[134] = 1; // block 1, cells 20-23
    e[292] = 1; // block 2, cells 40-42
    e[460] = 1; // block 3, cells 50-52
    e[643] = 1; // block 4, cells 70-71
    assert!(params.geometry().is_legal_placement(&e));

    let mut rng = ChaCha20Rng::from_seed(BLINDERS_SEED);
    let s: Vec<Scalar> = (0..P).map(|_| Scalar::random(&mut rng)).collect();

    let (board, proof) = wf::prove_with_rng(
        params,
        &PROVER_ID,
        &SID,
        &e,
        &s,
        ChaCha20Rng::from_seed(FINALIZE_SEED),
    )
    .expect("legal witness");
    let entry_bytes = board.to_bytes();
    let proof_bytes = proof.encode();

    let digest = hex(&sha512_256(&[&entry_bytes, &proof_bytes]));
    assert_eq!(
        digest, PINNED_DIGEST,
        "construction drifted from the digest pinned in wf.rs tests"
    );

    let placement: Vec<String> = e
        .iter()
        .enumerate()
        .filter(|(_, &b)| b == 1)
        .map(|(p, _)| p.to_string())
        .collect();

    let mut out = String::new();
    writeln!(
        out,
        "# zkbattleship deterministic commitment/proof vector v1"
    )
    .unwrap();
    writeln!(
        out,
        "# regenerate: cargo run -p zkb-core --example generate_commitment_vector"
    )
    .unwrap();
    writeln!(out, "profile = zkbattleship/reference/v1").unwrap();
    writeln!(out, "params_id = {}", hex(params.params_id())).unwrap();
    writeln!(out, "prover_id = {}", hex(&PROVER_ID)).unwrap();
    writeln!(out, "sid = {}", hex(&SID)).unwrap();
    writeln!(out, "placement_positions = {}", placement.join(",")).unwrap();
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
    writeln!(out, "entry_commitments_len = {}", entry_bytes.len()).unwrap();
    writeln!(
        out,
        "entry_commitments_sha512_256 = {}",
        hex(&sha512_256(&[&entry_bytes]))
    )
    .unwrap();
    writeln!(out, "proof_len = {}", proof_bytes.len()).unwrap();
    writeln!(
        out,
        "proof_sha512_256 = {}",
        hex(&sha512_256(&[&proof_bytes]))
    )
    .unwrap();
    writeln!(out, "combined_sha512_256 = {digest}").unwrap();
    writeln!(out, "entry_commitments_hex = {}", hex(&entry_bytes)).unwrap();
    writeln!(out, "proof_hex = {}", hex(&proof_bytes)).unwrap();

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors");
    std::fs::create_dir_all(&dir).expect("create vectors dir");
    let path = dir.join("commitment_proof_v1.txt");
    std::fs::write(&path, out).expect("write vector file");
    println!(
        "wrote {} ({} bytes)",
        path.display(),
        std::fs::metadata(&path).unwrap().len()
    );
}
