//! One measurement = one process = one proof.
//!
//! Replicates the timing boundaries of upstream `host/src/bin/bench.rs`
//! (same seed-42 fleet, same shot (9,9), same row-major history, prover =
//! `default_prover()`, timer around `prove_with_opts`, timer around the
//! upstream `verify_commit` / `verify_shot`), and adds what the upstream
//! bench does not report: bincode receipt size, repeated verification,
//! segment count, and peak RSS of this process and of the r0vm child.
//!
//! Usage:
//!   r0bs-measure --proof commit|shot --receipt composite|succinct
//!                [--hist N] [--verify-reps K] [--seed S]
//! Prints exactly one JSON object on stdout.

use std::time::Instant;

use anyhow::{bail, Context, Result};
use methods::{COMMIT_BOARD_ELF, COMMIT_BOARD_ID, PROVE_SHOT_ELF, PROVE_SHOT_ID};
use rand::rngs::StdRng;
use rand::SeedableRng;
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};
use zk_battleship_core::{CommitInput, Shot, ShotInput, ShotJournal};

use host::board_gen::{random_fleet, random_salt};
use host::game::host_commitment;
use host::verifier::{verify_commit, verify_shot};

/// Identical to upstream bench.rs `seal_bytes`.
fn seal_bytes(receipt: &Receipt) -> usize {
    match &receipt.inner {
        InnerReceipt::Composite(c) => c.segments.iter().map(|s| s.get_seal_bytes().len()).sum(),
        InnerReceipt::Succinct(s) => s.get_seal_bytes().len(),
        InnerReceipt::Groth16(g) => g.seal.len(),
        _ => 0,
    }
}

/// Identical to upstream bench.rs `history_of_len`.
fn history_of_len(n: usize) -> Vec<Shot> {
    (0..n as u8).map(|i| Shot::new(i / 10, i % 10)).collect()
}

fn maxrss_kb(who: i32) -> i64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(who, &mut ru) };
    ru.ru_maxrss
}

fn id_hex(id: &[u32; 8]) -> String {
    id.iter().flat_map(|w| w.to_le_bytes()).map(|b| format!("{b:02x}")).collect()
}

fn stats(v: &mut [f64]) -> (f64, f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    let med = if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 };
    (med, v[0], v[n - 1])
}

fn main() -> Result<()> {
    let mut proof = String::from("shot");
    let mut kind = String::from("composite");
    let mut hist: usize = 0;
    let mut verify_reps: usize = 20;
    let mut seed: u64 = 42;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().context("missing value");
        match a.as_str() {
            "--proof" => proof = val()?,
            "--receipt" => kind = val()?,
            "--hist" => hist = val()?.parse()?,
            "--verify-reps" => verify_reps = val()?.parse()?,
            "--seed" => seed = val()?.parse()?,
            _ => bail!("unknown arg {a}"),
        }
    }
    if hist > 99 {
        bail!("history length must be <= 99 (shot is (9,9))");
    }
    if verify_reps == 0 {
        bail!("--verify-reps must be >= 1");
    }
    if std::env::var_os("RISC0_DEV_MODE").is_some() {
        bail!("RISC0_DEV_MODE is set; refusing (upstream builds with disable-dev-mode)");
    }
    let opts = match kind.as_str() {
        "composite" => ProverOpts::default(),
        "succinct" => ProverOpts::succinct(),
        _ => bail!("--receipt must be composite|succinct"),
    };

    let mut rng = StdRng::seed_from_u64(seed);
    let fleet = random_fleet(&mut rng);
    let salt = random_salt(&mut rng);
    let commitment = host_commitment(&fleet, &salt);
    let shot = Shot::new(9, 9);
    let history = history_of_len(hist);

    let prover = default_prover();

    let (elf, image_id) = match proof.as_str() {
        "commit" => (COMMIT_BOARD_ELF, COMMIT_BOARD_ID),
        "shot" => (PROVE_SHOT_ELF, PROVE_SHOT_ID),
        _ => bail!("--proof must be commit|shot"),
    };
    let env = match proof.as_str() {
        "commit" => ExecutorEnv::builder()
            .write(&CommitInput { fleet: fleet.clone(), salt })?
            .build()?,
        _ => ExecutorEnv::builder()
            .write(&ShotInput {
                fleet: fleet.clone(),
                salt,
                commitment,
                shot,
                history: history.clone(),
            })?
            .build()?,
    };

    // ---- prove (same boundary as upstream bench) ----
    let t = Instant::now();
    let info = prover.prove_with_opts(env, elf, &opts)?;
    let prove_s = t.elapsed().as_secs_f64();
    let receipt = info.receipt;

    // ---- verify: first call (= upstream's single measurement), then repeats ----
    let do_verify = |r: &Receipt| -> Result<Option<ShotJournal>> {
        match proof.as_str() {
            "commit" => {
                let c = verify_commit(r)?;
                if c != commitment {
                    bail!("commit journal mismatch");
                }
                Ok(None)
            }
            _ => Ok(Some(verify_shot(r, commitment, shot, &history)?)),
        }
    };
    let t = Instant::now();
    let journal = do_verify(&receipt)?;
    let verify_first_ms = t.elapsed().as_secs_f64() * 1e3;
    let mut vs = Vec::with_capacity(verify_reps);
    for _ in 0..verify_reps {
        let t = Instant::now();
        do_verify(&receipt)?;
        vs.push(t.elapsed().as_secs_f64() * 1e3);
    }
    let (v_med, v_min, v_max) = stats(&mut vs);

    // ---- sizes ----
    let json_b = serde_json::to_vec(&receipt)?.len();
    let bincode_b = bincode::serialize(&receipt)?.len();
    let inner_bincode_b = bincode::serialize(&receipt.inner)?.len();
    // Round-trip the compact encoding to show it is a usable wire format.
    let rt: Receipt = bincode::deserialize(&bincode::serialize(&receipt)?)?;
    do_verify(&rt)?;
    let (inner_kind, n_seg_receipts) = match &receipt.inner {
        InnerReceipt::Composite(c) => ("composite", c.segments.len()),
        InnerReceipt::Succinct(_) => ("succinct", 1),
        InnerReceipt::Groth16(_) => ("groth16", 1),
        _ => ("other", 0),
    };

    let out = serde_json::json!({
        "proof": proof,
        "receipt": kind,
        "inner_receipt_kind": inner_kind,
        "history_len": if proof == "commit" { serde_json::Value::Null } else { hist.into() },
        "seed": seed,
        "prove_s": prove_s,
        "verify_first_ms": verify_first_ms,
        "verify_reps": verify_reps,
        "verify_median_ms": v_med,
        "verify_min_ms": v_min,
        "verify_max_ms": v_max,
        "journal_B": receipt.journal.bytes.len(),
        "seal_B": seal_bytes(&receipt),
        "wire_json_B": json_b,
        "wire_bincode_B": bincode_b,
        "inner_bincode_B": inner_bincode_b,
        "segment_receipts": n_seg_receipts,
        "segments": info.stats.segments,
        "user_cycles": info.stats.user_cycles,
        "total_cycles": info.stats.total_cycles,
        "paging_cycles": info.stats.paging_cycles,
        "reserved_cycles": info.stats.reserved_cycles,
        "hit": journal.as_ref().map(|j| j.hit),
        "sunk": journal.as_ref().map(|j| j.sunk.map(|s| format!("{s:?}"))),
        "defeated": journal.as_ref().map(|j| j.defeated),
        "image_id": id_hex(&image_id),
        "maxrss_self_kB": maxrss_kb(libc::RUSAGE_SELF),
        "maxrss_children_kB": maxrss_kb(libc::RUSAGE_CHILDREN),
        "rayon_num_threads_env": std::env::var("RAYON_NUM_THREADS").ok(),
        "available_parallelism": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "risc0_server_path": std::env::var("RISC0_SERVER_PATH").ok(),
    });
    println!("{out}");
    Ok(())
}
