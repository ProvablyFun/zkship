//! Regenerates `vectors/game_transcript_v1.txt`; must reproduce it byte-for-byte.
//! `cargo run -p zkb-session --example generate_game_transcript`

use curve25519_dalek::scalar::Scalar;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::fmt::Write as _;
use zkb_core::game::Role;
use zkb_core::params::{CellIndex, Parameters, N, P};
use zkb_session::hello::{self, Hello};
use zkb_session::identity::{ExpectedKey, IdentityKeypair, PeerAuthPolicy};
use zkb_session::state::{AcceptOutcome, Session};

const KEY_SEEDS: [[u8; 32]; 2] = [[0x11; 32], [0x22; 32]];
const HELLO_RNG_SEEDS: [[u8; 32]; 2] = [[0x33; 32], [0x44; 32]];
const PLACEMENTS: [[usize; 5]; 2] = [
    [0, 134, 292, 460, 643], // cells [0-4] [20-23] [40-42] [50-52] [70-71]
    [5, 127, 272, 444, 625], // cells [5-9] [10-13] [14-16] [30-32] [50-51]
];
const BLINDER_SEEDS: [[u8; 32]; 2] = [[0xA0; 32], [0xB0; 32]];
const PROOF_RNG_SEEDS: [[u8; 32]; 2] = [[0xA1; 32], [0xB1; 32]];
const COIN_RNG_SEEDS: [[u8; 32]; 2] = [[0xC1; 32], [0xC2; 32]];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn placement(positions: &[usize; 5]) -> Vec<u8> {
    let mut e = vec![0u8; P];
    for &p in positions {
        e[p] = 1;
    }
    e
}

fn blinders(seed: [u8; 32]) -> Vec<Scalar> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    (0..P).map(|_| Scalar::random(&mut rng)).collect()
}

fn main() {
    let params = Parameters::standard_v1();
    let params_id = *params.params_id();

    let keypairs: Vec<IdentityKeypair> = KEY_SEEDS.iter().map(IdentityKeypair::from_seed).collect();
    let hellos: Vec<Hello> = keypairs
        .iter()
        .zip(HELLO_RNG_SEEDS.iter())
        .map(|(kp, &seed)| Hello::create(kp, params_id, &mut ChaCha20Rng::from_seed(seed)))
        .collect();
    let checked: Vec<hello::CheckedHello> = keypairs
        .iter()
        .zip(hellos.iter().cloned())
        .map(|(kp, h)| hello::check_hello(h, &params_id, &ExpectedKey::new(kp.peer_key())).unwrap())
        .collect();
    let bootstrap = hello::complete_bootstrap(checked[0].clone(), checked[1].clone()).unwrap();

    let role_of: Vec<Role> = keypairs
        .iter()
        .map(|kp| bootstrap.role_of(&kp.peer_key()))
        .collect();
    let a_idx = if role_of[0] == Role::A { 0 } else { 1 };
    let b_idx = 1 - a_idx;

    let auth = |kp: &IdentityKeypair| {
        ExpectedKey::new(kp.peer_key())
            .authenticate(&kp.peer_key())
            .unwrap()
    };

    let mut sa = Session::new(
        params,
        &keypairs[a_idx],
        Role::A,
        auth(&keypairs[b_idx]),
        *bootstrap.sid(),
        *bootstrap.genesis_hash(),
        placement(&PLACEMENTS[0]),
        blinders(BLINDER_SEEDS[0]),
    )
    .unwrap();
    let mut sb = Session::new(
        params,
        &keypairs[b_idx],
        Role::B,
        auth(&keypairs[a_idx]),
        *bootstrap.sid(),
        *bootstrap.genesis_hash(),
        placement(&PLACEMENTS[1]),
        blinders(BLINDER_SEEDS[1]),
    )
    .unwrap();

    let mut coin_rng_a = ChaCha20Rng::from_seed(COIN_RNG_SEEDS[0]);
    let mut coin_rng_b = ChaCha20Rng::from_seed(COIN_RNG_SEEDS[1]);

    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut first_mover: Option<Role> = None;
    for _ in 0..16 {
        while let Some(f) = sa
            .produce_with_rng(&mut coin_rng_a, ChaCha20Rng::from_seed(PROOF_RNG_SEEDS[0]))
            .unwrap()
        {
            frames.push(f.bytes().to_vec());
            if let AcceptOutcome::GameReady { first_mover: fm } = sb.accept(f.bytes()).unwrap() {
                first_mover = Some(fm);
            }
        }
        while let Some(f) = sb
            .produce_with_rng(&mut coin_rng_b, ChaCha20Rng::from_seed(PROOF_RNG_SEEDS[1]))
            .unwrap()
        {
            frames.push(f.bytes().to_vec());
            if let AcceptOutcome::GameReady { first_mover: fm } = sa.accept(f.bytes()).unwrap() {
                first_mover = Some(fm);
            }
        }
        if first_mover.is_some() && sa.game().is_some() && sb.game().is_some() {
            break;
        }
    }
    let first_mover = first_mover.expect("coin flip resolved");

    let mut current = first_mover;
    let winner = loop {
        let defender = current.other();
        let (attacker, attacked) = match current {
            Role::A => (&mut sa, &mut sb),
            Role::B => (&mut sb, &mut sa),
        };
        let cell = (0..N as u8)
            .map(|i| CellIndex::from_index(i).unwrap())
            .find(|c| {
                !attacker
                    .game()
                    .unwrap()
                    .shots_on_board(defender)
                    .is_shot(*c)
            })
            .expect("unshot cells remain");
        let shot = attacker.fire_shot(cell).unwrap();
        frames.push(shot.bytes().to_vec());
        let answer = match attacked.accept(shot.bytes()).unwrap() {
            AcceptOutcome::ShotReceived { answer, .. } => answer,
            other => panic!("expected ShotReceived, got {other:?}"),
        };
        frames.push(answer.bytes().to_vec());
        match attacker.accept(answer.bytes()).unwrap() {
            AcceptOutcome::GameFinished { winner } => break winner,
            AcceptOutcome::Answer(_) => current = defender,
            other => panic!("expected Answer/GameFinished, got {other:?}"),
        }
    };

    assert_eq!(sa.transcript(), frames.as_slice());
    assert_eq!(sb.transcript(), frames.as_slice());
    assert_eq!(sa.winner(), Some(winner));
    let loser_hits = match winner {
        Role::A => sb.game().unwrap().verified_hits(),
        Role::B => sa.game().unwrap().verified_hits(),
    };
    let winner_hits = 17u8;
    let winner_sunk_total = 5u8;

    let positions = |idx: usize| {
        PLACEMENTS[idx]
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    let hello_of_role = |role: Role| {
        let idx = if role_of[0] == role { 0 } else { 1 };
        hex(&hellos[idx].encode())
    };

    let mut out = String::new();
    writeln!(
        out,
        "# zkbattleship deterministic game transcript vector v1"
    )
    .unwrap();
    writeln!(
        out,
        "# regenerate: cargo run -p zkb-session --example generate_game_transcript"
    )
    .unwrap();
    writeln!(out, "profile = zkbattleship/reference/v1").unwrap();
    writeln!(out, "params_id = {}", hex(params.params_id())).unwrap();
    writeln!(out, "key_seed_role_a = {}", hex(&KEY_SEEDS[a_idx])).unwrap();
    writeln!(out, "key_seed_role_b = {}", hex(&KEY_SEEDS[b_idx])).unwrap();
    writeln!(out, "hello_role_a = {}", hello_of_role(Role::A)).unwrap();
    writeln!(out, "hello_role_b = {}", hello_of_role(Role::B)).unwrap();
    writeln!(out, "placement_role_a = {}", positions(0)).unwrap();
    writeln!(out, "placement_role_b = {}", positions(1)).unwrap();
    writeln!(
        out,
        "blinders_seed_role_a = chacha20rng(seed={})",
        hex(&BLINDER_SEEDS[0])
    )
    .unwrap();
    writeln!(
        out,
        "blinders_seed_role_b = chacha20rng(seed={})",
        hex(&BLINDER_SEEDS[1])
    )
    .unwrap();
    writeln!(
        out,
        "proof_finalize_rng_role_a = chacha20rng(seed={})",
        hex(&PROOF_RNG_SEEDS[0])
    )
    .unwrap();
    writeln!(
        out,
        "proof_finalize_rng_role_b = chacha20rng(seed={})",
        hex(&PROOF_RNG_SEEDS[1])
    )
    .unwrap();
    writeln!(
        out,
        "coin_rng_role_a = chacha20rng(seed={})",
        hex(&COIN_RNG_SEEDS[0])
    )
    .unwrap();
    writeln!(
        out,
        "coin_rng_role_b = chacha20rng(seed={})",
        hex(&COIN_RNG_SEEDS[1])
    )
    .unwrap();
    writeln!(out, "sid = {}", hex(bootstrap.sid())).unwrap();
    writeln!(out, "genesis_hash = {}", hex(bootstrap.genesis_hash())).unwrap();
    writeln!(out, "first_mover = {first_mover:?}").unwrap();
    writeln!(out, "winner = {winner:?}").unwrap();
    writeln!(out, "winner_hits = {winner_hits}").unwrap();
    writeln!(out, "winner_sunk_total = {winner_sunk_total}").unwrap();
    writeln!(out, "loser_hits = {loser_hits}").unwrap();
    writeln!(out, "frame_count = {}", frames.len()).unwrap();
    for (i, frame) in frames.iter().enumerate() {
        writeln!(out, "frame[{i:04}] = {}", hex(frame)).unwrap();
    }

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors");
    std::fs::create_dir_all(&dir).expect("create vectors dir");
    let path = dir.join("game_transcript_v1.txt");
    std::fs::write(&path, out).expect("write vector file");
    println!(
        "wrote {} ({} bytes, {} frames, winner {winner:?})",
        path.display(),
        std::fs::metadata(&path).unwrap().len(),
        frames.len()
    );
}
