//! Per-operation timings: setup proving/verification and every kind of shot
//! answer, each timed on the prover (defender) and verifier (shooter) side.
//!
//! Answer states are built once and reused: answering and checking are pure
//! functions of the board state, so repeated samples measure the same work.

use crate::stats::summarize;
use crate::Out;
use curve25519_dalek::scalar::Scalar;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;
use std::time::Instant;
use zkb_core::answers::{self, AnswerContext, BoardShots, ResponderSecrets, ShotAnswer};
use zkb_core::fleet::{Fleet, SHIP_BITS};
use zkb_core::params::{CellIndex, Parameters, Rules, FLEET_LENGTHS, K, N};
use zkb_core::setup::{self, SetupMessage, VerifiedSetup};

const ID: [u8; 32] = [0xD1; 32];
const SID: [u8; 32] = [0x5D; 32];

pub struct Config {
    pub setup_iters: usize,
    pub answer_iters: usize,
    pub warmup: usize,
    pub fleets: usize,
}

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1e3
}

struct Series {
    rows: Vec<(String, f64)>,
}

impl Series {
    fn new() -> Series {
        Series { rows: Vec::new() }
    }
}

fn record(
    out: &mut Out,
    raw: &mut Series,
    op: &str,
    rules: &str,
    variant: &str,
    bytes: usize,
    samples: &[f64],
) {
    for (i, s) in samples.iter().enumerate() {
        raw.rows.push((format!("{op},{rules},{variant},{i}"), *s));
    }
    let s = summarize(samples);
    out.line(
        "ops_summary.csv",
        "op,rules,variant,bytes,n,median_ms,p95_ms,min_ms,max_ms,mean_ms,sd_ms",
        &format!(
            "{op},{rules},{variant},{bytes},{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4}",
            s.n, s.median, s.p95, s.min, s.max, s.mean, s.sd
        ),
    );
    eprintln!(
        "{op:<22} {rules:<9} {variant:<14} {bytes:>6} B  median {:>9.3} ms  p95 {:>9.3} ms  (n={})",
        s.median, s.p95, s.n
    );
}

fn blinders(rng: &mut ChaCha20Rng) -> Vec<Scalar> {
    (0..SHIP_BITS).map(|_| Scalar::random(rng)).collect()
}

fn rules_name(rules: Rules) -> &'static str {
    match rules {
        Rules::Standard => "standard",
        Rules::NoTouch => "no-touch",
    }
}

pub fn run(out: &mut Out, cfg: &Config) {
    let mut raw = Series::new();
    for rules in [Rules::Standard, Rules::NoTouch] {
        setup_ops(out, &mut raw, cfg, rules);
    }
    answer_ops(out, &mut raw, cfg);
    rejection_ops(out, &mut raw, cfg);
    for (key, ms) in &raw.rows {
        out.line(
            "ops_raw.csv",
            "op,rules,variant,iter,ms",
            &format!("{key},{ms:.5}"),
        );
    }
}

fn setup_ops(out: &mut Out, raw: &mut Series, cfg: &Config, rules: Rules) {
    let params = Parameters::for_rules(rules);
    let name = rules_name(rules);
    let mut rng = ChaCha20Rng::seed_from_u64(0x5e7 + rules as u64);
    let fleets: Vec<Fleet> = (0..cfg.fleets)
        .map(|_| Fleet::random(&mut rng, rules))
        .collect();
    let rhos: Vec<Vec<Scalar>> = (0..cfg.fleets).map(|_| blinders(&mut rng)).collect();

    // Prove: commitments plus legality proof, from a fixed witness.
    let mut msgs: Vec<SetupMessage> = Vec::new();
    let mut prove = Vec::with_capacity(cfg.setup_iters);
    for i in 0..cfg.warmup + cfg.setup_iters {
        let k = i % cfg.fleets;
        let finalize = ChaCha20Rng::seed_from_u64(i as u64);
        let start = Instant::now();
        let msg = setup::prove_with_rng(params, &ID, &SID, &fleets[k], &rhos[k], finalize).unwrap();
        let t = ms(start);
        if i >= cfg.warmup {
            prove.push(t);
        }
        if msgs.len() < cfg.fleets {
            msgs.push(black_box(msg));
        }
    }
    let bytes: Vec<Vec<u8>> = msgs.iter().map(|m| m.encode()).collect();
    let len = bytes[0].len();
    record(out, raw, "setup_prove", name, "-", len, &prove);

    let mut encode = Vec::new();
    let mut decode = Vec::new();
    let mut verify = Vec::new();
    let mut total = Vec::new();
    for i in 0..cfg.warmup + cfg.setup_iters {
        let k = i % cfg.fleets;
        let start = Instant::now();
        black_box(msgs[k].encode());
        let t_enc = ms(start);
        let start = Instant::now();
        let msg = SetupMessage::decode(&bytes[k], rules).unwrap();
        let t_dec = ms(start);
        let start = Instant::now();
        black_box(setup::verify(params, &ID, &SID, &msg).unwrap());
        let t_ver = ms(start);
        if i >= cfg.warmup {
            encode.push(t_enc);
            decode.push(t_dec);
            verify.push(t_ver);
            total.push(t_dec + t_ver);
        }
    }
    record(out, raw, "setup_encode", name, "-", len, &encode);
    record(out, raw, "setup_decode", name, "-", len, &decode);
    record(out, raw, "setup_verify", name, "-", len, &verify);
    record(out, raw, "setup_decode+verify", name, "-", len, &total);
}

/// A defender's board after some shots, with the matching public view.
struct State {
    verified: VerifiedSetup,
    board: BoardShots,
    secrets: ResponderSecrets,
}

impl State {
    fn new(params: &Parameters, fleet: &Fleet, rng: &mut ChaCha20Rng) -> State {
        let rho = blinders(rng);
        let msg = setup::prove_with_rng(params, &ID, &SID, fleet, &rho, rng.clone()).unwrap();
        State {
            verified: setup::verify(params, &ID, &SID, &msg).unwrap(),
            board: BoardShots::default(),
            secrets: ResponderSecrets::new(fleet, rho),
        }
    }

    fn register(&mut self, cell: CellIndex) {
        self.board.register(self.verified.ship_cells(), cell);
        self.secrets.register(cell);
    }

    /// Plays shots answering honestly and recording sink announcements.
    fn play(&mut self, params: &Parameters, cells: &[CellIndex], rng: &mut ChaCha20Rng) {
        for &cell in cells {
            self.register(cell);
            let ctx = AnswerContext {
                defender_id: &ID,
                sid: &SID,
            };
            let answer = answers::answer_shot(params, &ctx, &self.board, &self.secrets, cell, rng);
            if let ShotAnswer::Sunk { ship, .. } = answer {
                self.board.mark_sunk(ship);
            }
        }
    }
}

/// `(variant, state, shot cell)` for every answer shape.
fn scenarios(
    params: &Parameters,
    fleet: &Fleet,
    rng: &mut ChaCha20Rng,
) -> Vec<(String, State, CellIndex)> {
    let occupied = fleet.occupied();
    let empty = (0..N as u8)
        .map(|i| CellIndex::from_index(i).unwrap())
        .find(|c| !occupied[c.index() as usize])
        .unwrap();
    let mut out = Vec::new();

    let mut s = State::new(params, fleet, rng);
    s.register(empty);
    out.push(("miss".to_string(), s, empty));

    // Plain hits on ship 0 with 5..1 unsunk ships: sink ships K-1 down first.
    for sunk_first in 0..K {
        let unsunk = K - sunk_first;
        let mut s = State::new(params, fleet, rng);
        let cells: Vec<CellIndex> = (K - sunk_first..K).flat_map(|j| fleet.cells(j)).collect();
        s.play(params, &cells, rng);
        let target = fleet.cells(0)[0];
        s.register(target);
        out.push((format!("hit_unsunk{unsunk}"), s, target));
    }

    // Sink announcements, one per ship length.
    for j in [0usize, 1, 2, 4] {
        let mut s = State::new(params, fleet, rng);
        let cells = fleet.cells(j);
        let (last, rest) = cells.split_last().unwrap();
        s.play(params, rest, rng);
        s.register(*last);
        out.push((format!("sunk_len{}", FLEET_LENGTHS[j]), s, *last));
    }
    out
}

fn answer_ops(out: &mut Out, raw: &mut Series, cfg: &Config) {
    let params = Parameters::standard();
    let mut rng = ChaCha20Rng::seed_from_u64(0xa45);
    let fleets: Vec<Fleet> = (0..cfg.fleets.min(4))
        .map(|_| Fleet::random(&mut rng, Rules::Standard))
        .collect();
    let mut by_variant: Vec<(String, Vec<(State, CellIndex)>)> = Vec::new();
    for fleet in &fleets {
        for (variant, state, cell) in scenarios(params, fleet, &mut rng) {
            match by_variant.iter_mut().find(|(v, _)| *v == variant) {
                Some((_, list)) => list.push((state, cell)),
                None => by_variant.push((variant, vec![(state, cell)])),
            }
        }
    }
    let ctx = AnswerContext {
        defender_id: &ID,
        sid: &SID,
    };
    for (variant, states) in &by_variant {
        let (mut answer_t, mut verify_t, mut decode_t) = (Vec::new(), Vec::new(), Vec::new());
        let mut len = 0;
        let mut order: Vec<usize> = (0..cfg.warmup + cfg.answer_iters)
            .map(|i| i % states.len())
            .collect();
        order.shuffle(&mut rng);
        for (i, &k) in order.iter().enumerate() {
            let (state, cell) = &states[k];
            let start = Instant::now();
            let answer =
                answers::answer_shot(params, &ctx, &state.board, &state.secrets, *cell, &mut rng);
            let bytes = answer.encode();
            let t_ans = ms(start);
            let start = Instant::now();
            let decoded = ShotAnswer::decode(&bytes, state.board.unsunk_count()).unwrap();
            let t_dec = ms(start);
            let start = Instant::now();
            let outcome = answers::verify_answer(
                params,
                &ctx,
                state.verified.ship_cells(),
                state.verified.cell_commitments(),
                &state.board,
                *cell,
                &decoded,
            );
            let t_ver = ms(start);
            assert!(outcome.is_ok(), "{variant}: {outcome:?}");
            len = bytes.len();
            if i >= cfg.warmup {
                answer_t.push(t_ans);
                decode_t.push(t_dec);
                verify_t.push(t_ver);
            }
        }
        record(
            out,
            raw,
            "answer_produce",
            "standard",
            variant,
            len,
            &answer_t,
        );
        record(
            out,
            raw,
            "answer_decode",
            "standard",
            variant,
            len,
            &decode_t,
        );
        record(
            out,
            raw,
            "answer_verify",
            "standard",
            variant,
            len,
            &verify_t,
        );
    }
}

/// One prove and one verify, nothing else: the process's peak RSS is the
/// setup's memory cost (plus the binary and the profile's tables).
pub fn setup_once(rules: Rules) {
    let params = Parameters::for_rules(rules);
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let fleet = Fleet::random(&mut rng, rules);
    let msg = setup::prove(params, &ID, &SID, &fleet, &blinders(&mut rng)).unwrap();
    black_box(setup::verify(params, &ID, &SID, &msg).unwrap());
}

/// First use of each profile in a fresh process: hashing the generators and
/// building the fixed-base tables.
pub fn cold_init() {
    for rules in [Rules::Standard, Rules::NoTouch] {
        let start = Instant::now();
        black_box(Parameters::for_rules(rules));
        println!("cold_init,{},{:.4}", rules_name(rules), ms(start));
    }
}

/// Exact encodings: cryptographic payload (the abstract's count), the
/// message as sent (with its tag byte), and the signed frame.
pub fn sizes(out: &mut Out) {
    let frame = zkb_session::codec::HEADER_LEN + zkb_session::codec::SIGNATURE_LEN;
    let row = |out: &mut Out, message: &str, crypto: usize, payload: usize| {
        out.line(
            "sizes.csv",
            "message,crypto_bytes,payload_bytes,frame_bytes",
            &format!("{message},{crypto},{payload},{}", payload + frame),
        );
        eprintln!(
            "{message:<24} crypto {crypto:>6}  payload {payload:>6}  frame {:>6}",
            payload + frame
        );
    };
    let mut rng = ChaCha20Rng::seed_from_u64(0x512e);
    for rules in [Rules::Standard, Rules::NoTouch] {
        let params = Parameters::for_rules(rules);
        let fleet = Fleet::random(&mut rng, rules);
        let msg = setup::prove(params, &ID, &SID, &fleet, &blinders(&mut rng)).unwrap();
        let len = msg.encode().len();
        row(out, &format!("setup_{}", rules_name(rules)), len, len);
    }
    // The Hello is sent before any frame exists: version, params_id, key,
    // nonce, signature.
    let hello = zkb_session::hello::Hello::LEN;
    out.line(
        "sizes.csv",
        "message,crypto_bytes,payload_bytes,frame_bytes",
        &format!("hello_unframed,0,{hello},{hello}"),
    );
    row(out, "coin_message", 32, 32);
    row(out, "shot", 1, 1);
    let params = Parameters::standard();
    let fleet = Fleet::random(&mut rng, Rules::Standard);
    let ctx = AnswerContext {
        defender_id: &ID,
        sid: &SID,
    };
    for (variant, state, cell) in scenarios(params, &fleet, &mut rng) {
        let answer =
            answers::answer_shot(params, &ctx, &state.board, &state.secrets, cell, &mut rng);
        let len = answer.encode().len();
        // Tag byte; a sink announcement also names the ship and its cells.
        let crypto = match &answer {
            ShotAnswer::Sunk { openings, .. } => 32 + 32 * openings.len(),
            _ => len - 1,
        };
        row(out, &format!("answer_{variant}"), crypto, len);
    }
}

/// Flips the lowest bit of the scalar ending `from_end` bytes before the end
/// of `bytes`; the result stays canonical for any scalar below `2^252`.
fn flip_scalar(bytes: &mut [u8], from_end: usize) {
    let at = bytes.len() - from_end;
    bytes[at] ^= 1;
}

/// What refusing a forged message costs the receiver: an early failure (first
/// check) and a late one (the last check, so the whole verification runs).
fn rejection_ops(out: &mut Out, raw: &mut Series, cfg: &Config) {
    let params = Parameters::standard();
    let mut rng = ChaCha20Rng::seed_from_u64(0x4e7);
    let fleet = Fleet::random(&mut rng, Rules::Standard);
    let msg = setup::prove(params, &ID, &SID, &fleet, &blinders(&mut rng)).unwrap();

    let mut early = msg.clone();
    early.length_openings[0] += Scalar::ONE;
    let mut late = msg.encode();
    flip_scalar(&mut late, 32); // last scalar of the bit proof
    let late = SetupMessage::decode(&late, Rules::Standard).unwrap();
    for (variant, forged) in [("early_length", &early), ("late_bit_proof", &late)] {
        let mut samples = Vec::new();
        for i in 0..cfg.warmup + cfg.setup_iters {
            let start = Instant::now();
            let result = setup::verify(params, &ID, &SID, forged);
            let t = ms(start);
            assert!(result.is_err());
            if i >= cfg.warmup {
                samples.push(t);
            }
        }
        record(
            out,
            raw,
            "setup_reject",
            "standard",
            variant,
            msg.encode().len(),
            &samples,
        );
    }

    let ctx = AnswerContext {
        defender_id: &ID,
        sid: &SID,
    };
    let mut state = State::new(params, &fleet, &mut rng);
    let target = fleet.cells(0)[0];
    state.register(target);
    let honest = answers::answer_shot(params, &ctx, &state.board, &state.secrets, target, &mut rng);
    let ShotAnswer::Hit { rho, .. } = &honest else {
        panic!("first cell of a ship is a hit")
    };
    let false_miss = ShotAnswer::Miss { rho: *rho };
    let mut bytes = honest.encode();
    flip_scalar(&mut bytes, 32); // last scalar of the not-sunk proof
    let bad_proof = ShotAnswer::decode(&bytes, state.board.unsunk_count()).unwrap();
    for (variant, forged) in [
        ("false_miss", &false_miss),
        ("late_range_proof", &bad_proof),
    ] {
        let mut samples = Vec::new();
        for i in 0..cfg.warmup + cfg.answer_iters {
            let start = Instant::now();
            let result = answers::verify_answer(
                params,
                &ctx,
                state.verified.ship_cells(),
                state.verified.cell_commitments(),
                &state.board,
                target,
                forged,
            );
            let t = ms(start);
            assert!(result.is_err());
            if i >= cfg.warmup {
                samples.push(t);
            }
        }
        record(
            out,
            raw,
            "answer_reject",
            "standard",
            variant,
            forged.encode().len(),
            &samples,
        );
    }
}
