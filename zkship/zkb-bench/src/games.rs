//! Complete scripted games through the real session layer (signed frames,
//! setup proofs, coin flip, answers), with per-frame bytes and CPU time.
//!
//! In-process mode drives both sessions from one thread, so every
//! `produce`/`fire_shot`/`accept` call is timed on its own. Network mode runs
//! each player in its own thread over TCP through a delay proxy and measures
//! what a player waits for: from firing a shot to having verified the answer.

use crate::stats::summarize;
use crate::Out;
use curve25519_dalek::scalar::Scalar;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use zkb_core::fleet::{Fleet, SHIP_BITS};
use zkb_core::game::{Role, ShotOutcome};
use zkb_core::params::{CellIndex, Parameters, Rules, BOARD_N, N};
use zkb_session::codec::{HEADER_LEN, SIGNATURE_LEN};
use zkb_session::frame::SignedFrame;
use zkb_session::hello::{self, Hello};
use zkb_session::identity::{ExpectedKey, IdentityKeypair, PeerAuthPolicy};
use zkb_session::state::{AcceptOutcome, Session};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// Row-major sweep.
    Sweep,
    /// Uniformly random order.
    Random,
    /// Parity hunt, then target the neighbours of unsunk hits.
    HuntTarget,
}

impl Strategy {
    pub fn parse(s: &str) -> Option<Strategy> {
        match s {
            "sweep" => Some(Strategy::Sweep),
            "random" => Some(Strategy::Random),
            "hunt-target" => Some(Strategy::HuntTarget),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Strategy::Sweep => "sweep",
            Strategy::Random => "random",
            Strategy::HuntTarget => "hunt-target",
        }
    }
}

/// A shooter's policy and its view of the opponent's board.
struct Shooter {
    strategy: Strategy,
    rng: ChaCha20Rng,
    order: Vec<u8>,
    shot: [bool; N],
    targets: VecDeque<u8>,
}

impl Shooter {
    fn new(strategy: Strategy, seed: u64) -> Shooter {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut order: Vec<u8> = (0..N as u8).collect();
        match strategy {
            Strategy::Sweep => {}
            Strategy::Random => order.shuffle(&mut rng),
            Strategy::HuntTarget => {
                // Checkerboard cells first (every ship covers one), each half shuffled.
                let (mut even, mut odd): (Vec<u8>, Vec<u8>) =
                    order.iter().partition(|&&i| (i / 10 + i % 10) % 2 == 0);
                even.shuffle(&mut rng);
                odd.shuffle(&mut rng);
                order = even.into_iter().chain(odd).collect();
            }
        }
        Shooter {
            strategy,
            rng,
            order,
            shot: [false; N],
            targets: VecDeque::new(),
        }
    }

    fn next(&mut self) -> CellIndex {
        while let Some(t) = self.targets.pop_front() {
            if !self.shot[t as usize] {
                return self.take(t);
            }
        }
        let i = self
            .order
            .iter()
            .position(|&c| !self.shot[c as usize])
            .expect("unshot cells remain");
        let c = self.order[i];
        self.take(c)
    }

    fn take(&mut self, c: u8) -> CellIndex {
        self.shot[c as usize] = true;
        CellIndex::from_index(c).unwrap()
    }

    fn observe(&mut self, cell: CellIndex, outcome: ShotOutcome) {
        if self.strategy != Strategy::HuntTarget {
            return;
        }
        match outcome {
            ShotOutcome::Hit => {
                let (r, c) = (cell.row() as i8, cell.col() as i8);
                let mut next: Vec<u8> = [(r - 1, c), (r + 1, c), (r, c - 1), (r, c + 1)]
                    .into_iter()
                    .filter(|&(r, c)| {
                        (0..BOARD_N as i8).contains(&r) && (0..BOARD_N as i8).contains(&c)
                    })
                    .map(|(r, c)| (r as u8) * BOARD_N as u8 + c as u8)
                    .filter(|&i| !self.shot[i as usize])
                    .collect();
                next.shuffle(&mut self.rng);
                self.targets.extend(next);
            }
            // The sunk ship's cells are announced; remaining targets may
            // belong to another ship, so keep them.
            ShotOutcome::Sunk { .. } | ShotOutcome::Miss | ShotOutcome::Win => {}
        }
    }
}

fn blinders(seed: u64) -> Vec<Scalar> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    (0..SHIP_BITS).map(|_| Scalar::random(&mut rng)).collect()
}

fn auth(key: &IdentityKeypair) -> zkb_session::identity::AuthenticatedPeer {
    ExpectedKey::new(key.peer_key())
        .authenticate(&key.peer_key())
        .unwrap()
}

fn message_name(frame: &[u8]) -> &'static str {
    match SignedFrame::decode(frame).map(|f| f.header().message_type.to_u8()) {
        Ok(1) => "commit",
        Ok(2) => "coin_commit",
        Ok(3) => "coin_nonce",
        Ok(4) => "coin_reveal",
        Ok(5) => "shot",
        Ok(6) => match frame[HEADER_LEN] {
            0 => "answer_miss",
            1 => "answer_hit",
            _ => "answer_sunk",
        },
        Ok(7) => "resign",
        _ => "?",
    }
}

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1e3
}

fn role_ix(role: Role) -> usize {
    match role {
        Role::A => 0,
        Role::B => 1,
    }
}

pub struct GameConfig {
    pub rules: Rules,
    pub strategy: Strategy,
    pub games: usize,
    pub seed: u64,
}

/// Bootstraps two sessions (A, B) with seeded identities and fleets.
fn sessions<'a>(
    params: &'a Parameters,
    keys: &'a [IdentityKeypair; 2],
    seed: u64,
) -> (Session<'a>, Session<'a>, [Fleet; 2]) {
    let params_id = *params.params_id();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let hellos: Vec<Hello> = keys
        .iter()
        .map(|k| Hello::create(k, params_id, &mut rng))
        .collect();
    let checked: Vec<_> = keys
        .iter()
        .zip(hellos)
        .map(|(k, h)| hello::check_hello(h, &params_id, &ExpectedKey::new(k.peer_key())).unwrap())
        .collect();
    let bootstrap = hello::complete_bootstrap(checked[0].clone(), checked[1].clone()).unwrap();
    let a = if bootstrap.role_of(&keys[0].peer_key()) == Role::A {
        0
    } else {
        1
    };
    let fleets = [
        Fleet::random(&mut rng, params.rules()),
        Fleet::random(&mut rng, params.rules()),
    ];
    let make = |k: usize, role: Role, fleet: &Fleet| {
        Session::new(
            params,
            &keys[k],
            role,
            auth(&keys[1 - k]),
            *bootstrap.sid(),
            *bootstrap.genesis_hash(),
            fleet.clone(),
            blinders(seed ^ (k as u64 + 1)),
        )
        .unwrap()
    };
    (
        make(a, Role::A, &fleets[0]),
        make(1 - a, Role::B, &fleets[1]),
        fleets,
    )
}

pub fn run_local(out: &mut Out, cfg: &GameConfig) {
    let params = Parameters::for_rules(cfg.rules);
    let rules = match cfg.rules {
        Rules::Standard => "standard",
        Rules::NoTouch => "no-touch",
    };
    for g in 0..cfg.games {
        let seed = cfg.seed + g as u64;
        let keys = [
            IdentityKeypair::from_seed(&[seed as u8 ^ 0x11; 32]),
            IdentityKeypair::from_seed(&[seed as u8 ^ 0x22; 32]),
        ];
        let (sa, sb, _fleets) = sessions(params, &keys, seed);
        let mut s = [sa, sb];
        let mut shooters = [
            Shooter::new(cfg.strategy, seed * 2),
            Shooter::new(cfg.strategy, seed * 2 + 1),
        ];
        let mut coin_rng = ChaCha20Rng::seed_from_u64(seed ^ 0xC01);
        let mut frames = 0usize;
        // Per player: bytes sent, payload bytes sent, CPU ms, setup CPU ms.
        let mut sent = [0usize; 2];
        let mut payload = [0usize; 2];
        let mut cpu = [0f64; 2];
        let mut setup_cpu = [0f64; 2];
        let mut counts = [[0usize; 3]; 2]; // misses, hits, sinks (as shooter)

        let mut log = |out: &mut Out, from: usize, bytes: &[u8], produce: f64, accept: f64| {
            frames += 1;
            let name = message_name(bytes);
            out.line(
                "game_frames.csv",
                "rules,strategy,game,seq,sender,message,frame_bytes,payload_bytes,produce_ms,accept_ms",
                &format!(
                    "{rules},{},{g},{frames},{},{name},{},{},{produce:.4},{accept:.4}",
                    cfg.strategy.name(),
                    ["A", "B"][from],
                    bytes.len(),
                    bytes.len() - HEADER_LEN - SIGNATURE_LEN
                ),
            );
        };

        // Commit and coin: whoever owes a frame produces it; the other accepts.
        let mut first_mover = None;
        for _ in 0..16 {
            for from in 0..2 {
                loop {
                    let start = Instant::now();
                    let produced = s[from]
                        .produce_with_rng(
                            &mut coin_rng,
                            ChaCha20Rng::seed_from_u64(seed ^ from as u64),
                        )
                        .unwrap();
                    let t_prod = ms(start);
                    let Some(frame) = produced else { break };
                    let start = Instant::now();
                    let outcome = s[1 - from].accept(frame.bytes()).unwrap();
                    let t_acc = ms(start);
                    cpu[from] += t_prod;
                    cpu[1 - from] += t_acc;
                    if message_name(frame.bytes()) == "commit" {
                        setup_cpu[from] += t_prod;
                        setup_cpu[1 - from] += t_acc;
                    }
                    sent[from] += frame.bytes().len();
                    payload[from] += frame.bytes().len() - HEADER_LEN - SIGNATURE_LEN;
                    log(out, from, frame.bytes(), t_prod, t_acc);
                    if let AcceptOutcome::GameReady { first_mover: fm } = outcome {
                        first_mover = Some(fm);
                    }
                }
            }
            if first_mover.is_some() && s[0].game().is_some() && s[1].game().is_some() {
                break;
            }
        }
        let first_mover = first_mover.expect("coin flip resolved");

        let mut current = role_ix(first_mover);
        let winner = loop {
            let def = 1 - current;
            let cell = shooters[current].next();
            let start = Instant::now();
            let shot = s[current].fire_shot(cell).unwrap();
            let t_fire = ms(start);
            let start = Instant::now();
            let answer = match s[def].accept(shot.bytes()).unwrap() {
                AcceptOutcome::ShotReceived { answer, .. } => answer,
                other => panic!("expected ShotReceived, got {other:?}"),
            };
            let t_answer = ms(start);
            let start = Instant::now();
            let outcome = s[current].accept(answer.bytes()).unwrap();
            let t_check = ms(start);
            cpu[current] += t_fire + t_check;
            cpu[def] += t_answer;
            sent[current] += shot.bytes().len();
            sent[def] += answer.bytes().len();
            payload[current] += 1;
            payload[def] += answer.bytes().len() - HEADER_LEN - SIGNATURE_LEN;
            log(out, current, shot.bytes(), t_fire, 0.0);
            log(out, def, answer.bytes(), t_answer, t_check);
            let result = match outcome {
                AcceptOutcome::Answer(o) => o,
                AcceptOutcome::GameFinished { .. } => ShotOutcome::Win,
                other => panic!("expected Answer, got {other:?}"),
            };
            match result {
                ShotOutcome::Miss => counts[current][0] += 1,
                ShotOutcome::Hit => counts[current][1] += 1,
                ShotOutcome::Sunk { .. } | ShotOutcome::Win => {
                    counts[current][1] += 1;
                    counts[current][2] += 1;
                }
            }
            shooters[current].observe(cell, result);
            if result == ShotOutcome::Win {
                break current;
            }
            current = def;
        };
        for p in 0..2 {
            out.line(
                "games.csv",
                "rules,strategy,game,seed,player,winner,shots,misses,hits,sinks,frames_total,bytes_sent,payload_sent,cpu_ms,setup_cpu_ms",
                &format!(
                    "{rules},{},{g},{seed},{},{},{},{},{},{},{frames},{},{},{:.3},{:.3}",
                    cfg.strategy.name(),
                    ["A", "B"][p],
                    u8::from(winner == p),
                    counts[p][0] + counts[p][1],
                    counts[p][0],
                    counts[p][1],
                    counts[p][2],
                    sent[p],
                    payload[p],
                    cpu[p],
                    setup_cpu[p],
                ),
            );
        }
        eprintln!(
            "game {g} ({rules}, {}): winner {} after {} frames; bytes A {} B {}; cpu A {:.1} ms B {:.1} ms",
            cfg.strategy.name(),
            ["A", "B"][winner],
            frames,
            sent[0],
            sent[1],
            cpu[0],
            cpu[1]
        );
    }
}

// ---------------------------------------------------------------------------
// Network mode.

fn send(stream: &mut TcpStream, bytes: &[u8]) {
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
}

fn recv(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
    stream.read_exact(&mut buf).unwrap();
    buf
}

/// One direction of the delay proxy: every chunk is released `delay` after
/// it was read, and at most `bytes_per_sec` (0 = unlimited).
fn pipe(mut from: TcpStream, mut to: TcpStream, delay: Duration, bytes_per_sec: f64) {
    let (tx, rx) = mpsc::channel::<(Instant, Vec<u8>)>();
    let reader = std::thread::spawn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send((Instant::now(), buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut link_free = Instant::now();
    for (at, chunk) in rx {
        let mut release = at + delay;
        if bytes_per_sec > 0.0 {
            let start = link_free.max(at);
            link_free = start + Duration::from_secs_f64(chunk.len() as f64 / bytes_per_sec);
            release = link_free + delay;
        }
        if let Some(wait) = release.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
        if to.write_all(&chunk).is_err() {
            break;
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
    let _ = reader.join();
}

/// A connected pair `(a, b)` whose traffic crosses the proxy.
fn proxied_pair(one_way: Duration, bytes_per_sec: f64) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let a = TcpStream::connect(addr).unwrap();
    let (a_side, _) = listener.accept().unwrap();
    let b = TcpStream::connect(addr).unwrap();
    let (b_side, _) = listener.accept().unwrap();
    for s in [&a, &b, &a_side, &b_side] {
        s.set_nodelay(true).unwrap();
    }
    let (a_in, b_out) = (a_side.try_clone().unwrap(), b_side.try_clone().unwrap());
    std::thread::spawn(move || pipe(a_side, b_side, one_way, bytes_per_sec));
    std::thread::spawn(move || pipe(b_out, a_in, one_way, bytes_per_sec));
    (a, b)
}

struct NetRecord {
    turns: Vec<(usize, f64)>,
    setup_ms: f64,
    total_ms: f64,
}

/// Runs one player to the end of the game; returns its timings.
#[allow(clippy::too_many_arguments)]
fn net_player(
    params: &Parameters,
    key: &IdentityKeypair,
    peer: &IdentityKeypair,
    mut stream: TcpStream,
    fleet: Fleet,
    rho: Vec<Scalar>,
    strategy: Strategy,
    seed: u64,
    barrier: std::sync::Arc<std::sync::Barrier>,
) -> NetRecord {
    let params_id = *params.params_id();
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x4e7);
    // Bootstrap (not timed).
    let hello = Hello::create(key, params_id, &mut rng);
    send(&mut stream, &hello.encode());
    let peer_hello = Hello::decode(&recv(&mut stream)).unwrap();
    let own = hello::check_hello(hello, &params_id, &ExpectedKey::new(key.peer_key())).unwrap();
    let theirs =
        hello::check_hello(peer_hello, &params_id, &ExpectedKey::new(peer.peer_key())).unwrap();
    let (first, second) = if key.peer_key() < peer.peer_key() {
        (own, theirs)
    } else {
        (theirs, own)
    };
    let bootstrap = hello::complete_bootstrap(first, second).unwrap();
    let role = bootstrap.role_of(&key.peer_key());
    let mut session = Session::new(
        params,
        key,
        role,
        auth(peer),
        *bootstrap.sid(),
        *bootstrap.genesis_hash(),
        fleet,
        rho,
    )
    .unwrap();
    barrier.wait();
    let start = Instant::now();

    // Commit and coin.
    let first_mover = loop {
        while let Some(f) = session.produce(&mut rng).unwrap() {
            send(&mut stream, f.bytes());
        }
        if let AcceptOutcome::GameReady { first_mover } =
            session.accept(&recv(&mut stream)).unwrap()
        {
            while let Some(f) = session.produce(&mut rng).unwrap() {
                send(&mut stream, f.bytes());
            }
            break first_mover;
        }
    };
    let setup_ms = ms(start);

    let mut shooter = Shooter::new(strategy, seed);
    let mut turns = Vec::new();
    let mut current = first_mover;
    loop {
        if current == role {
            let cell = shooter.next();
            let t0 = Instant::now();
            let shot = session.fire_shot(cell).unwrap();
            send(&mut stream, shot.bytes());
            let outcome = session.accept(&recv(&mut stream)).unwrap();
            turns.push((turns.len(), ms(t0)));
            match outcome {
                AcceptOutcome::Answer(o) => shooter.observe(cell, o),
                AcceptOutcome::GameFinished { .. } => break,
                other => panic!("unexpected {other:?}"),
            }
        } else {
            match session.accept(&recv(&mut stream)).unwrap() {
                AcceptOutcome::ShotReceived { answer, winner, .. } => {
                    send(&mut stream, answer.bytes());
                    if winner.is_some() {
                        break;
                    }
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        current = current.other();
    }
    NetRecord {
        turns,
        setup_ms,
        total_ms: ms(start),
    }
}

pub struct NetConfig {
    pub game: GameConfig,
    pub rtt_ms: f64,
    pub mbps: f64,
}

pub fn run_net(out: &mut Out, cfg: &NetConfig) {
    let params = Parameters::for_rules(cfg.game.rules);
    let one_way = Duration::from_secs_f64(cfg.rtt_ms / 2e3);
    let bps = cfg.mbps * 1e6 / 8.0;
    for g in 0..cfg.game.games {
        let seed = cfg.game.seed + g as u64;
        let keys = [
            IdentityKeypair::from_seed(&[seed as u8 ^ 0x11; 32]),
            IdentityKeypair::from_seed(&[seed as u8 ^ 0x22; 32]),
        ];
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let fleets = [
            Fleet::random(&mut rng, params.rules()),
            Fleet::random(&mut rng, params.rules()),
        ];
        let (sa, sb) = proxied_pair(one_way, bps);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let records: Vec<NetRecord> = std::thread::scope(|scope| {
            let handles: Vec<_> = [sa, sb]
                .into_iter()
                .enumerate()
                .map(|(k, stream)| {
                    let (key, peer) = (&keys[k], &keys[1 - k]);
                    let fleet = fleets[k].clone();
                    let rho = blinders(seed ^ (k as u64 + 1) ^ rng.gen::<u64>());
                    let barrier = barrier.clone();
                    let strategy = cfg.game.strategy;
                    scope.spawn(move || {
                        net_player(
                            params,
                            key,
                            peer,
                            stream,
                            fleet,
                            rho,
                            strategy,
                            seed * 2 + k as u64,
                            barrier,
                        )
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let rules = match cfg.game.rules {
            Rules::Standard => "standard",
            Rules::NoTouch => "no-touch",
        };
        for (k, rec) in records.iter().enumerate() {
            for (t, lat) in &rec.turns {
                out.line(
                    "net_turns.csv",
                    "rules,strategy,rtt_ms,mbps,game,player,turn,shot_to_verified_ms",
                    &format!(
                        "{rules},{},{},{},{g},{k},{t},{lat:.4}",
                        cfg.game.strategy.name(),
                        cfg.rtt_ms,
                        cfg.mbps
                    ),
                );
            }
            let lats: Vec<f64> = rec.turns.iter().map(|x| x.1).collect();
            let s = summarize(&lats);
            out.line(
                "net_games.csv",
                "rules,strategy,rtt_ms,mbps,game,player,turns,setup_ms,total_ms,turn_median_ms,turn_p95_ms",
                &format!(
                    "{rules},{},{},{},{g},{k},{},{:.3},{:.3},{:.4},{:.4}",
                    cfg.game.strategy.name(),
                    cfg.rtt_ms,
                    cfg.mbps,
                    lats.len(),
                    rec.setup_ms,
                    rec.total_ms,
                    s.median,
                    s.p95
                ),
            );
        }
        let s = summarize(
            &records
                .iter()
                .flat_map(|r| r.turns.iter().map(|x| x.1))
                .collect::<Vec<_>>(),
        );
        eprintln!(
            "net game {g} rtt {} ms: setup {:.1} ms, total {:.1} ms, turn median {:.3} ms p95 {:.3} ms",
            cfg.rtt_ms, records[0].setup_ms, records[0].total_ms, s.median, s.p95
        );
    }
}
