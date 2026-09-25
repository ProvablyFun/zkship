//! Input: byte 0 = valid setup frames (0-5), byte 1 = honest exchanges (0-199),
//! then 3-byte adversarial instructions (at most 16). Under cfg(fuzzing) verified
//! prefixes are cached via Clone; mutated frames still pass ordinary
//! signature/proof verification.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zkb_core::answers::{self, BoardShots};
use zkb_core::fleet::Fleet;
use zkb_core::game::Role;
use zkb_core::params::{CellIndex, Parameters, Rules, FLEET_LENGTHS, K, N};
use zkb_session::codec::{
    MessageType, ANSWER_MISS_LEN, COMMIT_NO_TOUCH_PAYLOAD_LEN, COMMIT_PAYLOAD_LEN,
};
use zkb_session::frame::SignedFrame;
use zkb_session::identity::{ExpectedKey, IdentityKeypair, PeerAuthPolicy};
use zkb_session::state::{AcceptOutcome, Session, SessionError};

// Row, column, vertical per ship (lengths 5, 4, 3, 3, 2).
const FLEET_A: [u8; 15] = [0, 0, 0, 2, 0, 0, 4, 0, 0, 5, 0, 0, 7, 0, 0];
const FLEET_B: [u8; 15] = [0, 5, 0, 1, 0, 0, 1, 4, 0, 3, 0, 0, 5, 0, 0];

fn board(shots: &BoardShots) -> (u8, [bool; K]) {
    (shots.shots(), *shots.sunk())
}

// Class-B input must leave inspectable state unchanged.
fn accept(session: &mut Session<'_>, bytes: &[u8]) -> Result<AcceptOutcome, SessionError> {
    let snapshot = |s: &Session<'_>| {
        (
            s.head_sequence(),
            *s.head_hash(),
            s.transcript().len(),
            s.expected_sender(),
            s.winner(),
            s.game().map(|g| {
                (
                    g.state(),
                    g.verified_hits(),
                    g.hits_conceded(),
                    g.peer_sunk(),
                    board(g.shots_on_board(Role::A)),
                    board(g.shots_on_board(Role::B)),
                )
            }),
        )
    };
    let before = snapshot(session);
    let result = session.accept(bytes);
    if matches!(result, Err(SessionError::ClassB(_))) {
        assert_eq!(before, snapshot(session));
    }
    assert!(!matches!(result, Err(SessionError::InternalInvariant(_))));
    result
}

fn deliver(session: &mut Session<'_>, frame: &SignedFrame) -> AcceptOutcome {
    let result = accept(session, frame.bytes()).expect("honest frame accepted");
    assert!(matches!(
        accept(session, frame.bytes()),
        Err(SessionError::ClassB(_))
    ));
    result
}

fn unshot(shooter: &Session<'_>, defender: Role, choice: u8) -> CellIndex {
    (0..N)
        .map(|offset| (usize::from(choice) + offset) % N)
        .map(|index| CellIndex::from_index(index as u8).unwrap())
        .find(|cell| {
            !shooter
                .game()
                .unwrap()
                .shots_on_board(defender)
                .is_shot(*cell)
        })
        .expect("unshot cell before game ends")
}

fn play(shooter: &mut Session<'_>, defender: &mut Session<'_>, choice: u8) {
    let cell = unshot(shooter, defender.local_role(), choice);
    let shot = shooter.fire_shot(cell).unwrap();
    let AcceptOutcome::ShotReceived { answer, .. } = deliver(defender, &shot) else {
        panic!("honest shot produces answer");
    };
    deliver(shooter, &answer);
    assert_eq!(shooter.head_hash(), defender.head_hash());
    assert_eq!(shooter.winner(), defender.winner());
    let (shooter_game, defender_game) = (shooter.game().unwrap(), defender.game().unwrap());
    assert_eq!(
        shooter_game.peer_sunk(),
        *defender_game.shots_on_board(defender.local_role()).sunk()
    );
    assert_eq!(shooter_game.verified_hits(), defender_game.hits_conceded());
}

type Pair = (Session<'static>, Session<'static>);

fn keys() -> &'static [IdentityKeypair; 2] {
    use std::sync::OnceLock;
    static KEYS: OnceLock<[IdentityKeypair; 2]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [
            IdentityKeypair::from_seed(&[0x22; 32]),
            IdentityKeypair::from_seed(&[0x11; 32]),
        ]
    })
}

fn fresh_pair() -> Pair {
    let params = Parameters::standard();
    let keys = keys();
    let peer = |key: &IdentityKeypair| {
        ExpectedKey::new(key.peer_key())
            .authenticate(&key.peer_key())
            .unwrap()
    };
    let a = Session::new(
        params,
        &keys[0],
        Role::A,
        peer(&keys[1]),
        [3; 32],
        [4; 32],
        Fleet::from_bytes(&FLEET_A, Rules::Standard).unwrap(),
        zkb_fuzz::blinders(0x0a),
    )
    .unwrap();
    let b = Session::new(
        params,
        &keys[1],
        Role::B,
        peer(&keys[0]),
        [3; 32],
        [4; 32],
        Fleet::from_bytes(&FLEET_B, Rules::Standard).unwrap(),
        zkb_fuzz::blinders(0x0b),
    )
    .unwrap();
    (a, b)
}

fn setup_step(pair: &mut Pair, rngs: &mut [ChaCha20Rng; 2], step: usize) {
    let (a, b) = pair;
    let (sender, receiver, rng) = if a.expected_sender() == Some(Role::A) {
        (a, b, &mut rngs[0])
    } else {
        (b, a, &mut rngs[1])
    };
    let frame = sender
        .produce_with_rng(rng, ChaCha20Rng::from_seed([step as u8; 32]))
        .unwrap()
        .expect("fixed setup step");
    deliver(receiver, &frame);
}

fn advance_play(pair: &mut Pair) -> bool {
    let (a, b) = pair;
    match a.expected_sender() {
        Some(Role::A) => play(a, b, 0),
        Some(Role::B) => play(b, a, 0),
        None => return false,
    }
    true
}

fn fixture_rngs() -> [ChaCha20Rng; 2] {
    // Test fixtures only.
    [
        ChaCha20Rng::from_seed([0xc1; 32]),
        ChaCha20Rng::from_seed([0xc2; 32]),
    ]
}

#[cfg(fuzzing)]
fn prefix(phase: u8, exchanges: usize) -> Pair {
    use std::sync::OnceLock;
    struct Fixtures {
        setup: Vec<Pair>,
        play: Vec<(usize, Pair)>,
    }
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    let fixtures = FIXTURES.get_or_init(|| {
        let mut pair = fresh_pair();
        let mut rngs = fixture_rngs();
        let mut setup = vec![pair.clone()];
        for step in 0..5 {
            setup_step(&mut pair, &mut rngs, step);
            setup.push(pair.clone());
        }
        assert!(pair.0.game().is_some() && pair.1.game().is_some());
        let mut play = vec![(0, pair.clone())];
        for count in 1..=199 {
            assert!(
                advance_play(&mut pair),
                "fixture must stop at its terminal state"
            );
            let terminal = pair.0.winner().is_some();
            if count % 16 == 0 || terminal {
                play.push((count, pair.clone()));
            }
            if terminal {
                break;
            }
        }
        assert!(pair.0.winner().is_some(), "fixture reaches a complete game");
        Fixtures { setup, play }
    });
    if phase < 5 {
        return fixtures.setup[usize::from(phase)].clone();
    }
    let (completed, snapshot) = fixtures
        .play
        .iter()
        .rev()
        .find(|(count, _)| *count <= exchanges)
        .unwrap();
    let mut pair = snapshot.clone();
    for _ in *completed..exchanges {
        if !advance_play(&mut pair) {
            break;
        }
    }
    pair
}

// No snapshot Clone outside cfg(fuzzing).
#[cfg(not(fuzzing))]
fn prefix(phase: u8, exchanges: usize) -> Pair {
    let mut pair = fresh_pair();
    let mut rngs = fixture_rngs();
    for step in 0..usize::from(phase) {
        setup_step(&mut pair, &mut rngs, step);
    }
    if phase == 5 {
        for _ in 0..exchanges {
            if !advance_play(&mut pair) {
                break;
            }
        }
    }
    pair
}

fuzz_target!(|data: &[u8]| {
    let keys = keys();
    let phase = data.first().copied().unwrap_or(5) % 6;
    let exchanges = usize::from(data.get(1).copied().unwrap_or(2) % 200);
    let (mut a, mut b) = prefix(phase, exchanges);
    for event in data.get(2..).unwrap_or_default().chunks(3).take(16) {
        if a.is_aborted() || b.is_aborted() {
            break;
        }
        let sender_role = a.expected_sender().unwrap_or(Role::A);
        let (sender, receiver, key) = if sender_role == Role::A {
            (&mut a, &mut b, &keys[0])
        } else {
            (&mut b, &mut a, &keys[1])
        };
        let value = event.get(1).copied().unwrap_or(0);
        let extra = event.get(2).copied();
        match event[0] % 8 {
            0 if phase == 5 && sender.winner().is_none() => play(sender, receiver, value),
            1 => {
                let _ = accept(receiver, data);
            }
            2 if phase == 5 && sender.winner().is_none() => {
                // Mutate and re-sign the honest answer.
                let cell = unshot(sender, receiver.local_role(), 0);
                let shot = sender.fire_shot(cell).unwrap();
                let AcceptOutcome::ShotReceived { answer, .. } = deliver(receiver, &shot) else {
                    unreachable!()
                };
                let mut payload = answer.payload().to_vec();
                let index = usize::from(value) % payload.len();
                payload[index] ^= extra.unwrap_or(1);
                // Keep tag/length consistent to reach answer semantics.
                payload[0] = answer.payload()[0];
                let changed = payload != answer.payload();
                let altered = SignedFrame::craft(
                    if sender_role == Role::A {
                        &keys[1]
                    } else {
                        &keys[0]
                    },
                    sender.sid(),
                    sender_role.other(),
                    sender.head_sequence() + 1,
                    MessageType::Answer,
                    sender.head_hash(),
                    payload,
                );
                let result = accept(sender, altered.bytes());
                // Answers are non-malleable: any other byte string is rejected.
                if changed {
                    assert!(matches!(result, Err(SessionError::Attributable(_))));
                } else {
                    assert!(result.is_ok());
                }
                break; // The two transcripts may now differ.
            }
            3 => {
                if !receiver.transcript().is_empty() {
                    let bytes = receiver.transcript()
                        [usize::from(value) % receiver.transcript().len()]
                    .clone();
                    assert!(matches!(
                        accept(receiver, &bytes),
                        Err(SessionError::ClassB(_))
                    ));
                }
            }
            action => {
                let answer_fixture = |len: usize, tag: u8| {
                    let mut p = vec![0; len];
                    p[0] = tag;
                    p
                };
                let (kind, mut payload) = match value % 10 {
                    0 => (MessageType::Commit, vec![0; COMMIT_PAYLOAD_LEN]),
                    1 => (MessageType::CoinCommit, vec![0; 32]),
                    2 => (MessageType::CoinNonce, vec![0; 32]),
                    3 => (MessageType::CoinReveal, vec![0; 32]),
                    4 => (MessageType::Shot, vec![extra.unwrap_or(255)]),
                    5 => (MessageType::Answer, answer_fixture(ANSWER_MISS_LEN, 0)),
                    6 => {
                        let unsunk = 1 + usize::from(extra.unwrap_or(0)) % K;
                        (
                            MessageType::Answer,
                            answer_fixture(answers::hit_len(unsunk), 1),
                        )
                    }
                    7 => (MessageType::Resign, vec![]),
                    // Structurally valid, wrong for this session's rules.
                    8 => (MessageType::Commit, vec![0; COMMIT_NO_TOUCH_PAYLOAD_LEN]),
                    _ => {
                        let ship = usize::from(extra.unwrap_or(0)) % K;
                        let length = FLEET_LENGTHS[ship];
                        let mut p = answer_fixture(answers::sunk_len(length), 2);
                        p[33] = ship as u8;
                        for t in 0..usize::from(length) {
                            p[34 + 33 * t] = t as u8;
                        }
                        (MessageType::Answer, p)
                    }
                };
                let (tag, ship) = (payload.first().copied(), payload.get(33).copied());
                zkb_fuzz::patch(&mut payload, data.get(5..).unwrap_or_default());
                // Keep the answer shape consistent with its length.
                if kind == MessageType::Answer {
                    payload[0] = tag.unwrap();
                    if payload[0] == 2 {
                        payload[33] = ship.unwrap();
                    }
                }
                let role = if action == 7 {
                    sender_role.other()
                } else {
                    sender_role
                };
                let mut previous = *receiver.head_hash();
                if action == 6 {
                    previous[0] ^= 1;
                }
                let frame = SignedFrame::craft(
                    key,
                    receiver.sid(),
                    role,
                    receiver.head_sequence() + 1,
                    kind,
                    &previous,
                    payload,
                );
                let mut bytes = frame.bytes().to_vec();
                if action == 5 {
                    *bytes.last_mut().unwrap() ^= 1;
                }
                let result = accept(receiver, &bytes);
                if action == 5 || action == 6 {
                    assert!(matches!(result, Err(SessionError::ClassB(_))));
                } else {
                    // Sender may now be desynced; stop.
                    break;
                }
            }
        }
    }
});
