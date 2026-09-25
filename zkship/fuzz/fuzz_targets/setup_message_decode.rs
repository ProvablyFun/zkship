//! Input: byte 0 bit 0 = rules (standard, no-touch), bit 1 = fixture (all
//! zero, honest proof), then patch instructions.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::sync::OnceLock;
use zkb_core::fleet::Fleet;
use zkb_core::params::{Parameters, Rules};
use zkb_core::setup::{self, SetupMessage};

// Rows 0, 2, 4, 6, 8: legal under both rule sets.
const FLEET: [u8; 15] = [0, 0, 0, 2, 0, 0, 4, 0, 0, 6, 0, 0, 8, 0, 0];

fn honest(rules: Rules) -> Vec<u8> {
    let fleet = Fleet::from_bytes(&FLEET, rules).unwrap();
    setup::prove_with_rng(
        Parameters::for_rules(rules),
        &[0x0a; 32],
        &[0x77; 32],
        &fleet,
        &zkb_fuzz::blinders(0x01),
        ChaCha20Rng::from_seed([0x5e; 32]),
    )
    .unwrap()
    .encode()
}

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or(0);
    let rules = if selector & 1 == 0 {
        Rules::Standard
    } else {
        Rules::NoTouch
    };
    let _ = SetupMessage::decode(data, rules);
    let mut bytes = if selector & 2 == 0 {
        // Identity points and zero scalars are canonical, so mutations reach
        // every field; decoder fixture, not a valid proof.
        vec![0; setup::encoded_len(rules)]
    } else {
        static HONEST: OnceLock<[Vec<u8>; 2]> = OnceLock::new();
        let honest = HONEST.get_or_init(|| [honest(Rules::Standard), honest(Rules::NoTouch)]);
        honest[usize::from(rules == Rules::NoTouch)].clone()
    };
    assert_eq!(bytes.len(), setup::encoded_len(rules));
    zkb_fuzz::patch(&mut bytes, data.get(1..).unwrap_or_default());
    if let Ok(message) = SetupMessage::decode(&bytes, rules) {
        assert_eq!(message.encode(), bytes);
    }
});
