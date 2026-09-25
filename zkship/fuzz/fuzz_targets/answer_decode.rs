//! Input: byte 0 % 11 = shape (miss; hit for 1-5 unsunk ships; sunk ship
//! 0-4), then patch instructions. Every shape is decoded for every unsunk count.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zkb_core::answers::{self, ShotAnswer};
use zkb_core::params::{FLEET_LENGTHS, K};

fn check(bytes: &[u8]) {
    for unsunk in 0..=K {
        if let Ok(answer) = ShotAnswer::decode(bytes, unsunk) {
            assert_eq!(answer.encode(), bytes);
            assert!(ShotAnswer::is_possible_length(bytes[0], bytes.len()));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    let shape = usize::from(data.first().copied().unwrap_or(0)) % (1 + 2 * K);
    // Zero scalars and identity points are canonical.
    let mut bytes = match shape {
        0 => vec![0; answers::MISS_LEN],
        m @ 1..=K => {
            let mut b = vec![0; answers::hit_len(m)];
            b[0] = 1;
            b
        }
        _ => {
            let ship = shape - 1 - K;
            let length = FLEET_LENGTHS[ship];
            let mut b = vec![0; answers::sunk_len(length)];
            b[0] = 2;
            b[33] = ship as u8;
            for t in 0..usize::from(length) {
                b[34 + 33 * t] = t as u8;
            }
            b
        }
    };
    let (tag, ship) = (bytes[0], bytes.get(33).copied());
    zkb_fuzz::patch(&mut bytes[1..], data.get(1..).unwrap_or_default());
    bytes[0] = tag;
    if tag == 2 {
        bytes[33] = ship.unwrap();
    }
    check(&bytes);
});
