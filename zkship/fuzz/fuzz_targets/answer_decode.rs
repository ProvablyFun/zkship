#![no_main]

use libfuzzer_sys::fuzz_target;
use zkb_core::openings::ShotAnswer;

fuzz_target!(|data: &[u8]| {
    let _ = ShotAnswer::decode(data);
    for (flag, len) in [(0, ShotAnswer::MISS_LEN), (1, ShotAnswer::HIT_LEN)] {
        let mut bytes = vec![0; len];
        zkb_fuzz::patch(&mut bytes[1..], data);
        bytes[0] = flag;
        if let Ok(answer) = ShotAnswer::decode(&bytes) {
            assert_eq!(answer.encode(), bytes);
        }
    }
});
