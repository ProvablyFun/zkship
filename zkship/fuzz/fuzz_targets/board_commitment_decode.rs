#![no_main]

use libfuzzer_sys::fuzz_target;
use zkb_core::wf::UnverifiedBoardCommitment;

fuzz_target!(|data: &[u8]| {
    let _ = UnverifiedBoardCommitment::from_bytes(data);
    // Identity is a canonical point, so mutations reach all 760 decompressions.
    let mut bytes = vec![0; UnverifiedBoardCommitment::ENCODED_LEN];
    zkb_fuzz::patch(&mut bytes, data);
    if let Ok(board) = UnverifiedBoardCommitment::from_bytes(&bytes) {
        assert_eq!(board.to_bytes(), bytes);
    }
});
