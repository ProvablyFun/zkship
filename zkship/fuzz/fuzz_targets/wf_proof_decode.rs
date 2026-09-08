#![no_main]

use libfuzzer_sys::fuzz_target;
use zkb_core::wf::WfProof;

fuzz_target!(|data: &[u8]| {
    let _ = WfProof::decode(data);
    // All-zero scalars are canonical; decoder fixture, not a valid proof.
    let mut bytes = vec![0; WfProof::ENCODED_LEN];
    zkb_fuzz::patch(&mut bytes, data);
    if let Ok(proof) = WfProof::decode(&bytes) {
        assert_eq!(proof.encode(), bytes);
    }
});
