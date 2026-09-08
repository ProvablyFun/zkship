#![no_main]

use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::sync::OnceLock;
use zkb_core::params::Parameters;
use zkb_session::hello::{check_hello, Hello, WIRE_VERSION};
use zkb_session::identity::{ExpectedKey, IdentityKeypair};

fuzz_target!(|data: &[u8]| {
    let params_id = Parameters::standard_v1().params_id();
    if let Ok(hello) = Hello::decode(data) {
        let policy = ExpectedKey::new(*hello.key());
        let _ = check_hello(hello, params_id, &policy);
    }

    // Valid signed fixture (162 bytes); tail = key[32] || nonce[32] || sig[64].
    static HELLO: OnceLock<Vec<u8>> = OnceLock::new();
    let mut bytes = HELLO
        .get_or_init(|| {
            Hello::create(
                &IdentityKeypair::from_seed(&[0x22; 32]),
                *params_id,
                &mut ChaCha20Rng::from_seed([0xa1; 32]),
            )
            .encode()
        })
        .clone();
    assert_eq!(bytes.len(), Hello::LEN);
    zkb_fuzz::patch(&mut bytes[34..], data);
    if data.len() >= 128 {
        bytes[34..].copy_from_slice(&data[..128]);
    }
    bytes[..2].copy_from_slice(&WIRE_VERSION.to_le_bytes());
    bytes[2..34].copy_from_slice(params_id);
    if let Ok(hello) = Hello::decode(&bytes) {
        let policy = ExpectedKey::new(*hello.key());
        let _ = check_hello(hello, params_id, &policy);
    }
});
