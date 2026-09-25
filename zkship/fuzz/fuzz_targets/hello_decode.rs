//! Input: byte 0 bit 0 = profile (standard, no-touch), then patch
//! instructions over key/nonce/signature, or those 128 bytes verbatim.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::sync::OnceLock;
use zkb_core::params::Parameters;
use zkb_session::hello::{check_hello, Hello, HelloError, WIRE_VERSION};
use zkb_session::identity::{ExpectedKey, IdentityKeypair};

fn hello(params: &Parameters) -> Vec<u8> {
    Hello::create(
        &IdentityKeypair::from_seed(&[0x22; 32]),
        *params.params_id(),
        &mut ChaCha20Rng::from_seed([0xa1; 32]),
    )
    .encode()
}

fuzz_target!(|data: &[u8]| {
    let no_touch = data.first().copied().unwrap_or(0) & 1 == 1;
    let (params, other) = if no_touch {
        (Parameters::no_touch(), Parameters::standard())
    } else {
        (Parameters::standard(), Parameters::no_touch())
    };
    let params_id = params.params_id();
    if let Ok(hello) = Hello::decode(data) {
        let policy = ExpectedKey::new(*hello.key());
        let _ = check_hello(hello, params_id, &policy);
    }

    // Valid signed fixtures (162 bytes); tail = key[32] || nonce[32] || sig[64].
    static HELLO: OnceLock<[Vec<u8>; 2]> = OnceLock::new();
    let fixtures =
        HELLO.get_or_init(|| [hello(Parameters::standard()), hello(Parameters::no_touch())]);
    let mut bytes = fixtures[usize::from(no_touch)].clone();
    assert_eq!(bytes.len(), Hello::LEN);
    let data = data.get(1..).unwrap_or_default();
    zkb_fuzz::patch(&mut bytes[34..], data);
    if data.len() >= 128 {
        bytes[34..].copy_from_slice(&data[..128]);
    }
    bytes[..2].copy_from_slice(&WIRE_VERSION.to_le_bytes());
    bytes[2..34].copy_from_slice(params_id);
    if let Ok(hello) = Hello::decode(&bytes) {
        let policy = ExpectedKey::new(*hello.key());
        // Profiles never cross: the other params_id is refused before the signature.
        assert!(matches!(
            check_hello(hello.clone(), other.params_id(), &policy),
            Err(HelloError::ParamsIdMismatch)
        ));
        let _ = check_hello(hello, params_id, &policy);
    }
});
