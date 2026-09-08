#![no_main]

use curve25519_dalek::scalar::Scalar;
use libfuzzer_sys::fuzz_target;
use zkb_core::game::Role;
use zkb_core::params::{Parameters, P};
use zkb_session::identity::{AuthenticatedPeer, IdentityKeypair};
use zkb_session::state::Session;

fn placement() -> Vec<u8> {
    let mut e = vec![0u8; P];
    e[0] = 1;
    e[134] = 1;
    e[292] = 1;
    e[460] = 1;
    e[643] = 1;
    e
}

fuzz_target!(|data: &[u8]| {
    let params = Parameters::standard_v1();
    let local = IdentityKeypair::from_seed(&[1; 32]);
    let peer = AuthenticatedPeer::from_policy_decision(
        IdentityKeypair::from_seed(&[2; 32]).peer_key(),
    );
    let mut session = Session::new(
        params,
        &local,
        Role::B,
        peer,
        [3; 32],
        [4; 32],
        placement(),
        vec![Scalar::ZERO; P],
    )
    .expect("fixed legal witness");
    let _ = session.accept(data);
});
