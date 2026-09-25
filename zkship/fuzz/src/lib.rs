use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use zkb_core::fleet::SHIP_BITS;

/// At most 256 sparse writes; each 4-byte instruction is a 24-bit LE offset (mod
/// buffer length) and a value, so small inputs reach late fields of the 20 KiB setup message.
pub fn patch(bytes: &mut [u8], data: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    for instruction in data.chunks_exact(4).take(256) {
        let offset = usize::from(instruction[0])
            | (usize::from(instruction[1]) << 8)
            | (usize::from(instruction[2]) << 16);
        bytes[offset % bytes.len()] = instruction[3];
    }
}

/// Deterministic ship-cell blinders for fixtures only.
pub fn blinders(seed: u8) -> Vec<Scalar> {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    (0..SHIP_BITS)
        .map(|_| {
            let mut wide = [0u8; 64];
            rng.fill_bytes(&mut wide);
            Scalar::from_bytes_mod_order_wide(&wide)
        })
        .collect()
}
