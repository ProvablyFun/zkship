//! Input: byte 0 % 15 = message type and payload length (both commit lengths,
//! every answer length), then patch instructions.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zkb_core::answers;
use zkb_core::params::K;
use zkb_session::codec::{
    MessageType, ANSWER_MISS_LEN, COIN_PAYLOAD_LEN, COMMIT_NO_TOUCH_PAYLOAD_LEN,
    COMMIT_PAYLOAD_LEN, HEADER_LEN, SHOT_PAYLOAD_LEN, SIGNATURE_LEN,
};
use zkb_session::frame::SignedFrame;

fuzz_target!(|data: &[u8]| {
    let _ = SignedFrame::decode(data);
    let selector = usize::from(data.first().copied().unwrap_or(0)) % 15;
    let (kind, len, tag) = match selector {
        0 => (MessageType::Commit, COMMIT_PAYLOAD_LEN, None),
        1 => (MessageType::Commit, COMMIT_NO_TOUCH_PAYLOAD_LEN, None),
        2 => (MessageType::CoinCommit, COIN_PAYLOAD_LEN, None),
        3 => (MessageType::CoinNonce, COIN_PAYLOAD_LEN, None),
        4 => (MessageType::CoinReveal, COIN_PAYLOAD_LEN, None),
        5 => (MessageType::Shot, SHOT_PAYLOAD_LEN, None),
        6 => (MessageType::Answer, ANSWER_MISS_LEN, Some(0)),
        // Hit proofs for 1, 2 and 3-5 unsunk ships.
        7..=9 => (
            MessageType::Answer,
            answers::hit_len([1, 2, K][selector - 7]),
            Some(1),
        ),
        // Sunk ships of length 5, 4, 3 and 2.
        10..=13 => (
            MessageType::Answer,
            answers::sunk_len([5, 4, 3, 2][selector - 10]),
            Some(2),
        ),
        _ => (MessageType::Resign, 0, None),
    };
    let mut bytes = vec![0; HEADER_LEN + len + SIGNATURE_LEN];
    zkb_fuzz::patch(&mut bytes, data.get(1..).unwrap_or_default());
    bytes[41] = kind.to_u8();
    bytes[74..78].copy_from_slice(&(len as u32).to_le_bytes());
    if let Some(tag) = tag {
        bytes[HEADER_LEN] = tag;
    }
    let frame = SignedFrame::decode(&bytes).expect("normalized structural envelope");
    assert_eq!(frame.bytes(), bytes);
    assert_eq!(frame.payload().len(), len);
});
