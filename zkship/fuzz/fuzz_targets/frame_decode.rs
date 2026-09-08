#![no_main]

use libfuzzer_sys::fuzz_target;
use zkb_session::codec::{MessageType, COMMIT_PAYLOAD_LEN, HEADER_LEN, SIGNATURE_LEN};
use zkb_session::frame::SignedFrame;

fuzz_target!(|data: &[u8]| {
    let _ = SignedFrame::decode(data);
    let selector = data.first().copied().unwrap_or(0) % 8;
    let (kind, len) = match selector {
        0 => (MessageType::Commit, COMMIT_PAYLOAD_LEN),
        1 => (MessageType::CoinCommit, 32),
        2 => (MessageType::CoinNonce, 32),
        3 => (MessageType::CoinReveal, 32),
        4 => (MessageType::Shot, 1),
        5 => (MessageType::Answer, 33),
        6 => (MessageType::Answer, 165),
        _ => (MessageType::Resign, 0),
    };
    let mut bytes = vec![0; HEADER_LEN + len + SIGNATURE_LEN];
    zkb_fuzz::patch(&mut bytes, data.get(1..).unwrap_or_default());
    bytes[41] = kind.to_u8();
    bytes[74..78].copy_from_slice(&(len as u32).to_le_bytes());
    if kind == MessageType::Answer {
        bytes[HEADER_LEN] = u8::from(len == 165);
    }
    let frame = SignedFrame::decode(&bytes).expect("normalized structural envelope");
    assert_eq!(frame.bytes(), bytes);
    assert_eq!(frame.payload().len(), len);
});
