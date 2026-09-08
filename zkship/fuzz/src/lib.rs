/// At most 256 sparse writes; each 4-byte instruction is a 24-bit LE offset (mod
/// buffer length) and a value, so small inputs reach late fields of the 82 KiB proof.
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
