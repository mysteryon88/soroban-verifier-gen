/// Lowercase hex rendering.
pub fn to_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    static HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
