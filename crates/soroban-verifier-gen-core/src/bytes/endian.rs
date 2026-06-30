use num_bigint::BigUint;

/// Serialize big integer to fixed little-endian vector.
pub fn to_le_padded_bytes(value: &BigUint, len: usize) -> Vec<u8> {
    let mut bytes = value.to_bytes_le();
    bytes.resize(len, 0);
    if bytes.len() > len {
        bytes.truncate(len);
    }
    bytes
}
