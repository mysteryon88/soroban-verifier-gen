pub mod arkworks;

use crate::error::{Error, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub(crate) const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_DECIMAL_DIGITS: usize = 256;
pub(crate) const MAX_COLLECTION_ITEMS: usize = 65_536;

pub(crate) fn read_bounded_text(path: &Path) -> Result<String> {
    let file = File::open(path).map_err(|e| Error::Io {
        source: e,
        context: format!("failed to open file {}", path.display()),
    })?;
    let size = file
        .metadata()
        .map_err(|e| Error::Io {
            source: e,
            context: format!("failed to inspect file {}", path.display()),
        })?
        .len();
    if size > MAX_ARTIFACT_BYTES {
        return Err(Error::InputTooLarge {
            path: path.to_path_buf(),
            size,
            max: MAX_ARTIFACT_BYTES,
        });
    }

    let mut content = String::with_capacity(size as usize);
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_string(&mut content)
        .map_err(|e| Error::Io {
            source: e,
            context: format!("failed to read file {}", path.display()),
        })?;
    if content.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err(Error::InputTooLarge {
            path: path.to_path_buf(),
            size: content.len() as u64,
            max: MAX_ARTIFACT_BYTES,
        });
    }
    Ok(content)
}

pub(crate) fn decode_hex(raw: &str, field: &str) -> Result<Vec<u8>> {
    let value = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if value.is_empty() {
        return Err(Error::HexParse(format!("{field} must not be empty")));
    }
    if value.len() > MAX_ARTIFACT_BYTES as usize {
        return Err(Error::HexParse(format!(
            "{field} exceeds the maximum hex length"
        )));
    }
    if !value.len().is_multiple_of(2) {
        return Err(Error::HexParse(format!("{field} has odd hex length")));
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::HexParse(format!("{field} must be a hex string")));
    }
    hex::decode(value).map_err(|e| Error::HexParse(format!("{field}: {e}")))
}

pub(crate) fn validate_arkworks_vk_bytes(
    bytes: &[u8],
    fixed_bytes: usize,
    ic_point_bytes: usize,
    field: &str,
) -> Result<()> {
    let count_end = fixed_bytes
        .checked_add(8)
        .ok_or_else(|| Error::Serialization(format!("{field} fixed-size prefix overflow")))?;
    let count_bytes: [u8; 8] = bytes
        .get(fixed_bytes..count_end)
        .ok_or_else(|| Error::Serialization(format!("{field} is truncated before IC length")))?
        .try_into()
        .map_err(|_| Error::Serialization(format!("{field} has invalid IC length")))?;
    let count: usize = u64::from_le_bytes(count_bytes)
        .try_into()
        .map_err(|_| Error::IcLengthMismatch(format!("{field} IC length is too large")))?;
    if count == 0 || count > MAX_COLLECTION_ITEMS {
        return Err(Error::IcLengthMismatch(format!(
            "{field} IC length must be between 1 and {MAX_COLLECTION_ITEMS}, got {count}"
        )));
    }
    let expected = count_end
        .checked_add(
            count
                .checked_mul(ic_point_bytes)
                .ok_or_else(|| Error::Serialization(format!("{field} IC byte length overflow")))?,
        )
        .ok_or_else(|| Error::Serialization(format!("{field} byte length overflow")))?;
    if bytes.len() != expected {
        return Err(Error::Serialization(format!(
            "{field} length does not match its IC count"
        )));
    }
    Ok(())
}

pub(crate) fn validate_arkworks_proof_bytes(
    bytes: &[u8],
    expected: usize,
    field: &str,
) -> Result<()> {
    if bytes.len() != expected {
        return Err(Error::Serialization(format!(
            "{field} has invalid compressed proof length"
        )));
    }
    Ok(())
}
