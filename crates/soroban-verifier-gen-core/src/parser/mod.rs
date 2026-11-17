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

// Validate structure without allocating Value trees, including ignored/unknown fields.
pub(crate) fn bounded_json<T: serde::de::DeserializeOwned>(content: &str) -> serde_json::Result<T> {
    check_json_budget(
        content,
        MAX_COLLECTION_ITEMS,
        MAX_COLLECTION_ITEMS,
        MAX_COLLECTION_ITEMS * 16 + 1024,
    )?;
    serde_json::from_str(content)
}

fn check_json_budget(
    content: &str,
    collection: usize,
    public_limit: usize,
    total: usize,
) -> serde_json::Result<()> {
    use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
    struct Budget {
        collection: usize,
        public_limit: usize,
        remaining: usize,
    }
    struct Key;
    impl<'de> DeserializeSeed<'de> for Key {
        type Value = bool;
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<bool, D::Error> {
            d.deserialize_str(self)
        }
    }
    impl<'de> Visitor<'de> for Key {
        type Value = bool;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("JSON object key")
        }
        fn visit_str<E: serde::de::Error>(self, key: &str) -> std::result::Result<bool, E> {
            Ok(matches!(
                key,
                "public_input" | "public_inputs" | "publicSignals" | "public_signals"
            ))
        }
    }
    struct Node<'a> {
        budget: &'a mut Budget,
        index: usize,
    }
    impl<'de> DeserializeSeed<'de> for Node<'_> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> std::result::Result<(), D::Error> {
            if self.index >= self.budget.collection {
                return Err(serde::de::Error::custom(
                    "JSON collection exceeds maximum item count",
                ));
            }
            if self.budget.remaining == 0 {
                return Err(serde::de::Error::custom("JSON structural budget exceeded"));
            }
            self.budget.remaining -= 1;
            deserializer.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Node<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded JSON")
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
            let mut index = 0;
            while seq
                .next_element_seed(Node {
                    budget: self.budget,
                    index,
                })?
                .is_some()
            {
                index += 1;
            }
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
            let mut index = 0;
            while let Some(is_public) = map.next_key_seed(Key)? {
                // Compact metadata maps can exceed the curve's public-input array ceiling.
                if index >= self.budget.collection.max(32) {
                    return Err(serde::de::Error::custom(
                        "JSON collection exceeds maximum map entry count",
                    ));
                }
                let collection = self.budget.collection;
                if is_public {
                    self.budget.collection = self.budget.public_limit;
                }
                map.next_value_seed(Node {
                    budget: self.budget,
                    index: 0,
                })?;
                self.budget.collection = collection;
                index += 1;
            }
            Ok(())
        }
    }
    let mut deserializer = serde_json::Deserializer::from_str(content);
    Node {
        budget: &mut Budget {
            collection: if content.trim_start().starts_with('[') {
                public_limit
            } else {
                collection
            },
            public_limit,
            remaining: total,
        },
        index: 0,
    }
    .deserialize(&mut deserializer)?;
    deserializer.end()
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn stops_before_over_budget_value_is_parsed() {
        let err =
            check_json_budget("[null,null,{malformed expensive value]", 2, 2, 100).unwrap_err();
        assert!(err.to_string().contains("collection"), "{err}");
        let err = check_json_budget("[[null],[null],{malformed]", 10, 10, 5).unwrap_err();
        assert!(err.to_string().contains("budget"), "{err}");
        assert!(check_json_budget("{\"a\":[1,2],\"b\":true}", 2, 2, 6).is_ok());
    }
    #[test]
    fn public_array_ceiling_preserves_extra_ic_point() {
        assert!(check_json_budget("{\"IC\":[0,0,0]}", 3, 2, 100).is_ok());
        for key in [
            "public_input",
            "public_inputs",
            "publicSignals",
            "public_signals",
            "\\u0070ublicSignals",
        ] {
            let text = format!("{{\"{key}\":[0,0,{{malformed]}}");
            let err = check_json_budget(&text, 3, 2, 100).unwrap_err();
            assert!(err.to_string().contains("collection"), "{err}");
        }
    }
}
