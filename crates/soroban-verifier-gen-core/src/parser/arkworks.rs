use ark_bls12_381::{Bls12_381, G1Affine as BlsG1Affine, G2Affine as BlsG2Affine};
use ark_bn254::{Bn254, G1Affine as Bn254G1Affine, G2Affine as Bn254G2Affine};
use ark_groth16::{Proof as ArkProof, VerifyingKey as ArkVerifyingKey};
use ark_serialize::CanonicalDeserialize;
use serde_json::Value;
use std::io::Cursor;
use std::path::Path;

use crate::error::{Error, Result};
use crate::model::{
    CurveKind, Groth16G1Point, Groth16G2Point, Groth16Proof, Groth16VerificationKey,
    Groth16VerifierInputs, SourceFormat,
};
use crate::parser::{
    MAX_COLLECTION_ITEMS, decode_hex, read_bounded_text, validate_arkworks_proof_bytes,
    validate_arkworks_vk_bytes,
};
use crate::snarkjs::parse_decimal;

pub fn load_arkworks_bundle(
    path: &Path,
    curve_hint: Option<&str>,
) -> Result<Groth16VerifierInputs> {
    let value = read_json_or_string(path)?;
    let curve = parse_curve(value.get("curve").and_then(Value::as_str), curve_hint)?;
    let vk_hex = string_from_keys(&value, &["vk", "verification_key", "verifying_key"], "vk")?;
    let vk = decode_vk(&curve, &vk_hex)?;

    let proof = optional_string_from_keys(&value, &["proof", "proof_bytes"])
        .map(|hex| decode_proof(&curve, &hex))
        .transpose()?;

    let public_inputs = match optional_value_from_keys(&value, &["public_input", "public_inputs"]) {
        Some(public) => parse_public_inputs(public)?,
        None => Vec::new(),
    };

    Groth16VerifierInputs::from_parts(curve, vk, proof, public_inputs, SourceFormat::Arkworks)
}

pub fn load_arkworks_inputs(
    vk_path: &Path,
    proof_path: Option<&Path>,
    public_path: Option<&Path>,
    curve_hint: Option<&str>,
) -> Result<Groth16VerifierInputs> {
    let vk_value = read_json_or_string(vk_path)?;
    let curve = parse_curve(vk_value.get("curve").and_then(Value::as_str), curve_hint)?;
    let vk_hex = if vk_value.is_string() {
        vk_value.as_str().unwrap_or_default().to_string()
    } else {
        string_from_keys(
            &vk_value,
            &["vk", "verification_key", "verifying_key"],
            "vk",
        )?
    };
    let vk = decode_vk(&curve, &vk_hex)?;

    let proof = match proof_path {
        Some(path) => {
            let proof_value = read_json_or_string(path)?;
            let proof_hex = if proof_value.is_string() {
                proof_value.as_str().unwrap_or_default().to_string()
            } else {
                string_from_keys(&proof_value, &["proof", "proof_bytes"], "proof")?
            };
            Some(decode_proof(&curve, &proof_hex)?)
        }
        None => optional_string_from_keys(&vk_value, &["proof", "proof_bytes"])
            .map(|hex| decode_proof(&curve, &hex))
            .transpose()?,
    };

    let public_inputs = match public_path {
        Some(path) => parse_public_inputs(&read_json_or_string(path)?)?,
        None => match optional_value_from_keys(&vk_value, &["public_input", "public_inputs"]) {
            Some(public) => parse_public_inputs(public)?,
            None => Vec::new(),
        },
    };

    Groth16VerifierInputs::from_parts(curve, vk, proof, public_inputs, SourceFormat::Arkworks)
}

fn read_json_or_string(path: &Path) -> Result<Value> {
    let content = read_bounded_text(path)?;
    let trimmed = content.trim();
    // Preserve decimal precision before serde_json can convert large numbers to f64.
    if !trimmed.is_empty() && trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(Value::String(trimmed.to_string()));
    }
    if trimmed.starts_with(['{', '[', '\"'])
        || trimmed == "null"
        || trimmed == "true"
        || trimmed == "false"
    {
        return crate::parser::bounded_json(trimmed).map_err(|source| Error::JsonParse {
            source,
            context: format!("invalid JSON in {}", path.display()),
        });
    }
    // Byte alignment belongs to VK/proof decoding; raw public scalars also allow odd numeric hex.
    let raw = trimmed
        .strip_prefix("le:")
        .or_else(|| trimmed.strip_prefix("0x"))
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::HexParse(
            "raw Arkworks input must be hex or an explicit LE scalar".to_string(),
        ));
    }
    Ok(Value::String(trimmed.to_string()))
}

fn parse_curve(value: Option<&str>, curve_hint: Option<&str>) -> Result<CurveKind> {
    let metadata = value.map(CurveKind::from_name).transpose()?;
    let hint = curve_hint.map(CurveKind::from_name).transpose()?;
    match (metadata, hint) {
        (Some(metadata), Some(hint)) if metadata != hint => Err(Error::CurveMismatch(format!(
            "artifact curve {} conflicts with requested curve {}",
            metadata.canonical_name(),
            hint.canonical_name()
        ))),
        (Some(curve), _) | (_, Some(curve)) => Ok(curve),
        (None, None) => Err(Error::MissingInput(
            "arkworks input requires curve metadata".to_string(),
        )),
    }
}

fn string_from_keys(value: &Value, keys: &[&str], field: &str) -> Result<String> {
    optional_string_from_keys(value, keys)
        .ok_or_else(|| Error::MissingInput(format!("arkworks input requires {field} hex field")))
}

fn optional_string_from_keys(value: &Value, keys: &[&str]) -> Option<String> {
    if let Some(s) = value.as_str() {
        return Some(s.to_string());
    }
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(ToString::to_string)
    })
}

fn optional_value_from_keys<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| value.get(*key))
}

fn decode_vk(curve: &CurveKind, raw: &str) -> Result<Groth16VerificationKey> {
    match curve {
        CurveKind::Bn254 => decode_vk_bn254(raw),
        CurveKind::Bls12_381 => decode_vk_bls12381(raw),
    }
}

fn decode_proof(curve: &CurveKind, raw: &str) -> Result<Groth16Proof> {
    match curve {
        CurveKind::Bn254 => decode_proof_bn254(raw),
        CurveKind::Bls12_381 => decode_proof_bls12381(raw),
    }
}

fn decode_vk_bn254(raw: &str) -> Result<Groth16VerificationKey> {
    let bytes = decode_hex(raw, "vk")?;
    validate_arkworks_vk_bytes(&bytes, 224, 32, "BN254 verifying key")?;
    let mut cursor = Cursor::new(bytes);
    let vk = ArkVerifyingKey::<Bn254>::deserialize_compressed(&mut cursor).map_err(|e| {
        Error::Serialization(format!("failed to deserialize BN254 verifying key: {e:?}"))
    })?;
    ensure_no_trailing_bytes(&cursor, "BN254 verifying key")?;
    Ok(Groth16VerificationKey {
        n_public: vk.gamma_abc_g1.len().saturating_sub(1),
        vk_alpha_1: point_from_bn254_g1(&vk.alpha_g1),
        vk_beta_2: point_from_bn254_g2(&vk.beta_g2),
        vk_gamma_2: point_from_bn254_g2(&vk.gamma_g2),
        vk_delta_2: point_from_bn254_g2(&vk.delta_g2),
        ic: vk.gamma_abc_g1.iter().map(point_from_bn254_g1).collect(),
    })
}

fn decode_proof_bn254(raw: &str) -> Result<Groth16Proof> {
    let bytes = decode_hex(raw, "proof")?;
    validate_arkworks_proof_bytes(&bytes, 128, "BN254 proof")?;
    let mut cursor = Cursor::new(bytes);
    let proof = ArkProof::<Bn254>::deserialize_compressed(&mut cursor)
        .map_err(|e| Error::Serialization(format!("failed to deserialize BN254 proof: {e:?}")))?;
    ensure_no_trailing_bytes(&cursor, "BN254 proof")?;
    Ok(Groth16Proof {
        pi_a: point_from_bn254_g1(&proof.a),
        pi_b: point_from_bn254_g2(&proof.b),
        pi_c: point_from_bn254_g1(&proof.c),
    })
}

fn decode_vk_bls12381(raw: &str) -> Result<Groth16VerificationKey> {
    let bytes = decode_hex(raw, "vk")?;
    validate_arkworks_vk_bytes(&bytes, 336, 48, "BLS12-381 verifying key")?;
    let mut cursor = Cursor::new(bytes);
    let vk = ArkVerifyingKey::<Bls12_381>::deserialize_compressed(&mut cursor).map_err(|e| {
        Error::Serialization(format!(
            "failed to deserialize BLS12-381 verifying key: {e:?}"
        ))
    })?;
    ensure_no_trailing_bytes(&cursor, "BLS12-381 verifying key")?;
    Ok(Groth16VerificationKey {
        n_public: vk.gamma_abc_g1.len().saturating_sub(1),
        vk_alpha_1: point_from_bls_g1(&vk.alpha_g1),
        vk_beta_2: point_from_bls_g2(&vk.beta_g2),
        vk_gamma_2: point_from_bls_g2(&vk.gamma_g2),
        vk_delta_2: point_from_bls_g2(&vk.delta_g2),
        ic: vk.gamma_abc_g1.iter().map(point_from_bls_g1).collect(),
    })
}

fn decode_proof_bls12381(raw: &str) -> Result<Groth16Proof> {
    let bytes = decode_hex(raw, "proof")?;
    validate_arkworks_proof_bytes(&bytes, 192, "BLS12-381 proof")?;
    let mut cursor = Cursor::new(bytes);
    let proof = ArkProof::<Bls12_381>::deserialize_compressed(&mut cursor).map_err(|e| {
        Error::Serialization(format!("failed to deserialize BLS12-381 proof: {e:?}"))
    })?;
    ensure_no_trailing_bytes(&cursor, "BLS12-381 proof")?;
    Ok(Groth16Proof {
        pi_a: point_from_bls_g1(&proof.a),
        pi_b: point_from_bls_g2(&proof.b),
        pi_c: point_from_bls_g1(&proof.c),
    })
}

fn ensure_no_trailing_bytes(cursor: &Cursor<Vec<u8>>, field: &str) -> Result<()> {
    let position: usize = cursor
        .position()
        .try_into()
        .map_err(|_| Error::Serialization(format!("{field} cursor position overflow")))?;
    let len = cursor.get_ref().len();
    if position == len {
        return Ok(());
    }

    Err(Error::Serialization(format!(
        "{field} has {} trailing bytes after Arkworks compressed artifact",
        len.saturating_sub(position)
    )))
}

fn point_from_bn254_g1(point: &Bn254G1Affine) -> Groth16G1Point {
    Groth16G1Point {
        x: point.x.to_string(),
        y: point.y.to_string(),
        z: "1".to_string(),
    }
}

fn point_from_bn254_g2(point: &Bn254G2Affine) -> Groth16G2Point {
    Groth16G2Point {
        x0: point.x.c0.to_string(),
        x1: point.x.c1.to_string(),
        y0: point.y.c0.to_string(),
        y1: point.y.c1.to_string(),
        z0: "1".to_string(),
        z1: "0".to_string(),
    }
}

fn point_from_bls_g1(point: &BlsG1Affine) -> Groth16G1Point {
    Groth16G1Point {
        x: point.x.to_string(),
        y: point.y.to_string(),
        z: "1".to_string(),
    }
}

fn point_from_bls_g2(point: &BlsG2Affine) -> Groth16G2Point {
    Groth16G2Point {
        x0: point.x.c0.to_string(),
        x1: point.x.c1.to_string(),
        y0: point.y.c0.to_string(),
        y1: point.y.c1.to_string(),
        z0: "1".to_string(),
        z1: "0".to_string(),
    }
}

fn parse_public_inputs(value: &Value) -> Result<Vec<String>> {
    match value {
        Value::Array(values) => {
            if values.len() > MAX_COLLECTION_ITEMS {
                return Err(Error::PublicInputCountMismatch(format!(
                    "public input count exceeds maximum {MAX_COLLECTION_ITEMS}"
                )));
            }
            values
                .iter()
                .enumerate()
                .map(|(idx, value)| {
                    parse_public_input_value(value, &format!("public_inputs[{idx}]"))
                })
                .collect()
        }
        Value::Object(_) => {
            match optional_value_from_keys(value, &["public_input", "public_inputs"]) {
                Some(inner) => parse_public_inputs(inner),
                None => Err(Error::MissingInput(
                    "public input JSON object requires public_input or public_inputs".to_string(),
                )),
            }
        }
        _ => parse_public_input_value(value, "public_input").map(|value| vec![value]),
    }
}

fn parse_public_input_value(value: &Value, field_name: &str) -> Result<String> {
    match value {
        Value::String(raw) => parse_public_input_string(raw, field_name),
        Value::Number(num) => {
            let decimal = num.to_string();
            parse_decimal(&decimal, field_name)?;
            Ok(decimal)
        }
        _ => Err(Error::DecimalParse(format!(
            "{field_name} must be string or number"
        ))),
    }
}

fn parse_public_input_string(raw: &str, field_name: &str) -> Result<String> {
    crate::snarkjs::parser::parse_compact_scalar(raw.trim(), field_name)
}

#[cfg(test)]
mod scalar_regressions {
    use super::*;
    #[test]
    fn scalar_grammar_is_unambiguous() {
        let decimal = "1".repeat(64);
        assert_eq!(
            parse_public_input_string(&decimal, "public").unwrap(),
            decimal
        );
        assert_eq!(parse_public_input_string("0x10", "public").unwrap(), "16");
        assert_eq!(
            parse_public_input_string(&format!("0X{}10", "0".repeat(62)), "public").unwrap(),
            "16"
        );
        assert_eq!(
            parse_public_input_string(&format!("le:01{}", "0".repeat(62)), "public").unwrap(),
            "1"
        );
        for bad in ["", "le:01", "le:zz", "dead", "0x", "0xgg"] {
            assert!(parse_public_input_string(bad, "public").is_err(), "{bad}");
        }
    }
    #[test]
    fn scalar_grammar_reaches_both_curves_and_bundle_routes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let dir = tempfile::tempdir().unwrap();
        for curve in ["bn254", "bls12_381"] {
            let source = root
                .join("examples/ark-mimc/artifacts")
                .join(curve)
                .join("groth16_artifacts.json");
            let mut bundle: Value =
                serde_json::from_str(&std::fs::read_to_string(source).unwrap()).unwrap();
            bundle.as_object_mut().unwrap().remove("proof");
            let path = dir.path().join("bundle.json");
            for (raw, expected) in [
                ("1".repeat(64), "1".repeat(64)),
                ("0x10".into(), "16".into()),
                (format!("0X{}10", "0".repeat(62)), "16".into()),
                (format!("le:01{}", "0".repeat(62)), "1".into()),
            ] {
                bundle["public_input"] = raw.into();
                std::fs::write(&path, bundle.to_string()).unwrap();
                assert_eq!(
                    load_arkworks_bundle(&path, None).unwrap().public_inputs,
                    vec![expected.clone()]
                );
                assert_eq!(
                    crate::formats::load_compact_bundle(&path, None)
                        .unwrap()
                        .public_inputs,
                    vec![expected]
                );
            }
        }
    }

    #[test]
    fn raw_scalar_text_and_json_structures_remain_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input");
        std::fs::write(&path, "123").unwrap();
        assert_eq!(
            read_json_or_string(&path).unwrap(),
            serde_json::json!("123")
        );
        std::fs::write(&path, "deadbeef").unwrap();
        assert_eq!(
            read_json_or_string(&path).unwrap(),
            serde_json::json!("deadbeef")
        );
        std::fs::write(&path, "{\"broken\":[").unwrap();
        assert!(matches!(
            read_json_or_string(&path),
            Err(Error::JsonParse { .. })
        ));
    }
}
