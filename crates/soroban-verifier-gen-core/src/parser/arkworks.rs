use ark_bls12_381::{Bls12_381, G1Affine as BlsG1Affine, G2Affine as BlsG2Affine};
use ark_bn254::{Bn254, G1Affine as Bn254G1Affine, G2Affine as Bn254G2Affine};
use ark_groth16::{Proof as ArkProof, VerifyingKey as ArkVerifyingKey};
use ark_serialize::CanonicalDeserialize;
use num_bigint::BigUint;
use serde_json::Value;
use std::fs;
use std::io::Cursor;
use std::path::Path;

use crate::error::{Error, Result};
use crate::model::{
    CurveKind, Groth16G1Point, Groth16G2Point, Groth16Proof, Groth16VerificationKey,
    Groth16VerifierInputs, SourceFormat,
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
    let content = fs::read_to_string(path).map_err(|e| Error::Io {
        source: e,
        context: format!("failed to read file {}", path.display()),
    })?;
    let trimmed = content.trim();
    match serde_json::from_str::<Value>(trimmed) {
        Ok(value) => Ok(value),
        Err(_) => Ok(Value::String(trimmed.to_string())),
    }
}

fn parse_curve(value: Option<&str>, curve_hint: Option<&str>) -> Result<CurveKind> {
    let raw = value
        .or(curve_hint)
        .ok_or_else(|| Error::MissingInput("arkworks input requires curve metadata".to_string()))?;
    CurveKind::from_name(raw)
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
        Value::Array(values) => values
            .iter()
            .enumerate()
            .map(|(idx, value)| parse_public_input_value(value, &format!("public_inputs[{idx}]")))
            .collect(),
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
    let trimmed = raw.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    if without_prefix.len() >= 64
        && without_prefix.len().is_multiple_of(64)
        && without_prefix.chars().all(|c| c.is_ascii_hexdigit())
    {
        let bytes = decode_hex(without_prefix, field_name)?;
        if bytes.len() == 32 {
            return Ok(BigUint::from_bytes_le(&bytes).to_string());
        }
        return Err(Error::MissingInput(format!(
            "{field_name} contains multiple public inputs; use an array or public_inputs field"
        )));
    }

    parse_scalar(trimmed, field_name)
}

fn parse_scalar(raw: &str, field_name: &str) -> Result<String> {
    let has_hex_prefix = raw.starts_with("0x") || raw.starts_with("0X");
    let value = if has_hex_prefix { &raw[2..] } else { raw };
    if value.chars().all(|c| c.is_ascii_digit()) {
        parse_decimal(value, field_name)?;
        return Ok(value.to_string());
    }
    if value.chars().all(|c| c.is_ascii_hexdigit()) {
        let parsed = BigUint::parse_bytes(value.as_bytes(), 16).ok_or_else(|| {
            Error::DecimalParse(format!("{field_name} could not parse hex scalar {raw}"))
        })?;
        return Ok(parsed.to_string());
    }
    Err(Error::DecimalParse(format!(
        "{field_name} must be decimal or hex string"
    )))
}

fn decode_hex(raw: &str, field: &str) -> Result<Vec<u8>> {
    let hex = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if hex.is_empty() {
        return Err(Error::HexParse(format!("{field} must not be empty")));
    }
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::HexParse(format!(
            "{field} must be a hex string, got {raw}"
        )));
    }
    if !hex.len().is_multiple_of(2) {
        return Err(Error::HexParse(format!(
            "{field} has odd hex length, got {hex}"
        )));
    }
    hex::decode(hex).map_err(|e| Error::HexParse(format!("{field}: {e}")))
}
