use crate::error::{Error, Result};
use crate::snarkjs::model::{
    PackedArtifact, Proof, RawProof, RawVerificationKey, SnarkJsG1, SnarkJsG2, VerificationKey,
    parse_decimal,
};
use ark_bls12_381::{Bls12_381, G1Affine as BlsG1Affine, G2Affine as BlsG2Affine};
use ark_bn254::{Bn254, G1Affine as Bn254G1Affine, G2Affine as Bn254G2Affine};
use ark_groth16::{Proof as ArkProof, VerifyingKey as ArkVerifyingKey};
use ark_serialize::CanonicalDeserialize;
use num_bigint::BigUint;
use serde_json::Value;
use std::fs;
use std::io::Cursor;
use std::path::Path;

pub fn parse_verification_key(path: &Path) -> Result<VerificationKey> {
    let raw = read_json(path)?;
    let raw_vk: RawVerificationKey =
        serde_json::from_value(raw.clone()).map_err(|e| Error::JsonParse {
            source: e,
            context: format!(
                "failed to deserialize verification_key.json from {}",
                path.display()
            ),
        })?;

    let vk_alpha_1 = parse_vk_alpha_1(raw_vk.vk_alpha_1.clone())?;
    let vk_beta_2 = SnarkJsG2::from_value(raw_vk.vk_beta_2, "vk_beta_2")?;
    let vk_gamma_2 = SnarkJsG2::from_value(raw_vk.vk_gamma_2, "vk_gamma_2")?;
    let vk_delta_2 = SnarkJsG2::from_value(raw_vk.vk_delta_2, "vk_delta_2")?;
    let ic = raw_vk
        .ic
        .into_iter()
        .enumerate()
        .map(|(idx, item)| SnarkJsG1::from_value(item, &format!("IC[{idx}]")))
        .collect::<Result<Vec<_>>>()?;

    Ok(VerificationKey {
        protocol: raw_vk.protocol,
        curve: raw_vk.curve,
        n_public: raw_vk.n_public,
        vk_alpha_1,
        vk_beta_2,
        vk_gamma_2,
        vk_delta_2,
        ic,
    })
}

pub fn parse_proof(path: &Path) -> Result<Proof> {
    let raw = read_json(path)?;
    let raw_proof: RawProof = serde_json::from_value(raw).map_err(|e| Error::JsonParse {
        source: e,
        context: format!("failed to deserialize proof.json from {}", path.display()),
    })?;

    Ok(Proof {
        protocol: raw_proof.protocol,
        curve: raw_proof.curve,
        pi_a: SnarkJsG1::from_value(raw_proof.pi_a, "pi_a")?,
        pi_b: SnarkJsG2::from_value(raw_proof.pi_b, "pi_b")?,
        pi_c: SnarkJsG1::from_value(raw_proof.pi_c, "pi_c")?,
    })
}

pub fn parse_public_inputs(path: &Path) -> Result<Vec<String>> {
    let raw = read_json(path)?;
    let array: Vec<Value> = serde_json::from_value(raw).map_err(|e| Error::JsonParse {
        source: e,
        context: format!("expected public.json to be array at {}", path.display()),
    })?;

    array
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            match value {
                Value::String(s) => {
                    // verify decimal
                    parse_decimal(s, &format!("public[{idx}]"))?;
                    Ok(s.clone())
                }
                Value::Number(num) => {
                    let decimal = num.to_string();
                    parse_decimal(&decimal, &format!("public[{idx}]"))?;
                    Ok(decimal)
                }
                _ => Err(Error::DecimalParse(format!(
                    "public[{idx}] must be string or number"
                ))),
            }
        })
        .collect()
}

pub fn parse_compact_artifact(
    path: &Path,
    curve_hint: Option<&str>,
) -> Result<(VerificationKey, Option<Proof>, Vec<String>)> {
    let raw = read_json(path)?;
    let raw: PackedArtifact = serde_json::from_value(raw).map_err(|e| Error::JsonParse {
        source: e,
        context: format!(
            "failed to deserialize compact artifact from {}",
            path.display()
        ),
    })?;

    let curve = parse_curve(raw.curve.as_deref(), curve_hint)?;
    let protocol = raw.protocol;
    let public_inputs = match raw.public_input {
        Some(public_input) => parse_public_input(Some(public_input), "public_input")?,
        None => Vec::new(),
    };

    let vk = parse_compact_vk(&curve, raw.vk)?;
    let proof = raw
        .proof
        .map(|proof| parse_compact_proof(&curve, proof))
        .transpose()?;

    let mut vk = vk;
    let mut proof = proof;
    let normalized_curve = curve.normalized_name().to_string();
    vk.curve = Some(normalized_curve.clone());
    if let Some(proof) = proof.as_mut() {
        proof.curve = Some(normalized_curve);
    }
    if let Some(protocol) = protocol {
        vk.protocol = Some(protocol.clone());
        if let Some(proof) = proof.as_mut() {
            proof.protocol = Some(protocol);
        }
    }

    Ok((vk, proof, public_inputs))
}

fn parse_vk_alpha_1(v: Value) -> Result<SnarkJsG1> {
    match v {
        Value::Array(items) => {
            // snarkjs sometimes sends [[x,y,z]]
            if items.len() == 1 {
                SnarkJsG1::from_value(items[0].clone(), "vk_alpha_1[0]") // flatten nested
            } else {
                SnarkJsG1::from_value(Value::Array(items), "vk_alpha_1")
            }
        }
        _ => Err(Error::MalformedG1(
            "vk_alpha_1 must be [x,y,z] or [[x,y,z]]".to_string(),
        )),
    }
}

fn read_json(path: &Path) -> Result<Value> {
    let content = fs::read_to_string(path).map_err(|e| Error::Io {
        source: e,
        context: format!("failed to read file {}", path.display()),
    })?;
    serde_json::from_str::<Value>(&content).map_err(|e| Error::JsonParse {
        source: e,
        context: format!("invalid json in file {}", path.display()),
    })
}

#[derive(Debug, Clone, Copy)]
enum CurveChoice {
    Bn254,
    Bls12381,
}

impl CurveChoice {
    fn normalized_name(&self) -> &'static str {
        match self {
            Self::Bn254 => "bn254",
            Self::Bls12381 => "bls12381",
        }
    }
}

fn parse_curve(value: Option<&str>, curve_hint: Option<&str>) -> Result<CurveChoice> {
    let raw_curve = value.or(curve_hint).ok_or_else(|| {
        Error::MissingInput("compact artifact requires curve metadata".to_string())
    })?;
    match normalize_curve_name(raw_curve).as_str() {
        "bn128" | "bn254" | "altbn128" => Ok(CurveChoice::Bn254),
        "bls12381" => Ok(CurveChoice::Bls12381),
        _ => Err(Error::UnsupportedCurve(format!(
            "unsupported curve in compact artifact: {raw_curve}"
        ))),
    }
}

fn normalize_curve_name(value: &str) -> String {
    value.to_lowercase().replace(['-', '_'], "")
}

fn parse_compact_proof(curve: &CurveChoice, proof: String) -> Result<Proof> {
    match curve {
        CurveChoice::Bn254 => parse_bn254_proof(&proof),
        CurveChoice::Bls12381 => parse_bls_proof(&proof),
    }
}

fn parse_compact_vk(curve: &CurveChoice, vk: Option<String>) -> Result<VerificationKey> {
    let vk = vk
        .ok_or_else(|| Error::MissingInput("compact artifact requires vk hex field".to_string()))?;
    match curve {
        CurveChoice::Bn254 => parse_bn254_vk(&vk),
        CurveChoice::Bls12381 => parse_bls_vk(&vk),
    }
}

fn parse_bn254_vk(vk_hex: &str) -> Result<VerificationKey> {
    let vk = decode_verifying_key_bn254(vk_hex)?;
    let vk_alpha_1 = point_from_bn254_g1(&vk.alpha_g1);
    let vk_beta_2 = point_from_bn254_g2(&vk.beta_g2);
    let vk_gamma_2 = point_from_bn254_g2(&vk.gamma_g2);
    let vk_delta_2 = point_from_bn254_g2(&vk.delta_g2);
    let ic = vk
        .gamma_abc_g1
        .iter()
        .map(point_from_bn254_g1)
        .collect::<Vec<_>>();

    Ok(VerificationKey {
        protocol: None,
        curve: Some("bn254".to_string()),
        n_public: vk.gamma_abc_g1.len().checked_sub(1).ok_or_else(|| {
            Error::IcLengthMismatch("compact BN254 VK has no IC points".to_string())
        })?,
        vk_alpha_1,
        vk_beta_2,
        vk_gamma_2,
        vk_delta_2,
        ic,
    })
}

fn decode_verifying_key_bn254(vk_hex: &str) -> Result<ArkVerifyingKey<Bn254>> {
    let bytes = decode_hex(vk_hex, "vk")?;
    let mut cursor = Cursor::new(bytes);
    let vk = ArkVerifyingKey::<Bn254>::deserialize_compressed(&mut cursor).map_err(|e| {
        Error::Serialization(format!(
            "failed to deserialize BN254 verifying key from hex: {e:?}"
        ))
    })?;
    ensure_no_trailing_bytes(&cursor, "BN254 verifying key")?;
    Ok(vk)
}

fn parse_bn254_proof(proof_hex: &str) -> Result<Proof> {
    let proof = decode_proof_bn254(proof_hex)?;
    Ok(Proof {
        protocol: None,
        curve: None,
        pi_a: point_from_bn254_g1(&proof.a),
        pi_b: point_from_bn254_g2(&proof.b),
        pi_c: point_from_bn254_g1(&proof.c),
    })
}

fn decode_proof_bn254(proof_hex: &str) -> Result<ArkProof<Bn254>> {
    let bytes = decode_hex(proof_hex, "proof")?;
    let mut cursor = Cursor::new(bytes);
    let proof = ArkProof::deserialize_compressed(&mut cursor).map_err(|e| {
        Error::Serialization(format!("failed to deserialize BN254 proof from hex: {e:?}"))
    })?;
    ensure_no_trailing_bytes(&cursor, "BN254 proof")?;
    Ok(proof)
}

fn parse_bls_vk(vk_hex: &str) -> Result<VerificationKey> {
    let vk = decode_verifying_key_bls(vk_hex)?;
    let vk_alpha_1 = point_from_bls_g1(&vk.alpha_g1);
    let vk_beta_2 = point_from_bls_g2(&vk.beta_g2);
    let vk_gamma_2 = point_from_bls_g2(&vk.gamma_g2);
    let vk_delta_2 = point_from_bls_g2(&vk.delta_g2);
    let ic = vk
        .gamma_abc_g1
        .iter()
        .map(point_from_bls_g1)
        .collect::<Vec<_>>();

    Ok(VerificationKey {
        protocol: None,
        curve: Some("bls12381".to_string()),
        n_public: vk.gamma_abc_g1.len().checked_sub(1).ok_or_else(|| {
            Error::IcLengthMismatch("compact BLS12-381 VK has no IC points".to_string())
        })?,
        vk_alpha_1,
        vk_beta_2,
        vk_gamma_2,
        vk_delta_2,
        ic,
    })
}

fn decode_verifying_key_bls(vk_hex: &str) -> Result<ArkVerifyingKey<Bls12_381>> {
    let bytes = decode_hex(vk_hex, "vk")?;
    let mut cursor = Cursor::new(bytes);
    let vk = ArkVerifyingKey::<Bls12_381>::deserialize_compressed(&mut cursor).map_err(|e| {
        Error::Serialization(format!(
            "failed to deserialize BLS12-381 verifying key from hex: {e:?}"
        ))
    })?;
    ensure_no_trailing_bytes(&cursor, "BLS12-381 verifying key")?;
    Ok(vk)
}

fn parse_bls_proof(proof_hex: &str) -> Result<Proof> {
    let proof = decode_proof_bls(proof_hex)?;
    Ok(Proof {
        protocol: None,
        curve: None,
        pi_a: point_from_bls_g1(&proof.a),
        pi_b: point_from_bls_g2(&proof.b),
        pi_c: point_from_bls_g1(&proof.c),
    })
}

fn decode_proof_bls(proof_hex: &str) -> Result<ArkProof<Bls12_381>> {
    let bytes = decode_hex(proof_hex, "proof")?;
    let mut cursor = Cursor::new(bytes);
    let proof = ArkProof::deserialize_compressed(&mut cursor).map_err(|e| {
        Error::Serialization(format!(
            "failed to deserialize BLS12-381 proof from hex: {e:?}"
        ))
    })?;
    ensure_no_trailing_bytes(&cursor, "BLS12-381 proof")?;
    Ok(proof)
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

fn point_from_bn254_g1(point: &Bn254G1Affine) -> SnarkJsG1 {
    SnarkJsG1 {
        x: point.x.to_string(),
        y: point.y.to_string(),
        z: "1".to_string(),
    }
}

fn point_from_bn254_g2(point: &Bn254G2Affine) -> SnarkJsG2 {
    SnarkJsG2 {
        x0: point.x.c0.to_string(),
        x1: point.x.c1.to_string(),
        y0: point.y.c0.to_string(),
        y1: point.y.c1.to_string(),
        z0: "1".to_string(),
        z1: "0".to_string(),
    }
}

fn point_from_bls_g1(point: &BlsG1Affine) -> SnarkJsG1 {
    SnarkJsG1 {
        x: point.x.to_string(),
        y: point.y.to_string(),
        z: "1".to_string(),
    }
}

fn point_from_bls_g2(point: &BlsG2Affine) -> SnarkJsG2 {
    SnarkJsG2 {
        x0: point.x.c0.to_string(),
        x1: point.x.c1.to_string(),
        y0: point.y.c0.to_string(),
        y1: point.y.c1.to_string(),
        z0: "1".to_string(),
        z1: "0".to_string(),
    }
}

fn parse_public_input(value: Option<Value>, field_name: &str) -> Result<Vec<String>> {
    let value = value.ok_or_else(|| {
        Error::MissingInput(format!(
            "{field_name} is required in compact artifacts; use standard public.json in legacy mode"
        ))
    })?;

    match value {
        Value::Array(values) => values
            .iter()
            .enumerate()
            .map(|(idx, item)| parse_public_input_value(item, &format!("{field_name}[{idx}]")))
            .collect(),
        _ => Ok(vec![parse_public_input_value(&value, field_name)?]),
    }
}

fn parse_public_input_value(value: &Value, field_name: &str) -> Result<String> {
    match value {
        Value::String(raw) => {
            let trimmed = raw.trim();
            parse_compact_scalar(trimmed, field_name)
        }
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

fn parse_compact_scalar(raw: &str, field_name: &str) -> Result<String> {
    let has_hex_prefix = raw.starts_with("0x") || raw.starts_with("0X");
    let value = if has_hex_prefix { &raw[2..] } else { raw };
    if has_hex_prefix {
        if value.chars().all(|c| c.is_ascii_hexdigit()) {
            let value = BigUint::parse_bytes(value.as_bytes(), 16)
                .ok_or_else(|| {
                    Error::DecimalParse(format!("{field_name} could not parse hex scalar {raw}"))
                })?
                .to_string();
            return Ok(value);
        }
        return Err(Error::DecimalParse(format!(
            "{field_name} has invalid hex prefix form"
        )));
    }

    if value.chars().all(|c| c.is_ascii_digit()) {
        parse_decimal(value, field_name)?;
        return Ok(value.to_string());
    }
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(value).map_err(|e| {
            Error::DecimalParse(format!(
                "{field_name} could not parse serialized scalar bytes {raw}: {e}"
            ))
        })?;
        return Ok(BigUint::from_bytes_le(&bytes).to_string());
    }
    if value.chars().all(|c| c.is_ascii_hexdigit()) {
        let value = BigUint::parse_bytes(value.as_bytes(), 16)
            .ok_or_else(|| {
                Error::DecimalParse(format!("{field_name} could not parse hex scalar {raw}"))
            })?
            .to_string();
        return Ok(value);
    }
    Err(Error::DecimalParse(format!(
        "{field_name} must be decimal or hex string"
    )))
}

fn decode_hex(raw: &str, field: &str) -> Result<Vec<u8>> {
    let hex = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
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
