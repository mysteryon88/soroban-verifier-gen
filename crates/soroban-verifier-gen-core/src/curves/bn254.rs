use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use num_bigint::BigUint;
use std::str::FromStr;

use crate::bytes::to_le_padded_bytes;
use crate::curves::{CurveAdapter, CurveId, PointFormat};
use crate::error::{Error, Result};
use crate::model::{
    DecimalValue, Groth16G1Point, Groth16G2Point, Groth16Proof, Groth16VerificationKey,
    Groth16VerifierInputs,
};
use crate::snarkjs::parse_decimal;

#[derive(Default)]
pub struct Bn254Adapter;

impl CurveAdapter for Bn254Adapter {
    fn id(&self) -> CurveId {
        CurveId::Bn254
    }

    fn accepted_curve_names(&self) -> &'static [&'static str] {
        &["bn128", "bn254", "alt_bn128"]
    }

    fn serialize_g1_vk(&self, point: &Groth16G1Point) -> Result<Vec<u8>> {
        serialize_g1_uncompressed(point)
    }

    fn serialize_g2_vk(&self, point: &Groth16G2Point) -> Result<Vec<u8>> {
        serialize_g2_uncompressed(point)
    }

    fn serialize_g1_proof(&self, point: &Groth16G1Point) -> Result<Vec<u8>> {
        serialize_g1_uncompressed(point)
    }

    fn serialize_g2_proof(&self, point: &Groth16G2Point) -> Result<Vec<u8>> {
        serialize_g2_uncompressed(point)
    }

    fn serialize_fr_public_input(&self, value: &DecimalValue) -> Result<Vec<u8>> {
        serialize_fr_le(value)
    }

    fn local_verify(&self, inputs: &Groth16VerifierInputs) -> Result<bool> {
        let vk = convert_vkey(&inputs.verifying_key)?;
        let proof = inputs.proof.as_ref().ok_or_else(|| {
            Error::MissingInput("local verification requires proof input".to_string())
        })?;
        let proof = convert_proof(proof)?;
        let public_inputs = parse_public_inputs(&inputs.public_inputs)?;

        let prepared_vk = prepare_verifying_key(&vk);
        let ok =
            Groth16::<Bn254>::verify_proof(&prepared_vk, &proof, &public_inputs).map_err(|e| {
                Error::LocalProofVerificationFailed(format!(
                    "groth16 BN254 local verify failed: {e:?}"
                ))
            })?;
        Ok(ok)
    }

    fn default_point_format(&self) -> PointFormat {
        PointFormat::Uncompressed
    }
}

fn serialize_g1_uncompressed(point: &Groth16G1Point) -> Result<Vec<u8>> {
    let point = normalize_g1(point)?;
    let x = point.x.into_bigint().to_bytes_le();
    let y = point.y.into_bigint().to_bytes_le();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&to_le_padded_bytes(&BigUint::from_bytes_le(&x), 32));
    out.extend_from_slice(&to_le_padded_bytes(&BigUint::from_bytes_le(&y), 32));
    Ok(out)
}

fn serialize_g2_uncompressed(point: &Groth16G2Point) -> Result<Vec<u8>> {
    let point = normalize_g2(point)?;
    let mut out = Vec::with_capacity(128);
    let x_c0 = point.x.c0.into_bigint().to_bytes_le();
    let x_c1 = point.x.c1.into_bigint().to_bytes_le();
    let y_c0 = point.y.c0.into_bigint().to_bytes_le();
    let y_c1 = point.y.c1.into_bigint().to_bytes_le();
    out.extend_from_slice(&to_le_padded_bytes(&BigUint::from_bytes_le(&x_c0), 32));
    out.extend_from_slice(&to_le_padded_bytes(&BigUint::from_bytes_le(&x_c1), 32));
    out.extend_from_slice(&to_le_padded_bytes(&BigUint::from_bytes_le(&y_c0), 32));
    out.extend_from_slice(&to_le_padded_bytes(&BigUint::from_bytes_le(&y_c1), 32));
    Ok(out)
}

fn serialize_fr_le(value: &DecimalValue) -> Result<Vec<u8>> {
    let scalar = parse_field_fr(value, "public input")?;
    let bytes = scalar.into_bigint().to_bytes_le();
    Ok(to_le_padded_bytes(&BigUint::from_bytes_le(&bytes), 32))
}

fn convert_vkey(vk: &Groth16VerificationKey) -> Result<VerifyingKey<Bn254>> {
    Ok(VerifyingKey {
        alpha_g1: normalize_g1(&vk.vk_alpha_1)?,
        beta_g2: normalize_g2(&vk.vk_beta_2)?,
        gamma_g2: normalize_g2(&vk.vk_gamma_2)?,
        delta_g2: normalize_g2(&vk.vk_delta_2)?,
        gamma_abc_g1: vk.ic.iter().map(normalize_g1).collect::<Result<Vec<_>>>()?,
    })
}

fn convert_proof(proof: &Groth16Proof) -> Result<Proof<Bn254>> {
    Ok(Proof {
        a: normalize_g1(&proof.pi_a)?,
        b: normalize_g2(&proof.pi_b)?,
        c: normalize_g1(&proof.pi_c)?,
    })
}

fn parse_public_inputs(values: &[DecimalValue]) -> Result<Vec<Fr>> {
    values
        .iter()
        .enumerate()
        .map(|(idx, value)| parse_field_fr(value, &format!("public[{idx}]")))
        .collect()
}

fn normalize_g1(point: &Groth16G1Point) -> Result<G1Affine> {
    let x = parse_base_field(&point.x, "g1.x")?;
    let y = parse_base_field(&point.y, "g1.y")?;
    let z = parse_base_field(&point.z, "g1.z")?;

    if z.is_zero() {
        return Err(Error::MalformedG1("g1.z is zero".to_string()));
    }

    let z_inv = z
        .inverse()
        .ok_or_else(|| Error::PointNotOnCurve("g1.z is non-invertible".to_string()))?;
    let z_inv2 = z_inv.square();
    let z_inv3 = z_inv2 * z_inv;
    let affine = G1Affine::new_unchecked(x * z_inv2, y * z_inv3);

    if !affine.is_on_curve() {
        return Err(Error::PointNotOnCurve(
            "g1 point is not on curve".to_string(),
        ));
    }
    if !affine.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::PointNotInSubgroup(
            "g1 point is not in the correct subgroup".to_string(),
        ));
    }
    Ok(affine)
}

fn normalize_g2(point: &Groth16G2Point) -> Result<G2Affine> {
    let x = Fq2::new(
        parse_base_field(&point.x0, "g2.x.0")?,
        parse_base_field(&point.x1, "g2.x.1")?,
    );
    let y = Fq2::new(
        parse_base_field(&point.y0, "g2.y.0")?,
        parse_base_field(&point.y1, "g2.y.1")?,
    );
    let z = Fq2::new(
        parse_base_field(&point.z0, "g2.z.0")?,
        parse_base_field(&point.z1, "g2.z.1")?,
    );

    if z.is_zero() {
        return Err(Error::MalformedG2("g2.z is zero".to_string()));
    }

    let z_inv = z
        .inverse()
        .ok_or_else(|| Error::PointNotOnCurve("g2.z is non-invertible".to_string()))?;
    let z_inv2 = z_inv.square();
    let z_inv3 = z_inv2 * z_inv;
    let affine = G2Affine::new_unchecked(x * z_inv2, y * z_inv3);

    if !affine.is_on_curve() {
        return Err(Error::PointNotOnCurve(
            "g2 point is not on curve".to_string(),
        ));
    }
    if !affine.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::PointNotInSubgroup(
            "g2 point is not in the correct subgroup".to_string(),
        ));
    }

    Ok(affine)
}

fn parse_base_field(value: &str, field: &str) -> Result<Fq> {
    let max = parse_biguint(&format!("{}", Fq::MODULUS))?;
    let parsed = parse_decimal(value, field)?;
    if parsed >= max {
        return Err(Error::FieldOverflow(format!(
            "{field} is not a valid BN254 base field element"
        )));
    }
    Fq::from_str(value).map_err(|_| Error::DecimalParse(format!("{field} parse to field failed")))
}

fn parse_field_fr(value: &str, field: &str) -> Result<Fr> {
    let max = parse_biguint(&format!("{}", Fr::MODULUS))?;
    let parsed = parse_decimal(value, field)?;
    if parsed >= max {
        return Err(Error::FieldOverflow(format!(
            "{field} is not a valid BN254 scalar field element"
        )));
    }
    Fr::from_str(value).map_err(|_| Error::DecimalParse(format!("{field} parse to scalar failed")))
}

fn parse_biguint(raw: &str) -> Result<BigUint> {
    BigUint::from_str(raw)
        .map_err(|_| Error::Serialization("failed to parse internal field modulus".to_string()))
}
