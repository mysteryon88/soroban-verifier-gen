mod bls12381;
mod bn254;

use crate::error::{Error, Result};
use crate::model::{DecimalValue, Groth16G1Point, Groth16G2Point, Groth16VerifierInputs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveId {
    Bn254,
    Bls12381,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointFormat {
    Compressed,
    Uncompressed,
}

pub trait CurveAdapter: Send + Sync {
    fn id(&self) -> CurveId;
    fn accepted_curve_names(&self) -> &'static [&'static str];
    fn serialize_g1_vk(&self, point: &Groth16G1Point) -> Result<Vec<u8>>;
    fn serialize_g2_vk(&self, point: &Groth16G2Point) -> Result<Vec<u8>>;
    fn serialize_g1_proof(&self, point: &Groth16G1Point) -> Result<Vec<u8>>;
    fn serialize_g2_proof(&self, point: &Groth16G2Point) -> Result<Vec<u8>>;
    fn serialize_fr_public_input(&self, value: &DecimalValue) -> Result<Vec<u8>>;
    fn local_verify(&self, inputs: &Groth16VerifierInputs) -> Result<bool>;
    fn default_point_format(&self) -> PointFormat;
}

pub fn create_adapter(name: &str) -> Result<Box<dyn CurveAdapter>> {
    let normalized = name.to_lowercase().replace(['_', '-'], "");
    match normalized.as_str() {
        "bn128" | "bn254" | "altbn128" => Ok(Box::new(bn254::Bn254Adapter {})),
        "bls12381" => Ok(Box::new(bls12381::Bls12381Adapter {})),
        other => Err(Error::UnsupportedCurve(format!(
            "unsupported curve: {other}"
        ))),
    }
}
