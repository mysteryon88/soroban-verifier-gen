use crate::curves::{CurveAdapter, CurveId};
use crate::error::Result;
use crate::model::{CurveKind, Groth16VerifierInputs};
mod local_verify;

pub fn local_verify(adapter: &dyn CurveAdapter, inputs: &Groth16VerifierInputs) -> Result<bool> {
    let expected_curve = match adapter.id() {
        CurveId::Bn254 => CurveKind::Bn254,
        CurveId::Bls12381 => CurveKind::Bls12_381,
    };
    inputs.validate_for_local_verification(expected_curve)?;
    adapter.local_verify(inputs)
}
