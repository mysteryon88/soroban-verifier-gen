use crate::error::Result;
use crate::model::{Groth16VerifierInputs, SourceFormat};
use crate::snarkjs::parse_compact_artifact;
use std::path::Path;

pub fn load_compact_bundle(path: &Path, curve_hint: Option<&str>) -> Result<Groth16VerifierInputs> {
    let (vk, proof, public_inputs) = parse_compact_artifact(path, curve_hint)?;
    match proof {
        Some(proof) => Groth16VerifierInputs::from_legacy(
            vk,
            proof,
            public_inputs,
            SourceFormat::ArkworksCompact,
        ),
        None => Groth16VerifierInputs::from_legacy_vk_only(
            vk,
            public_inputs,
            SourceFormat::ArkworksCompact,
        ),
    }
}
