use crate::error::{Error, Result};
use crate::snarkjs::{Proof, VerificationKey};

fn normalize_protocol(protocol: &str) -> String {
    protocol.to_lowercase()
}

fn normalize_curve_name(curve: &str) -> String {
    curve.to_lowercase().replace(['-', '_'], "")
}

fn canonical_curve(curve: &str) -> Option<&'static str> {
    match normalize_curve_name(curve).as_str() {
        "bn128" | "bn254" | "altbn128" => Some("bn254"),
        "bls12381" => Some("bls12381"),
        _ => None,
    }
}

pub fn validate_protocol(
    vk_protocol: Option<&String>,
    proof_protocol: Option<&String>,
) -> Result<()> {
    if let Some(p) = vk_protocol
        && normalize_protocol(p) != "groth16"
    {
        return Err(Error::UnsupportedProtocol(format!(
            "verification key protocol is {p}, expected groth16"
        )));
    }
    if let Some(p) = proof_protocol
        && normalize_protocol(p) != "groth16"
    {
        return Err(Error::UnsupportedProtocol(format!(
            "proof protocol is {p}, expected groth16"
        )));
    }
    Ok(())
}

pub fn validate_curve_match(
    vk_curve: Option<&String>,
    proof_curve: Option<&String>,
) -> Result<String> {
    match (vk_curve, proof_curve) {
        (Some(v), Some(p)) => {
            let vk_curve = canonical_curve(v).ok_or_else(|| {
                Error::UnsupportedCurve(format!("unsupported verification key curve: {v}"))
            })?;
            let proof_curve = canonical_curve(p)
                .ok_or_else(|| Error::UnsupportedCurve(format!("unsupported proof curve: {p}")))?;

            if vk_curve != proof_curve {
                return Err(Error::CurveMismatch(format!(
                    "verification key curve {v} does not match proof curve {p}"
                )));
            }

            Ok(vk_curve.to_string())
        }
        (Some(v), None) => canonical_curve(v).map(str::to_string).ok_or_else(|| {
            Error::UnsupportedCurve(format!("unsupported verification key curve: {v}"))
        }),
        (None, Some(p)) => canonical_curve(p)
            .map(str::to_string)
            .ok_or_else(|| Error::UnsupportedCurve(format!("unsupported proof curve: {p}"))),
        (None, None) => Err(Error::UnsupportedCurve(
            "curve not specified in input files; include curve metadata".to_string(),
        )),
    }
}

pub fn validate_public_counts(vk: &VerificationKey, public_inputs: &[String]) -> Result<()> {
    if vk.n_public != public_inputs.len() {
        return Err(Error::PublicInputCountMismatch(format!(
            "expected nPublic={}, got {}",
            vk.n_public,
            public_inputs.len()
        )));
    }
    if vk.ic.len() != vk.n_public + 1 {
        return Err(Error::IcLengthMismatch(format!(
            "expected IC length = nPublic + 1, got {}",
            vk.ic.len()
        )));
    }
    Ok(())
}

pub fn validate_verification_key_geometry(vk: &VerificationKey) -> Result<()> {
    if vk.vk_alpha_1.z.is_empty() {
        return Err(Error::MalformedG1("vk_alpha_1 invalid".to_string()));
    }
    if vk.vk_beta_2.z0.is_empty() || vk.vk_gamma_2.z0.is_empty() || vk.vk_delta_2.z0.is_empty() {
        return Err(Error::MalformedG2("G2 point malformed".to_string()));
    }
    Ok(())
}

pub fn validate_proof_curve_and_protocol(vk: &VerificationKey, proof: &Proof) -> Result<()> {
    validate_protocol(vk.protocol.as_ref(), proof.protocol.as_ref())?;
    validate_curve_match(vk.curve.as_ref(), proof.curve.as_ref())?;
    Ok(())
}
