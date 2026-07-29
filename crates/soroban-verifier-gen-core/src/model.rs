use crate::error::{Error, Result};
use crate::snarkjs::{
    Proof as LegacyProof, SnarkJsG1, SnarkJsG2, VerificationKey as LegacyVerificationKey,
    validate_curve_match, validate_protocol, validate_public_counts,
    validate_verification_key_geometry,
};

pub type DecimalValue = String;

pub(crate) fn expected_ic_len(n_public: usize) -> Result<usize> {
    n_public.checked_add(1).ok_or_else(|| {
        Error::IcLengthMismatch("nPublic is too large to represent IC length".to_string())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveKind {
    Bn254,
    Bls12_381,
}

impl CurveKind {
    pub fn from_name(value: &str) -> Result<Self> {
        match normalize_curve_name(value).as_str() {
            "bn128" | "bn254" | "altbn128" => Ok(Self::Bn254),
            "bls12381" => Ok(Self::Bls12_381),
            _ => Err(Error::UnsupportedCurve(format!(
                "unsupported curve: {value}"
            ))),
        }
    }

    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Bn254 => "bn254",
            Self::Bls12_381 => "bls12381",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    SnarkjsJson,
    Arkworks,
    ArkworksCompact,
    GnarkJson,
    GnarkBinary,
    Sp1Groth16,
}

#[derive(Debug, Clone)]
pub struct Groth16G1Point {
    pub x: DecimalValue,
    pub y: DecimalValue,
    pub z: DecimalValue,
}

#[derive(Debug, Clone)]
pub struct Groth16G2Point {
    pub x0: DecimalValue,
    pub x1: DecimalValue,
    pub y0: DecimalValue,
    pub y1: DecimalValue,
    pub z0: DecimalValue,
    pub z1: DecimalValue,
}

#[derive(Debug, Clone)]
pub struct Groth16VerificationKey {
    pub n_public: usize,
    pub vk_alpha_1: Groth16G1Point,
    pub vk_beta_2: Groth16G2Point,
    pub vk_gamma_2: Groth16G2Point,
    pub vk_delta_2: Groth16G2Point,
    pub ic: Vec<Groth16G1Point>,
}

#[derive(Debug, Clone)]
pub struct Groth16Proof {
    pub pi_a: Groth16G1Point,
    pub pi_b: Groth16G2Point,
    pub pi_c: Groth16G1Point,
}

#[derive(Debug, Clone)]
pub struct Groth16VerifierInputs {
    pub curve: CurveKind,
    pub protocol: String,
    pub verifying_key: Groth16VerificationKey,
    pub proof: Option<Groth16Proof>,
    pub public_inputs: Vec<DecimalValue>,
    pub source_format: SourceFormat,
}

impl Groth16VerifierInputs {
    pub(crate) fn validate_for_local_verification(&self, expected_curve: CurveKind) -> Result<()> {
        if self.curve != expected_curve {
            return Err(Error::CurveMismatch(format!(
                "local verification adapter expects {}, got {}",
                expected_curve.canonical_name(),
                self.curve.canonical_name()
            )));
        }
        if !self.protocol.eq_ignore_ascii_case("groth16") {
            return Err(Error::UnsupportedProtocol(format!(
                "local verification requires groth16, got {}",
                self.protocol
            )));
        }
        if self.proof.is_none() {
            return Err(Error::MissingInput(
                "local verification requires proof input".to_string(),
            ));
        }
        let expected_ic = expected_ic_len(self.verifying_key.n_public)?;
        if self.verifying_key.ic.len() != expected_ic {
            return Err(Error::IcLengthMismatch(format!(
                "expected {expected_ic} IC points, got {}",
                self.verifying_key.ic.len()
            )));
        }
        if self.public_inputs.len() != self.verifying_key.n_public {
            return Err(Error::PublicInputCountMismatch(format!(
                "verification key expects {} public inputs, got {}",
                self.verifying_key.n_public,
                self.public_inputs.len()
            )));
        }
        Ok(())
    }

    pub fn from_legacy(
        vk: LegacyVerificationKey,
        proof: LegacyProof,
        public_inputs: Vec<DecimalValue>,
        source_format: SourceFormat,
    ) -> Result<Self> {
        validate_protocol(vk.protocol.as_ref(), proof.protocol.as_ref())?;
        validate_verification_key_geometry(&vk)?;
        validate_public_counts(&vk, &public_inputs)?;

        let curve_name = validate_curve_match(vk.curve.as_ref(), proof.curve.as_ref())?;
        let curve = CurveKind::from_name(&curve_name)?;
        let protocol = vk
            .protocol
            .clone()
            .or_else(|| proof.protocol.clone())
            .unwrap_or_else(|| "groth16".to_string());

        Ok(Self {
            curve,
            protocol,
            verifying_key: Groth16VerificationKey {
                n_public: vk.n_public,
                vk_alpha_1: vk.vk_alpha_1.into(),
                vk_beta_2: vk.vk_beta_2.into(),
                vk_gamma_2: vk.vk_gamma_2.into(),
                vk_delta_2: vk.vk_delta_2.into(),
                ic: vk.ic.into_iter().map(Into::into).collect(),
            },
            proof: Some(Groth16Proof {
                pi_a: proof.pi_a.into(),
                pi_b: proof.pi_b.into(),
                pi_c: proof.pi_c.into(),
            }),
            public_inputs,
            source_format,
        })
    }

    pub fn from_legacy_vk_only(
        vk: LegacyVerificationKey,
        public_inputs: Vec<DecimalValue>,
        source_format: SourceFormat,
    ) -> Result<Self> {
        validate_protocol(vk.protocol.as_ref(), None)?;
        validate_verification_key_geometry(&vk)?;

        if vk.ic.len() != expected_ic_len(vk.n_public)? {
            return Err(Error::IcLengthMismatch(format!(
                "expected IC length = nPublic + 1, got {}",
                vk.ic.len()
            )));
        }
        if !public_inputs.is_empty() && vk.n_public != public_inputs.len() {
            return Err(Error::PublicInputCountMismatch(format!(
                "expected nPublic={}, got {}",
                vk.n_public,
                public_inputs.len()
            )));
        }

        let curve_name = validate_curve_match(vk.curve.as_ref(), None)?;
        let curve = CurveKind::from_name(&curve_name)?;
        let protocol = vk.protocol.clone().unwrap_or_else(|| "groth16".to_string());

        Ok(Self {
            curve,
            protocol,
            verifying_key: Groth16VerificationKey {
                n_public: vk.n_public,
                vk_alpha_1: vk.vk_alpha_1.into(),
                vk_beta_2: vk.vk_beta_2.into(),
                vk_gamma_2: vk.vk_gamma_2.into(),
                vk_delta_2: vk.vk_delta_2.into(),
                ic: vk.ic.into_iter().map(Into::into).collect(),
            },
            proof: None,
            public_inputs,
            source_format,
        })
    }

    pub fn from_parts(
        curve: CurveKind,
        verifying_key: Groth16VerificationKey,
        proof: Option<Groth16Proof>,
        public_inputs: Vec<DecimalValue>,
        source_format: SourceFormat,
    ) -> Result<Self> {
        if verifying_key.ic.len() != expected_ic_len(verifying_key.n_public)? {
            return Err(Error::IcLengthMismatch(format!(
                "expected {} IC points, got {}",
                verifying_key.n_public + 1,
                verifying_key.ic.len()
            )));
        }
        if proof.is_some() && public_inputs.len() != verifying_key.n_public {
            return Err(Error::PublicInputCountMismatch(format!(
                "verification key expects {} public inputs, got {}",
                verifying_key.n_public,
                public_inputs.len()
            )));
        }
        if proof.is_none()
            && !public_inputs.is_empty()
            && public_inputs.len() != verifying_key.n_public
        {
            return Err(Error::PublicInputCountMismatch(format!(
                "verification key expects {} public inputs, got {}",
                verifying_key.n_public,
                public_inputs.len()
            )));
        }

        Ok(Self {
            curve,
            protocol: "groth16".to_string(),
            verifying_key,
            proof,
            public_inputs,
            source_format,
        })
    }

    pub fn has_test_vectors(&self) -> bool {
        self.proof.is_some()
    }
}

impl From<SnarkJsG1> for Groth16G1Point {
    fn from(value: SnarkJsG1) -> Self {
        Self {
            x: value.x,
            y: value.y,
            z: value.z,
        }
    }
}

impl From<SnarkJsG2> for Groth16G2Point {
    fn from(value: SnarkJsG2) -> Self {
        Self {
            x0: value.x0,
            x1: value.x1,
            y0: value.y0,
            y1: value.y1,
            z0: value.z0,
            z1: value.z1,
        }
    }
}

fn normalize_curve_name(value: &str) -> String {
    value.to_lowercase().replace(['-', '_'], "")
}

#[cfg(test)]
mod tests {
    use super::expected_ic_len;

    #[test]
    fn oversized_public_input_count_returns_error() {
        assert!(expected_ic_len(usize::MAX).is_err());
    }
}
