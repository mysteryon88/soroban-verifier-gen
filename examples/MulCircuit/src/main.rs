use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_snarkjs::{export_proof, export_vk};
use ark_std::One;
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::test_rng;
use std::fs;
use std::path::Path;

#[derive(Clone)]
struct MulCircuit<F: PrimeField> {
    pub x: Option<F>, // witness
    pub y: Option<F>, // witness
    pub z: F,         // public = x*y
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MulCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x = FpVar::<F>::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y = FpVar::<F>::new_witness(cs.clone(), || {
            self.y.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let z = FpVar::<F>::new_input(cs, || Ok(self.z))?;
        let prod = &x * &y;
        prod.enforce_equal(&z)?;
        Ok(())
    }
}

fn public_inputs_json(inputs: &[Fr]) -> String {
    let values = inputs
        .iter()
        .map(|value| format!("\"{}\"", value.into_bigint()))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{values}]")
}

fn main() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    // числа для примера
    let x: u128 = 641;
    let y: u128 = 6_700_417;

    let xf = Fr::from(x);
    let yf = Fr::from(y);
    let zf = xf * yf;

    let empty = MulCircuit::<Fr> {
        x: None,
        y: None,
        z: Fr::one(),
    };
    let params =
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(empty, &mut rng).unwrap();

    let circuit = MulCircuit::<Fr> {
        x: Some(xf),
        y: Some(yf),
        z: zf,
    };
    let proof = Groth16::<Bls12_381>::prove(&params, circuit, &mut rng).unwrap();

    let pvk = prepare_verifying_key(&params.vk);
    let public_inputs = vec![zf];
    let ok = Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap();
    assert!(ok);

    let out_dir = Path::new("artifacts").join("bls12_381");
    fs::create_dir_all(&out_dir).unwrap();
    export_proof::<Bls12_381, _>(&proof, &public_inputs, out_dir.join("proof.json")).unwrap();
    export_vk::<Bls12_381, _>(
        &params.vk,
        public_inputs.len(),
        out_dir.join("verification_key.json"),
    )
    .unwrap();
    fs::write(
        out_dir.join("public.json"),
        public_inputs_json(&public_inputs),
    )
    .unwrap();

    let mut vk_bytes = Vec::new();
    params.vk.serialize_compressed(&mut vk_bytes).unwrap();
    println!("\n[BLS12-381] VK: {}", hex::encode(vk_bytes));

    let mut pr_bytes = Vec::new();
    proof.serialize_compressed(&mut pr_bytes).unwrap();
    println!("[BLS12-381] Proof: {}", hex::encode(pr_bytes));

    let mut pi_bytes = Vec::new();
    zf.serialize_compressed(&mut pi_bytes).unwrap();
    println!("[BLS12-381] Public inputs: {}", hex::encode(pi_bytes));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_inputs_json_uses_decimal_strings() {
        let json = public_inputs_json(&[Fr::from(42_u64), Fr::from(7_u64)]);

        assert_eq!(json, "[\"42\",\"7\"]");
    }
}
