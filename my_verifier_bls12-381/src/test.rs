extern crate std;

use ark_bls12_381::{Fq, Fq2};
use ark_serialize::CanonicalSerialize;
use core::str::FromStr;
use serde::Deserialize;
use soroban_sdk::{
    Env, U256, Vec,
    crypto::bls12_381::{
        Bls12381Fr, Bls12381G1Affine, Bls12381G2Affine, G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE,
    },
};

use crate::{Groth16Error, Groth16Verifier, Groth16VerifierClient, Proof};

#[derive(Deserialize)]
struct ProofJson {
    pi_a: [std::string::String; 3],
    pi_b: [[std::string::String; 2]; 3],
    pi_c: [std::string::String; 3],
}

fn g1_from_coords(env: &Env, x: &str, y: &str) -> Bls12381G1Affine {
    let ark_g1 = ark_bls12_381::G1Affine::new(Fq::from_str(x).unwrap(), Fq::from_str(y).unwrap());
    let mut buf = [0u8; G1_SERIALIZED_SIZE];
    ark_g1.serialize_uncompressed(&mut buf[..]).unwrap();
    Bls12381G1Affine::from_array(env, &buf)
}

fn g2_from_coords(env: &Env, x1: &str, x2: &str, y1: &str, y2: &str) -> Bls12381G2Affine {
    let x = Fq2::new(Fq::from_str(x1).unwrap(), Fq::from_str(x2).unwrap());
    let y = Fq2::new(Fq::from_str(y1).unwrap(), Fq::from_str(y2).unwrap());
    let ark_g2 = ark_bls12_381::G2Affine::new(x, y);
    let mut buf = [0u8; G2_SERIALIZED_SIZE];
    ark_g2.serialize_uncompressed(&mut buf[..]).unwrap();
    Bls12381G2Affine::from_array(env, &buf)
}

fn create_client(e: &Env) -> Groth16VerifierClient<'_> {
    let contract_id = e.register(Groth16Verifier {}, ());
    Groth16VerifierClient::new(e, &contract_id)
}

fn load_proof(env: &Env) -> Proof {
    let proof_json_str = include_str!("../../examples/data/bls12-381/proof.json");
    let proof_json: ProofJson = serde_json::from_str(proof_json_str).unwrap();

    let pi_ax = &proof_json.pi_a[0];
    let pi_ay = &proof_json.pi_a[1];
    let pi_bx1 = &proof_json.pi_b[0][0];
    let pi_bx2 = &proof_json.pi_b[0][1];
    let pi_by1 = &proof_json.pi_b[1][0];
    let pi_by2 = &proof_json.pi_b[1][1];
    let pi_cx = &proof_json.pi_c[0];
    let pi_cy = &proof_json.pi_c[1];

    Proof {
        a: g1_from_coords(env, pi_ax, pi_ay),
        b: g2_from_coords(env, pi_bx1, pi_bx2, pi_by1, pi_by2),
        c: g1_from_coords(env, pi_cx, pi_cy),
    }
}

fn load_public_signals(env: &Env) -> Vec<Bls12381Fr> {
    let public_json_str = include_str!("../../examples/data/bls12-381/public.json");
    let public_signals: std::vec::Vec<std::string::String> =
        serde_json::from_str(public_json_str).unwrap();
    let expected_output: u32 = public_signals[0].parse().unwrap();
    Vec::from_array(
        env,
        [Bls12381Fr::from_u256(U256::from_u32(&env, expected_output))],
    )
}

#[test]
fn accepts_valid_proof_with_expected_public_signal() {
    let env = Env::default();
    let proof = load_proof(&env);
    let output = load_public_signals(&env);
    let client = create_client(&env);

    let res = client.verify_proof(&proof, &output);
    assert_eq!(res, true);
}

#[test]
fn rejects_valid_proof_with_wrong_public_signal() {
    let env = Env::default();
    let proof = load_proof(&env);
    let client = create_client(&env);

    let output = Vec::from_array(&env, [Bls12381Fr::from_u256(U256::from_u32(&env, 22))]);
    let res = client.verify_proof(&proof, &output);
    assert_eq!(res, false);
}

#[test]
fn errors_when_public_signal_length_does_not_match_vk() {
    let env = Env::default();
    let proof = load_proof(&env);

    let res = Groth16Verifier::verify_proof(env.clone(), proof, Vec::new(&env));
    assert_eq!(res, Err(Groth16Error::MalformedVerifyingKey));
}
