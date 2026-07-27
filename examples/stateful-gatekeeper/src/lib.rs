#![no_std]
use soroban_sdk::{
    Bytes, BytesN, Env, Vec, contract, contracterror, contractimpl, contracttype,
    crypto::bn254::{
        BN254_G1_SERIALIZED_SIZE, BN254_G2_SERIALIZED_SIZE, Bn254Fr, Bn254G1Affine, Bn254G2Affine,
    },
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Groth16Error {
    MalformedVerifyingKey = 0,
    NonCanonicalPublicInput = 1,
}

#[derive(Clone)]
#[contracttype]
pub struct VerificationKey {
    pub alpha: Bn254G1Affine,
    pub beta: Bn254G2Affine,
    pub gamma: Bn254G2Affine,
    pub delta: Bn254G2Affine,
    pub ic: Vec<Bn254G1Affine>,
}

#[derive(Clone)]
#[contracttype]
pub struct Proof {
    pub a: Bn254G1Affine,
    pub b: Bn254G2Affine,
    pub c: Bn254G1Affine,
}

// AUTO-GENERATED VK BYTES (uncompressed). DO NOT EDIT.
const VK_ALPHA: [u8; BN254_G1_SERIALIZED_SIZE] = [
    0x12, 0x2c, 0x44, 0x62, 0x20, 0xb5, 0x12, 0x7b, 0x2b, 0xf6, 0x8e, 0x3c, 0x69, 0x58, 0xc0, 0xc5,
    0xa1, 0xf7, 0x10, 0xdc, 0x39, 0x4b, 0xcf, 0xcb, 0xed, 0x6d, 0x97, 0x34, 0xed, 0x94, 0x50, 0x43,
    0x17, 0x8f, 0x28, 0x05, 0xa2, 0x1b, 0x49, 0x19, 0x2a, 0x21, 0x64, 0x80, 0x5d, 0xe3, 0x4b, 0xf5,
    0x1c, 0xba, 0x6f, 0x1e, 0xae, 0x25, 0xc3, 0x9d, 0xec, 0x5c, 0x2c, 0xea, 0xab, 0xa1, 0x43, 0x94,
];
const VK_BETA: [u8; BN254_G2_SERIALIZED_SIZE] = [
    0x00, 0x72, 0xfc, 0xb3, 0xe7, 0xbd, 0xfb, 0x17, 0x92, 0x78, 0x8e, 0x62, 0x19, 0xb5, 0x91, 0xe0,
    0xe0, 0x93, 0xa7, 0x56, 0xb7, 0xe1, 0x05, 0x30, 0x7d, 0x71, 0xd8, 0x44, 0x2a, 0xfc, 0x41, 0x62,
    0x25, 0x31, 0x98, 0xab, 0x9c, 0xa9, 0x4e, 0xd7, 0x9f, 0x1d, 0x53, 0x05, 0x2c, 0xed, 0x2a, 0xd9,
    0x58, 0x23, 0xcc, 0x5d, 0x7d, 0x5b, 0x9b, 0xca, 0x82, 0xff, 0xee, 0x19, 0x15, 0x53, 0x98, 0xa6,
    0x22, 0xbc, 0xc5, 0x80, 0x62, 0x51, 0x24, 0xfc, 0x45, 0xdd, 0x51, 0xf1, 0x1f, 0x76, 0xf6, 0x5e,
    0xa6, 0x35, 0xdd, 0x5b, 0xd3, 0xad, 0xed, 0x6d, 0x8f, 0x83, 0x1e, 0x71, 0x1d, 0x7c, 0x8d, 0xa2,
    0x17, 0x4b, 0x9b, 0x56, 0x3a, 0x2d, 0xa8, 0xbc, 0x92, 0x2e, 0xf2, 0xe6, 0x1e, 0x62, 0xcf, 0x6b,
    0xac, 0x7b, 0xf2, 0xa0, 0x03, 0x58, 0xb3, 0x21, 0xe0, 0xf2, 0x2d, 0x31, 0x32, 0x75, 0x75, 0x8f,
];
const VK_GAMMA: [u8; BN254_G2_SERIALIZED_SIZE] = [
    0x07, 0xd9, 0x3d, 0x2c, 0x62, 0x5c, 0xf3, 0xfd, 0x1d, 0xd4, 0x66, 0x7d, 0xd3, 0xdd, 0x6b, 0x6f,
    0xb8, 0x39, 0x69, 0xe3, 0xd5, 0x4e, 0x56, 0x56, 0xb6, 0xb6, 0x24, 0xb9, 0xf4, 0xc8, 0xbd, 0xfa,
    0x15, 0x3d, 0x19, 0x23, 0x82, 0xe1, 0x8a, 0x12, 0x00, 0x08, 0x12, 0xf3, 0x6d, 0xa3, 0x2d, 0xb6,
    0x0d, 0x4c, 0x45, 0xc0, 0xd8, 0xd5, 0xb8, 0x62, 0xde, 0xef, 0x02, 0x72, 0xda, 0xe9, 0x08, 0xcd,
    0x04, 0xcf, 0x07, 0x1c, 0x48, 0x9d, 0xc0, 0x6d, 0xf7, 0x9c, 0x15, 0x06, 0x1d, 0x0d, 0x11, 0x8c,
    0x6d, 0xac, 0x19, 0xbe, 0x6a, 0xeb, 0xec, 0xdc, 0x17, 0x64, 0xc0, 0x15, 0x86, 0x23, 0xd7, 0x1b,
    0x0e, 0x76, 0x00, 0x29, 0x8f, 0x7e, 0xfc, 0x1f, 0x13, 0xde, 0xb2, 0x95, 0x62, 0x2b, 0xc2, 0x43,
    0xa8, 0xc6, 0x3d, 0xca, 0xd3, 0x06, 0x51, 0xf9, 0x9b, 0xae, 0x4e, 0xe7, 0x46, 0xa7, 0x39, 0xae,
];
const VK_DELTA: [u8; BN254_G2_SERIALIZED_SIZE] = [
    0x02, 0x1e, 0x17, 0x33, 0x38, 0xb4, 0x0d, 0x29, 0x61, 0x6b, 0x26, 0xa8, 0x6d, 0x8c, 0xaf, 0xf0,
    0xee, 0x0f, 0x63, 0x24, 0x4a, 0xf0, 0x89, 0xf9, 0xb6, 0x9b, 0x09, 0xa5, 0x03, 0xf2, 0x77, 0xb4,
    0x0a, 0xf4, 0x25, 0xd9, 0x22, 0x1d, 0xfa, 0x9e, 0x24, 0x5a, 0xbb, 0xd8, 0x2d, 0xdc, 0x4c, 0x96,
    0xe1, 0xc4, 0x2f, 0x92, 0x25, 0x00, 0xf7, 0x6d, 0x7e, 0xb7, 0x18, 0x8e, 0xb1, 0x60, 0x36, 0xc0,
    0x2f, 0xea, 0xea, 0x1d, 0x07, 0x65, 0x7d, 0xc6, 0xe9, 0xfb, 0x68, 0x24, 0xac, 0xe4, 0x67, 0x87,
    0x6d, 0x68, 0x6e, 0x66, 0x1b, 0x1a, 0xf5, 0x18, 0x3d, 0xf5, 0x01, 0x07, 0x32, 0xef, 0xa2, 0x75,
    0x29, 0x3d, 0x2c, 0x57, 0x4b, 0xcc, 0x9d, 0xc2, 0xfe, 0x2c, 0x55, 0xc0, 0x85, 0xcb, 0x7c, 0xfd,
    0x70, 0x81, 0x61, 0x8f, 0x93, 0xe4, 0xa4, 0xe0, 0xf0, 0xad, 0x01, 0x9c, 0xcc, 0x15, 0x01, 0xdc,
];
const VK_FINGERPRINT: [u8; 32] = [
    0x15, 0xb1, 0xdb, 0x33, 0x4e, 0x8b, 0x15, 0x3d, 0x9b, 0x2f, 0x60, 0xe5, 0xc3, 0x6f, 0x24, 0xc0,
    0xdd, 0xf9, 0x48, 0x27, 0x50, 0x2a, 0xa7, 0xbf, 0x4b, 0x27, 0xb1, 0x62, 0xf0, 0xc8, 0xae, 0x15,
];
const SCALAR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

const VK_IC: [[u8; BN254_G1_SERIALIZED_SIZE]; 2] = [
    [
        0x2f, 0xb6, 0xdc, 0xeb, 0xff, 0xf9, 0xe2, 0xbd, 0xc4, 0x15, 0x02, 0xb2, 0xaa, 0x25, 0x27,
        0x07, 0xf4, 0x00, 0xc3, 0x74, 0x66, 0x01, 0x75, 0xce, 0x2a, 0x5b, 0x7a, 0xee, 0x44, 0xcc,
        0x70, 0xca, 0x28, 0x73, 0xa5, 0x4c, 0x8f, 0xee, 0x4d, 0x19, 0xba, 0x40, 0xab, 0xe8, 0x1f,
        0x4f, 0x2a, 0x14, 0x43, 0xbe, 0xf9, 0x8b, 0x3d, 0x74, 0xf8, 0x08, 0xa0, 0xeb, 0xb4, 0x76,
        0xf7, 0xc0, 0xa6, 0x57,
    ],
    [
        0x28, 0x19, 0x53, 0x3b, 0x9c, 0x75, 0xdf, 0xd1, 0x11, 0x00, 0xdc, 0x15, 0x6f, 0xb6, 0x92,
        0xc5, 0x66, 0x5c, 0x49, 0x55, 0x26, 0x16, 0x84, 0xcd, 0x4b, 0xea, 0xc8, 0xa3, 0x9b, 0x27,
        0x48, 0x6a, 0x23, 0xeb, 0x0e, 0x47, 0xc4, 0x83, 0x44, 0x10, 0x98, 0x27, 0xb8, 0x89, 0xd4,
        0x9a, 0xb3, 0x31, 0xe8, 0xa4, 0x31, 0x2c, 0x94, 0x6a, 0x4d, 0x70, 0x28, 0x0a, 0x18, 0x0d,
        0x72, 0x6a, 0x4c, 0x30,
    ],
];

// AUTO-GENERATED TEST VECTOR BYTES (uncompressed). DO NOT EDIT.
#[cfg(test)]
const TEST_PROOF_A: [u8; BN254_G1_SERIALIZED_SIZE] = [
    0x14, 0xdb, 0xfc, 0xee, 0x9b, 0x27, 0x4f, 0xab, 0x39, 0x37, 0x28, 0x51, 0x2d, 0x5d, 0xeb, 0xfe,
    0xdb, 0xec, 0x44, 0x27, 0x0c, 0xb0, 0x07, 0x4c, 0x38, 0x8a, 0x4c, 0xeb, 0x64, 0x4d, 0xf9, 0x4a,
    0x1c, 0xf0, 0x97, 0x84, 0x33, 0x52, 0xbb, 0xc1, 0x3f, 0x50, 0xfd, 0x62, 0x8f, 0x93, 0xaf, 0x78,
    0x81, 0x7e, 0xb4, 0xe4, 0xdc, 0xa4, 0x12, 0xeb, 0xe4, 0x94, 0x87, 0xc1, 0x17, 0xa8, 0xb4, 0x9a,
];
#[cfg(test)]
const TEST_PROOF_B: [u8; BN254_G2_SERIALIZED_SIZE] = [
    0x10, 0xc3, 0x94, 0xe0, 0x07, 0x5a, 0x84, 0xe7, 0x24, 0x4a, 0xe6, 0x0b, 0xb2, 0xca, 0xde, 0xf4,
    0x59, 0x8c, 0x7c, 0x48, 0xbc, 0x57, 0xdc, 0x52, 0x32, 0xaa, 0x77, 0x9b, 0xf7, 0xa5, 0x19, 0xeb,
    0x16, 0x97, 0xaa, 0x88, 0x6b, 0x04, 0xfd, 0xc4, 0xa9, 0x22, 0x06, 0x30, 0x27, 0x76, 0x50, 0x69,
    0xce, 0x8b, 0x14, 0xf3, 0xcb, 0x57, 0x5c, 0x52, 0xbf, 0x80, 0xd2, 0x7f, 0xc8, 0xc5, 0x98, 0x9f,
    0x0a, 0x67, 0x8a, 0x22, 0xda, 0x90, 0x01, 0x2a, 0xdd, 0x0a, 0x37, 0x97, 0x68, 0x9f, 0xe5, 0x00,
    0x5c, 0xb7, 0xa6, 0xc9, 0x6b, 0xdb, 0xde, 0x64, 0xf3, 0x9f, 0x86, 0x4a, 0x5b, 0xcc, 0x17, 0x88,
    0x1c, 0x33, 0x8d, 0x39, 0xcd, 0xfc, 0x44, 0xb3, 0x0c, 0xc4, 0x3b, 0xfb, 0xba, 0xbf, 0xe6, 0xe6,
    0x03, 0x1d, 0xa7, 0xc8, 0xda, 0x3e, 0x71, 0xe7, 0xaf, 0xc9, 0xa1, 0x5a, 0x3c, 0xbf, 0x5e, 0x43,
];
#[cfg(test)]
const TEST_PROOF_C: [u8; BN254_G1_SERIALIZED_SIZE] = [
    0x08, 0xf2, 0xe5, 0xf5, 0x72, 0xf8, 0x98, 0x06, 0x27, 0xd4, 0x75, 0x54, 0x7d, 0x8f, 0x29, 0xd9,
    0x26, 0x30, 0x1b, 0x0f, 0x7e, 0x69, 0xbb, 0x90, 0xc9, 0xef, 0x79, 0x5e, 0xee, 0x46, 0x25, 0x57,
    0x14, 0x08, 0x8f, 0x65, 0x97, 0x79, 0xde, 0x2d, 0xbb, 0x8a, 0x35, 0xe1, 0x04, 0xd8, 0xb8, 0x84,
    0x96, 0x05, 0xf0, 0x02, 0xff, 0x10, 0x6a, 0xc9, 0x91, 0x63, 0x91, 0x20, 0x95, 0x19, 0xb8, 0xd6,
];
#[cfg(test)]
const TEST_PUBLIC_INPUTS: [[u8; 32]; 1] = [[
    0x02, 0x17, 0x86, 0x71, 0xed, 0x0b, 0xa1, 0x6a, 0x21, 0x15, 0x0f, 0xd3, 0x4a, 0x25, 0x2d, 0x56,
    0x99, 0xc2, 0x26, 0xc2, 0x8f, 0x6e, 0x18, 0xaf, 0x55, 0x04, 0x01, 0x0a, 0x8c, 0x24, 0x15, 0x26,
]];

fn vk(env: &Env) -> VerificationKey {
    let alpha = Bn254G1Affine::from_array(env, &VK_ALPHA);
    let beta = Bn254G2Affine::from_array(env, &VK_BETA);
    let gamma = Bn254G2Affine::from_array(env, &VK_GAMMA);
    let delta = Bn254G2Affine::from_array(env, &VK_DELTA);

    let mut ic = Vec::new(env);
    for p in VK_IC.iter() {
        ic.push_back(Bn254G1Affine::from_array(env, p));
    }

    VerificationKey {
        alpha,
        beta,
        gamma,
        delta,
        ic,
    }
}

#[contract]
pub struct Verifier;

fn canonical_fr(_env: &Env, bytes: BytesN<32>) -> Result<Bn254Fr, Groth16Error> {
    if bytes.to_array() >= SCALAR_MODULUS_BE {
        return Err(Groth16Error::NonCanonicalPublicInput);
    }
    Ok(Bn254Fr::from_bytes(bytes))
}

#[contractimpl]
impl Verifier {
    pub fn vk_fingerprint(env: Env) -> BytesN<32> {
        BytesN::from_array(&env, &VK_FINGERPRINT)
    }

    pub fn verify_proof_strict(
        env: Env,
        proof: Proof,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<bool, Groth16Error> {
        let mut pub_signals = Vec::new(&env);
        for bytes in public_inputs.iter() {
            pub_signals.push_back(canonical_fr(&env, bytes)?);
        }
        Self::verify_proof(env, proof, pub_signals)
    }

    pub fn verify_proof(
        env: Env,
        proof: Proof,
        pub_signals: Vec<Bn254Fr>,
    ) -> Result<bool, Groth16Error> {
        let bn = env.crypto().bn254();
        let vk = vk(&env);

        if pub_signals.len() + 1 != vk.ic.len() {
            return Err(Groth16Error::MalformedVerifyingKey);
        }

        let mut vk_x = vk.ic.get(0).unwrap();
        for (s, v) in pub_signals.iter().zip(vk.ic.iter().skip(1)) {
            let prod = bn.g1_mul(&v, &s);
            vk_x = bn.g1_add(&vk_x, &prod);
        }

        let neg_a = -proof.a;
        let vp1 = soroban_sdk::vec![&env, neg_a, vk.alpha, vk_x, proof.c];
        let vp2 = soroban_sdk::vec![&env, proof.b, vk.beta, vk.gamma, vk.delta];

        Ok(bn.pairing_check(vp1, vp2))
    }
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum GatekeeperError {
    InvalidProof = 100,
    Replay = 101,
    WrongDomain = 102,
    WrongFingerprint = 103,
}

#[derive(Clone)]
#[contracttype]
enum DataKey {
    Used(BytesN<32>),
}

const DOMAIN: &[u8] = b"gatekeeper/v1";
const CHAIN: &[u8] = b"soroban-mainnet";
const OPERATION: &[u8] = b"mint";
const NULLIFIER_TTL_THRESHOLD: u32 = 120_960;
const NULLIFIER_TTL_EXTEND_TO: u32 = 241_920;
const CONTEXT_MASK: [u8; 31] = [
    0x8c, 0x50, 0x4f, 0x4a, 0x76, 0x4e, 0x51, 0xc3, 0x01, 0xf6, 0xcb, 0x7e, 0xfa, 0xda, 0x17, 0x84,
    0xd4, 0x98, 0x5f, 0xbd, 0x24, 0x18, 0x71, 0x63, 0x84, 0x9d, 0x3a, 0x69, 0x7a, 0x3d, 0xc5,
];

#[contract]
pub struct Gatekeeper;

#[contractimpl]
impl Gatekeeper {
    pub fn authorize(
        env: Env,
        proof: Proof,
        domain: Bytes,
        nullifier: BytesN<32>,
        expected_vk_fingerprint: BytesN<32>,
    ) -> Result<(), GatekeeperError> {
        if domain != Bytes::from_slice(&env, DOMAIN) {
            return Err(GatekeeperError::WrongDomain);
        }
        if expected_vk_fingerprint != Verifier::vk_fingerprint(env.clone()) {
            return Err(GatekeeperError::WrongFingerprint);
        }

        let key = DataKey::Used(nullifier.clone());
        if env.storage().persistent().has(&key) {
            return Err(GatekeeperError::Replay);
        }

        let public_input = context_public_input(&env, &domain, &nullifier);
        let inputs = soroban_sdk::vec![&env, public_input];
        let verified = Verifier::verify_proof_strict(env.clone(), proof, inputs)
            .map_err(|_| GatekeeperError::InvalidProof)?;
        if !verified {
            return Err(GatekeeperError::InvalidProof);
        }

        let storage = env.storage().persistent();
        storage.set(&key, &true);
        storage.extend_ttl(&key, NULLIFIER_TTL_THRESHOLD, NULLIFIER_TTL_EXTEND_TO);
        Ok(())
    }

    pub fn is_used(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage().persistent().has(&DataKey::Used(nullifier))
    }
}

fn context_public_input(env: &Env, domain: &Bytes, nullifier: &BytesN<32>) -> BytesN<32> {
    let mut encoded = Bytes::new(env);
    append_field(
        &mut encoded,
        &Bytes::from_slice(env, b"groth16-gatekeeper-v1"),
    );
    append_field(&mut encoded, domain);
    append_field(&mut encoded, &Bytes::from_array(env, &nullifier.to_array()));
    append_field(&mut encoded, &Bytes::from_array(env, &VK_FINGERPRINT));
    append_field(
        &mut encoded,
        &env.current_contract_address().to_string().to_bytes(),
    );
    append_field(&mut encoded, &Bytes::from_slice(env, CHAIN));
    append_field(&mut encoded, &Bytes::from_slice(env, OPERATION));

    let digest = env.crypto().sha256(&encoded).to_array();
    let mut canonical = [0u8; 32];
    canonical[0] = 2;
    for i in 1..32 {
        canonical[i] = digest[i] ^ CONTEXT_MASK[i - 1];
    }
    BytesN::from_array(env, &canonical)
}

fn append_field(encoded: &mut Bytes, field: &Bytes) {
    encoded.push_back(field.len() as u8);
    encoded.append(field);
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::U256;

    #[test]
    fn rejects_wrong_public_input_count() {
        let env = Env::default();
        let proof = Proof {
            a: Bn254G1Affine::from_array(&env, &VK_ALPHA),
            b: Bn254G2Affine::from_array(&env, &VK_BETA),
            c: Bn254G1Affine::from_array(&env, &VK_ALPHA),
        };
        let mut pub_signals = Vec::new(&env);
        for _ in 0..VK_IC.len() {
            pub_signals.push_back(Bn254Fr::from_bytes(BytesN::from_array(&env, &[0u8; 32])));
        }

        assert_eq!(
            Verifier::verify_proof(env, proof, pub_signals),
            Err(Groth16Error::MalformedVerifyingKey)
        );
    }

    #[test]
    fn canonical_public_input_boundaries() {
        let env = Env::default();
        let mut max = SCALAR_MODULUS_BE;
        max[31] -= 1;
        assert!(canonical_fr(&env, BytesN::from_array(&env, &max)).is_ok());
        assert!(matches!(
            canonical_fr(&env, BytesN::from_array(&env, &SCALAR_MODULUS_BE)),
            Err(Groth16Error::NonCanonicalPublicInput)
        ));
    }

    #[test]
    fn sdk_modulo_reduction_requires_canonical_storage_keys() {
        let env = Env::default();
        let modulus = U256::from_be_bytes(&env, &Bytes::from_array(&env, &SCALAR_MODULUS_BE));
        let x = U256::from_u32(&env, 5);
        let x_plus_modulus = modulus.add(&x);
        let canonical_x = Bn254Fr::from_u256(x.clone());
        let reduced_x = Bn254Fr::from_u256(x_plus_modulus.clone());

        assert_eq!(canonical_x, reduced_x);
        assert_eq!(canonical_x.to_u256(), x);
        assert_eq!(reduced_x.to_u256(), x);

        let canonical_contract = address(
            &env,
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADFP5BVL",
        );
        let raw_contract = address(
            &env,
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC7O6C3N",
        );
        env.register_at(&canonical_contract, Gatekeeper, ());
        env.register_at(&raw_contract, Gatekeeper, ());

        env.as_contract(&canonical_contract, || {
            env.storage()
                .persistent()
                .set(&canonical_x.to_u256(), &true);
            assert!(env.storage().persistent().has(&reduced_x.to_u256()));
        });
        env.as_contract(&raw_contract, || {
            env.storage().persistent().set(&x, &true);
            assert!(!env.storage().persistent().has(&x_plus_modulus));
        });
    }

    #[test]
    fn verifies_embedded_test_vectors() {
        let env = Env::default();
        let proof = Proof {
            a: Bn254G1Affine::from_array(&env, &TEST_PROOF_A),
            b: Bn254G2Affine::from_array(&env, &TEST_PROOF_B),
            c: Bn254G1Affine::from_array(&env, &TEST_PROOF_C),
        };
        let mut pub_signals = Vec::new(&env);
        for input in TEST_PUBLIC_INPUTS.iter() {
            pub_signals.push_back(Bn254Fr::from_bytes(BytesN::from_array(&env, input)));
        }

        assert_eq!(Verifier::verify_proof(env, proof, pub_signals), Ok(true));
    }

    fn proof(env: &Env) -> Proof {
        Proof {
            a: Bn254G1Affine::from_array(env, &TEST_PROOF_A),
            b: Bn254G2Affine::from_array(env, &TEST_PROOF_B),
            c: Bn254G1Affine::from_array(env, &TEST_PROOF_C),
        }
    }

    fn address(env: &Env, encoded: &str) -> soroban_sdk::Address {
        soroban_sdk::Address::from_string(&soroban_sdk::String::from_str(env, encoded))
    }

    fn domain(env: &Env) -> Bytes {
        Bytes::from_slice(env, DOMAIN)
    }

    fn nullifier(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &[0x11; 32])
    }

    #[test]
    fn first_use_with_valid_proof_succeeds_and_replay_is_rejected() {
        let env = Env::default();
        let contract = address(
            &env,
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADFP5BVL",
        );
        env.register_at(&contract, Gatekeeper, ());
        let fingerprint = Verifier::vk_fingerprint(env.clone());
        let n = nullifier(&env);

        let first = env.as_contract(&contract, || {
            Gatekeeper::authorize(
                env.clone(),
                proof(&env),
                domain(&env),
                n.clone(),
                fingerprint.clone(),
            )
        });
        assert_eq!(first, Ok(()));
        assert!(env.as_contract(&contract, || Gatekeeper::is_used(env.clone(), n.clone())));

        let replay = env.as_contract(&contract, || {
            Gatekeeper::authorize(
                env.clone(),
                proof(&env),
                domain(&env),
                n.clone(),
                fingerprint.clone(),
            )
        });
        assert_eq!(replay, Err(GatekeeperError::Replay));
    }

    #[test]
    fn another_domain_address_and_fingerprint_cannot_reuse_proof() {
        let env = Env::default();
        let expected = address(
            &env,
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADFP5BVL",
        );
        let other = address(
            &env,
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC7O6C3N",
        );
        env.register_at(&expected, Gatekeeper, ());
        env.register_at(&other, Gatekeeper, ());
        let fingerprint = Verifier::vk_fingerprint(env.clone());

        let wrong_domain = env.as_contract(&expected, || {
            Gatekeeper::authorize(
                env.clone(),
                proof(&env),
                Bytes::from_slice(&env, b"other-domain"),
                nullifier(&env),
                fingerprint.clone(),
            )
        });
        assert_eq!(wrong_domain, Err(GatekeeperError::WrongDomain));

        let wrong_address = env.as_contract(&other, || {
            Gatekeeper::authorize(
                env.clone(),
                proof(&env),
                domain(&env),
                nullifier(&env),
                fingerprint.clone(),
            )
        });
        assert_eq!(wrong_address, Err(GatekeeperError::InvalidProof));

        let wrong_fingerprint = env.as_contract(&expected, || {
            Gatekeeper::authorize(
                env.clone(),
                proof(&env),
                domain(&env),
                nullifier(&env),
                BytesN::from_array(&env, &[0u8; 32]),
            )
        });
        assert_eq!(wrong_fingerprint, Err(GatekeeperError::WrongFingerprint));
    }

    #[test]
    fn invalid_proof_is_rejected_before_nullifier_is_stored() {
        let env = Env::default();
        let contract = address(
            &env,
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADFP5BVL",
        );
        env.register_at(&contract, Gatekeeper, ());
        let invalid = Proof {
            a: Bn254G1Affine::from_array(&env, &VK_ALPHA),
            b: Bn254G2Affine::from_array(&env, &VK_BETA),
            c: Bn254G1Affine::from_array(&env, &VK_ALPHA),
        };
        let n = nullifier(&env);
        let result = env.as_contract(&contract, || {
            Gatekeeper::authorize(
                env.clone(),
                invalid,
                domain(&env),
                n.clone(),
                Verifier::vk_fingerprint(env.clone()),
            )
        });
        assert_eq!(result, Err(GatekeeperError::InvalidProof));
        assert!(!env.as_contract(&contract, || Gatekeeper::is_used(env.clone(), n)));
    }
}
