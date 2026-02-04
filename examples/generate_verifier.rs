use soroban_verifier_gen::{Curve, GenerateOptions, generate_verifier_contract_to_dir};

fn main() -> anyhow::Result<()> {
    // Generate BLS12-381 verifier (default)
    generate_verifier_contract_to_dir(GenerateOptions {
        vk_json_path: "examples/data/bls12-381/verification_key.json".into(),
        out_dir: "my_verifier_bls12-381".into(),
        contract_name: "Groth16Verifier".into(),
        crate_name: "my_verifier_bls12-381".into(),
        curve: Curve::Bls12_381,
    })?;

    println!("BLS12-381 verifier generated in my_verifier/");

    // Uncomment to also generate BN254 verifier (if you have bn254 verification key)
    generate_verifier_contract_to_dir(GenerateOptions {
        vk_json_path: "examples/data/bn254/verification_key.json".into(),
        out_dir: "my_verifier_bn254".into(),
        contract_name: "Groth16VerifierBn254".into(),
        crate_name: "my_verifier_bn254".into(),
        curve: Curve::Bn254,
    })?;

    Ok(())
}
