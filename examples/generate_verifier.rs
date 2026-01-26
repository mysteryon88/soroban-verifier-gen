use soroban_verifier_gen::{GenerateOptions, generate_verifier_contract_to_dir};

fn main() -> anyhow::Result<()> {
    generate_verifier_contract_to_dir(GenerateOptions {
        vk_json_path: "examples/data/verification_key.json".into(),
        out_dir: "my_verifier".into(),
        contract_name: "MyGroth16Verifier".into(),
        crate_name: "my_verifier".into(),
    })?;
    Ok(())
}
