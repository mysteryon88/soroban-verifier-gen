use anyhow::Result;
use clap::Parser;
use soroban_verifier_gen::{GenerateOptions, generate_verifier_contract_to_dir};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "soroban-verifier-gen")]
#[command(about = "Generate Soroban smart contracts for Groth16 ZK proof verification")]
struct Args {
    /// Path to verification key JSON (circom/snarkjs format)
    #[arg(short, long)]
    vk: PathBuf,

    /// Output directory for the generated contract crate
    #[arg(short, long, default_value = "verifier")]
    out: PathBuf,

    /// Generated crate name (Cargo.toml [package].name)
    #[arg(long, default_value = "verifier")]
    crate_name: String,

    /// Generated contract struct name
    #[arg(long, default_value = "Groth16Verifier")]
    contract_name: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let out = args.out.clone();
    generate_verifier_contract_to_dir(GenerateOptions {
        vk_json_path: args.vk,
        out_dir: args.out,
        crate_name: args.crate_name,
        contract_name: args.contract_name,
    })?;
    println!("Verifier contract generated in {}", out.display());
    Ok(())
}
