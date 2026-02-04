use anyhow::Result;
use clap::{Parser, ValueEnum};
use soroban_verifier_gen::{Curve, GenerateOptions, generate_verifier_contract_to_dir};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CurveArg {
    /// BLS12-381 curve
    Bls12_381,
    /// BN254 curve (also known as BN128 or alt_bn128)
    Bn254,
}

impl From<CurveArg> for Curve {
    fn from(arg: CurveArg) -> Self {
        match arg {
            CurveArg::Bls12_381 => Curve::Bls12_381,
            CurveArg::Bn254 => Curve::Bn254,
        }
    }
}

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

    /// Elliptic curve to use (bls12-381 or bn254)
    #[arg(short, long, value_enum, default_value = "bls12-381")]
    curve: CurveArg,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let out = args.out.clone();
    let curve = args.curve.into();
    generate_verifier_contract_to_dir(GenerateOptions {
        vk_json_path: args.vk,
        out_dir: args.out,
        crate_name: args.crate_name,
        contract_name: args.contract_name,
        curve,
    })?;
    println!("Verifier contract generated in {} (curve: {:?})", out.display(), curve);
    Ok(())
}
