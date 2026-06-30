use clap::{Parser, ValueEnum};
use soroban_verifier_gen_core::{
    GenerateInputsOptions, SorobanSdkVersion, generate_verifier_contract_from_inputs_with_sdk,
    load_verifier_inputs,
};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CurveArg {
    /// BLS12-381 curve
    Bls12_381,
    /// BN254 curve (also known as BN128 or alt_bn128)
    Bn254,
}

impl CurveArg {
    fn as_curve_hint(self) -> &'static str {
        match self {
            Self::Bls12_381 => "bls12381",
            Self::Bn254 => "bn254",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SorobanSdkArg {
    /// Generate a contract crate that depends on soroban-sdk 26.x
    V26,
    /// Generate a contract crate that depends on soroban-sdk 27.x
    V27,
}

impl From<SorobanSdkArg> for SorobanSdkVersion {
    fn from(value: SorobanSdkArg) -> Self {
        match value {
            SorobanSdkArg::V26 => SorobanSdkVersion::V26,
            SorobanSdkArg::V27 => SorobanSdkVersion::V27,
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "soroban-verifier-gen")]
#[command(
    about = "Generate Soroban smart contracts for Groth16 zero-knowledge proof verification",
    version
)]
struct Args {
    /// Path to verification key (snarkjs, arkworks JSON/hex, native gnark JSON, gnark binary or SP1 wrapper)
    #[arg(long)]
    vk: Option<PathBuf>,

    /// Path to proof (optional for VK-only mode)
    #[arg(long)]
    proof: Option<PathBuf>,

    /// Public inputs JSON (required for some artifact formats)
    #[arg(long)]
    public: Option<PathBuf>,

    /// Output directory for generated verifier crate
    #[arg(long, short, default_value = "verifier")]
    out: PathBuf,

    /// Generated crate name (Cargo.toml [package].name)
    #[arg(long, default_value = "verifier")]
    crate_name: String,

    /// Generated contract struct name
    #[arg(long, default_value = "Groth16Verifier")]
    contract_name: String,

    /// Hint to speed/validate curve detection
    #[arg(short, long, value_enum)]
    curve: Option<CurveArg>,

    /// Path to Arkworks compact bundle instead of separate VK/proof files
    #[arg(long)]
    bundle: Option<PathBuf>,

    /// Soroban SDK version for the generated contract crate
    #[arg(long, value_enum, default_value_t = SorobanSdkArg::V27)]
    soroban_sdk_version: SorobanSdkArg,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let inputs = load_verifier_inputs(
        args.vk.as_deref(),
        args.proof.as_deref(),
        args.public.as_deref(),
        args.bundle.as_deref(),
        args.curve.map(|curve| curve.as_curve_hint()),
    )?;

    let out = args.out.clone();
    generate_verifier_contract_from_inputs_with_sdk(
        GenerateInputsOptions {
            inputs,
            out_dir: out.clone(),
            crate_name: args.crate_name,
            contract_name: args.contract_name,
        },
        args.soroban_sdk_version.into(),
    )?;

    println!("Verifier contract generated in {}", out.display());
    Ok(())
}
