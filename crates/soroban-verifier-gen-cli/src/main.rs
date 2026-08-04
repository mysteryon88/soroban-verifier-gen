use anyhow::{Context, bail};
use clap::{Parser, ValueEnum};
use soroban_verifier_gen_core::{
    GenerateInputsOptions, SorobanSdkVersion, curves::create_adapter,
    generate_verifier_contract_from_inputs_with_sdk, load_verifier_inputs,
    validate_generated_names, verifier::local_verify,
};
use std::path::PathBuf;
use std::process::Command;

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
    #[arg(long, short)]
    out: PathBuf,

    /// Generated crate name (`Cargo.toml` package name)
    #[arg(long, default_value = "verifier")]
    crate_name: String,

    /// Generated contract struct name
    #[arg(long, default_value = "Groth16Verifier")]
    contract_name: String,

    /// Path to Arkworks compact bundle instead of separate VK/proof files
    #[arg(long)]
    bundle: Option<PathBuf>,

    /// Soroban SDK version for the generated contract crate
    #[arg(long, value_enum, default_value_t = SorobanSdkArg::V27)]
    soroban_sdk_version: SorobanSdkArg,

    /// Replace an existing output directory
    #[arg(long)]
    force: bool,

    /// Skip local verification when proof and public inputs are present
    #[arg(long)]
    skip_local_verify: bool,

    /// Run `cargo test` in the generated contract crate
    #[arg(long)]
    run_soroban_test: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    validate_generated_names(&args.crate_name, &args.contract_name)?;

    let inputs = load_verifier_inputs(
        args.vk.as_deref(),
        args.proof.as_deref(),
        args.public.as_deref(),
        args.bundle.as_deref(),
        None,
    )?;

    if !args.skip_local_verify && inputs.has_test_vectors() {
        let adapter = create_adapter(inputs.curve.canonical_name())?;
        if !local_verify(adapter.as_ref(), &inputs)? {
            bail!("local proof verification returned false");
        }
    }

    let out = args.out.clone();
    generate_verifier_contract_from_inputs_with_sdk(
        GenerateInputsOptions {
            inputs,
            out_dir: out.clone(),
            crate_name: args.crate_name,
            contract_name: args.contract_name,
            force: args.force,
        },
        args.soroban_sdk_version.into(),
    )?;

    if args.run_soroban_test {
        run_soroban_test(&out)?;
    }

    println!("Verifier contract generated in {}", out.display());
    Ok(())
}

fn run_soroban_test(out_dir: &std::path::Path) -> anyhow::Result<()> {
    let manifest = out_dir.join("Cargo.toml");
    let output = Command::new("cargo")
        .arg("test")
        .arg("--manifest-path")
        .arg(&manifest)
        .output()
        .with_context(|| format!("failed to run cargo test for {}", out_dir.display()))?;
    if !output.status.success() {
        bail!(
            "generated Soroban contract tests failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
