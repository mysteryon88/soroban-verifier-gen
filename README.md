# Soroban Groth16 Verifier Generator

Generate Soroban smart contracts for Groth16 zero-knowledge proof verification.

[![dependency status](https://deps.rs/repo/github/mysteryon88/soroban-verifier-gen/status.svg)](https://deps.rs/repo/github/mysteryon88/soroban-verifier-gen)

### Input format

Verification key JSON in circom/snarkjs format.

### CLI

```bash
cargo install soroban-verifier-gen
soroban-verifier-gen --vk verification_key.json --out verifier
```

Options:

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--vk` | `-v` | *(required)* | Path to verification key JSON |
| `--out` | `-o` | `verifier` | Output directory for the generated crate |
| `--crate-name` | | `verifier` | `[package].name` in generated Cargo.toml |
| `--contract-name` | | `Groth16Verifier` | Contract struct name in generated code |

### Library

```rust
use soroban_verifier_gen::{GenerateOptions, generate_verifier_contract_to_dir};

fn main() -> anyhow::Result<()> {
    generate_verifier_contract_to_dir(GenerateOptions {
        vk_json_path: "verification_key.json".into(),
        out_dir: "contracts/verifier".into(),
        contract_name: "MyGroth16Verifier".into(),
        crate_name: "verifier".into(),
    })?;
    Ok(())
}
```
