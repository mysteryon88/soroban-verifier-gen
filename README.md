# Soroban Groth16 Verifier Generator

Generate Soroban smart contracts for Groth16 zero-knowledge proof verification.

[![dependency status](https://deps.rs/repo/github/mysteryon88/soroban-verifier-gen/status.svg)](https://deps.rs/repo/github/mysteryon88/soroban-verifier-gen)

### Features

- Supports **BLS12-381** and **BN254** elliptic curves
- Compatible with circom/snarkjs output format

### CLI

```bash
cargo install soroban-verifier-gen

# Generate BLS12-381 verifier (default)
soroban-verifier-gen --vk verification_key.json --out verifier

# Generate BN254 verifier
soroban-verifier-gen --vk verification_key_bn254.json --out verifier_bn254 --curve bn254
```

Options:

| Option            | Short | Default           | Description                                    |
| ----------------- | ----- | ----------------- | ---------------------------------------------- |
| `--vk`            | `-v`  | _(required)_      | Path to verification key JSON                  |
| `--out`           | `-o`  | `verifier`        | Output directory for the generated crate       |
| `--crate-name`    |       | `verifier`        | `[package].name` in generated Cargo.toml       |
| `--contract-name` |       | `Groth16Verifier` | Contract struct name in generated code         |
| `--curve`         | `-c`  | `bls12-381`       | Elliptic curve to use (`bls12-381` or `bn254`) |

### Library

```rust
use soroban_verifier_gen::{Curve, GenerateOptions, generate_verifier_contract_to_dir};

fn main() -> anyhow::Result<()> {
    // Generate BLS12-381 verifier
    generate_verifier_contract_to_dir(GenerateOptions {
        vk_json_path: "verification_key.json".into(),
        out_dir: "contracts/verifier".into(),
        contract_name: "MyGroth16Verifier".into(),
        crate_name: "verifier".into(),
        curve: Curve::Bls12_381,
    })?;

    // Or generate BN254 verifier
    generate_verifier_contract_to_dir(GenerateOptions {
        vk_json_path: "verification_key_bn254.json".into(),
        out_dir: "contracts/verifier_bn254".into(),
        contract_name: "MyGroth16VerifierBn254".into(),
        crate_name: "verifier_bn254".into(),
        curve: Curve::Bn254,
    })?;

    Ok(())
}
```
