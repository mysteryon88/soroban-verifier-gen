# Soroban Groth16 Verifier Generator

Generate Soroban smart contracts for Groth16 proof verification.

[![dependency status](https://deps.rs/repo/github/mysteryon88/soroban-verifier-gen/status.svg)](https://deps.rs/repo/github/mysteryon88/soroban-verifier-gen)

## Features

- Supports **BLS12-381** and **BN254**.
- Loads verification artifacts from:
  - snarkjs JSON
  - native Arkworks JSON/hex (compact `groth16_artifacts.json` and `vk`/`proof` JSON)
  - native Gnark JSON
  - native Gnark binary artifacts (`vk.WriteTo`, `proof.WriteTo`)
  - SP1 Groth16 wrapper proof artifacts
- Supports auto-detection of input format (or optional `--curve` hint).

## Usage

```bash
cd soroban-verifier-gen

# BLS12-381 from snarkjs
cargo run -p soroban-verifier-gen -- \
  --vk examples/ark-mimc/artifacts/bls12_381/verification_key.json \
  --proof examples/ark-mimc/artifacts/bls12_381/proof.json \
  --out examples/generated/ark_mimc_bls12_381_snarkjs \
  --crate-name ark-mimc-bls12_381-snarkjs \
  --contract-name ArkMimcBls12381SnarkJsVerifier

# BN254 from Arkworks bundle (native)
cargo run -p soroban-verifier-gen -- \
  --bundle examples/ark-mimc/artifacts/bn254/groth16_artifacts.json \
  --out examples/generated/ark_mimc_bn254_arkworks \
  --crate-name ark-mimc-bn254-arkworks \
  --contract-name ArkMimcBn254ArkworksVerifier

# Gnark JSON (native)
cargo run -p soroban-verifier-gen -- \
  --vk examples/gnark-native/cubic/artifacts/bn254/verification_key_gnark.json \
  --proof examples/gnark-native/cubic/artifacts/bn254/proof_gnark.json \
  --public examples/gnark-native/cubic/artifacts/bn254/public.json \
  --out examples/generated/gnark_cubic_bn254_json \
  --crate-name gnark-cubic-bn254-json \
  --contract-name GnarkCubicBn254JsonVerifier

# Gnark binary (native)
cargo run -p soroban-verifier-gen -- \
  --vk examples/gnark-native/cubic/artifacts/bn254/verification_key.bin \
  --proof examples/gnark-native/cubic/artifacts/bn254/proof.bin \
  --public examples/gnark-native/cubic/artifacts/bn254/public.json \
  --out examples/generated/gnark_cubic_bn254_bin \
  --crate-name gnark-cubic-bn254-bin \
  --contract-name GnarkCubicBn254BinVerifier

# SP1 Groth16 wrapper
cargo run -p soroban-verifier-gen -- \
  --vk examples/sp1-groth16/fibonacci/artifacts/groth16_vk_v5.bin \
  --proof examples/sp1-groth16/fibonacci/artifacts/fibonacci_proof.bin \
  --out examples/generated/sp1_fibonacci_groth16_v5 \
  --crate-name sp1-fibonacci-groth16-v5 \
  --contract-name Sp1FibonacciGroth16V5Verifier
```

## CLI

| Option            | Short | Default     | Description |
| ----------------- | ----- | ----------- | ----------- |
| `--vk`            |       | _(required)_| Path to verification key file |
| `--proof`         |       |             | Optional proof file. |
| `--public`        |       |             | Optional public-input file. |
| `--bundle`        |       |             | Arkworks compact bundle (alternative to `--vk`). |
| `--out`           | `-o`  | `verifier`  | Output directory for generated crate. |
| `--crate-name`    |       | `verifier`  | Cargo package name in generated crate. |
| `--contract-name` |       | `Groth16Verifier` | Soroban contract struct name. |
| `--curve`         | `-c`  | auto        | Optional curve hint (`bls12-381` or `bn254`). |
| `--soroban-sdk-version` | | `v27` | Generated contract SDK (`v27` or `v26`). |

Generated contracts use `soroban-sdk` 27 by default. Pass `--soroban-sdk-version v26` to generate a Soroban SDK 26 contract crate.

## Library

```rust
use soroban_verifier_gen_core::{
    GenerateOptions,
    Curve,
    generate_verifier_contract_to_dir,
};

fn main() -> anyhow::Result<()> {
    generate_verifier_contract_to_dir(GenerateOptions {
        vk_json_path: "examples/MulCircuit/artifacts/bls12_381/verification_key.json".into(),
        out_dir: "contracts/verifier".into(),
        crate_name: "verifier".into(),
        contract_name: "Groth16Verifier".into(),
        curve: Curve::Bls12_381,
    })
}
```

For examples and prebuilt fixtures, see `examples/`.

## Security considerations

Generated verifiers are stateless: a valid Groth16 proof is not a one-time authorization. Applications that authorize a state change must include a domain-separated nullifier in the circuit public inputs, reject a used nullifier, and persist it only after proof verification succeeds. Bind the statement to the contract address, network identifier, operation, and generated VK fingerprint. See [the stateful gatekeeper example](./examples/stateful-gatekeeper/).

Public inputs received from outside the contract must use `verify_proof_strict(Vec<BytesN<32>>)`. It rejects non-canonical field encodings (`x >= r`) before the Soroban SDK constructs an `Fr`. The typed `Bn254Fr`/`Bls12381Fr` constructors reduce `U256` modulo `r`, so using raw `U256` values as replay-storage keys is unsafe unless they have first been canonicalized.

The generated `verifier-manifest.json` and `vk_fingerprint()` accessor identify the exact canonical VK embedded in the contract. The SHA-256 fingerprint provides integrity and circuit/VK binding only; it does not establish authenticity, prove that a trusted setup ceremony was honest, or eliminate toxic waste. Obtain the expected fingerprint through an authenticated release process and review generated code before production deployment.

Only BN254 and BLS12-381 are supported. Input artifacts are checked for canonical coordinates, on-curve and subgroup membership, identity points, public-input count, and supported encodings before files are written.

## Migration notes

- New generated contracts default to `soroban-sdk = 27.0.1`; SDK 26 remains available through `--soroban-sdk-version v26`.
- Integrations accepting externally encoded public inputs should migrate from the modulo-reducing typed verifier call to `verify_proof_strict`.
- Generated output now includes `verifier-manifest.json`, `VK_FINGERPRINT`, and `vk_fingerprint()`.
