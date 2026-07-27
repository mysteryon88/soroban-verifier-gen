# Soroban Groth16 Verifier Generator

[![dependency status](https://deps.rs/repo/github/mysteryon88/soroban-verifier-gen/status.svg)](https://deps.rs/repo/github/mysteryon88/soroban-verifier-gen)

**Soroban Groth16 Verifier Generator** is a CLI tool and Rust library for generating **Groth16** Soroban smart contracts.

It supports **BN254** and **BLS12-381** verification artifacts from **snarkjs**, **Gnark**, **SP1**, and **Arkworks**. Supported inputs include JSON, native Gnark binary files, SP1 Groth16 wrapper proofs, Arkworks JSON/hex files, and compact Arkworks bundles. The curve and input format are auto-detected.

When proof data is supplied, the tool verifies it locally and generates Rust tests with the contract. VK-only generation is also supported.

## Installation

```bash
cargo install soroban-verifier-gen

# Help
soroban-verifier-gen --help
```

## Import as a library

```bash
cargo add soroban-verifier-gen-core
```

```rust
use soroban_verifier_gen_core::{
    generate_verifier_contract_to_dir, Curve, GenerateOptions,
};
```

Most users only need the CLI. Use the core crate when embedding verifier generation into another Rust tool.

## Usage CLI

```sh
# From snarkjs-compatible verification_key.json:
soroban-verifier-gen --vk ./verification_key.json --out ./generated/verifier

# Include proof data for local verification and generated Rust tests:
soroban-verifier-gen --vk ./verification_key.json --proof ./proof.json --public ./public.json --out ./generated/verifier

# From native Gnark JSON or binary artifacts:
soroban-verifier-gen --vk ./verification_key_gnark.json --proof ./proof_gnark.json --public ./public.json --out ./generated/gnark_verifier
soroban-verifier-gen --vk ./verification_key.bin --proof ./proof.bin --public ./public.json --out ./generated/gnark_verifier

# From an SP1 Groth16 wrapper proof:
soroban-verifier-gen --vk ./groth16_vk.bin --proof ./sp1_proof.bin --out ./generated/sp1_verifier

# From a compact Arkworks bundle:
soroban-verifier-gen --bundle ./groth16_artifacts.json --out ./generated/arkworks_verifier

# Customize the generated contract:
soroban-verifier-gen --vk ./verification_key.json --out ./generated/verifier --crate-name verifier --contract-name Groth16Verifier

# Generate a contract for Soroban SDK 26 instead of SDK 27:
soroban-verifier-gen --vk ./verification_key.json --out ./generated/verifier --soroban-sdk-version v26
```

`--out` defaults to `verifier`, `--crate-name` defaults to `verifier`, `--contract-name` defaults to `Groth16Verifier`, and `--soroban-sdk-version` defaults to `v27`.

## License

MIT.

## References

- [Soroban smart contract documentation](https://developers.stellar.org/docs/build/smart-contracts)
- [Examples](./examples/)
- [gnark-to-snarkjs](https://github.com/mysteryon88/gnark-to-snarkjs)
- [ark-snarkjs](https://github.com/mysteryon88/ark-snarkjs)
- [Circom](https://docs.circom.io/)
- [Noname](https://github.com/zksecurity/noname)
- [Gnark](https://github.com/Consensys/gnark)
- [SP1](https://github.com/succinctlabs/sp1)
- [Arkworks](https://github.com/arkworks-rs)
