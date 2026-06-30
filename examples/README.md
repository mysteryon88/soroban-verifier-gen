# soroban-verifier-gen examples

This directory uses separate fixture projects plus generated contracts for all supported input formats:

- `ark-mimc` — Arkworks/BN254 + BLS12-381 artifacts and bundled files
- `MulCircuit` — SnarkJS/BLS12-381 artifacts
- `gnark-native` — Gnark JSON and native binary artifacts
- `sp1-groth16` — SP1 Groth16 wrapper artifacts

Generated Soroban verifier contracts are placed under `examples/generated`.

## Generate all formats via `soroban-verifier-gen`

Run these commands from repository root:

They generate `soroban-sdk` 27 contracts by default. Add `--soroban-sdk-version v26` to any command to target SDK 26.

```sh
cargo run -p soroban-verifier-gen -- \
  --vk examples/ark-mimc/artifacts/bls12_381/verification_key.json \
  --proof examples/ark-mimc/artifacts/bls12_381/proof.json \
  --out examples/generated/ark_mimc_bls12_381_snarkjs \
  --crate-name ark-mimc-bls12_381-snarkjs \
  --contract-name ArkMimcBls12381SnarkJsVerifier

cargo run -p soroban-verifier-gen -- \
  --vk examples/ark-mimc/artifacts/bn254/verification_key.json \
  --proof examples/ark-mimc/artifacts/bn254/proof.json \
  --out examples/generated/ark_mimc_bn254_snarkjs \
  --crate-name ark-mimc-bn254-snarkjs \
  --contract-name ArkMimcBn254SnarkJsVerifier

cargo run -p soroban-verifier-gen -- \
  --bundle examples/ark-mimc/artifacts/bls12_381/groth16_artifacts.json \
  --out examples/generated/ark_mimc_bls12_381_arkworks \
  --crate-name ark-mimc-bls12_381-arkworks \
  --contract-name ArkMimcBls12381ArkworksVerifier

cargo run -p soroban-verifier-gen -- \
  --bundle examples/ark-mimc/artifacts/bn254/groth16_artifacts.json \
  --out examples/generated/ark_mimc_bn254_arkworks \
  --crate-name ark-mimc-bn254-arkworks \
  --contract-name ArkMimcBn254ArkworksVerifier

cargo run -p soroban-verifier-gen -- \
  --vk examples/MulCircuit/artifacts/bls12_381/verification_key.json \
  --proof examples/MulCircuit/artifacts/bls12_381/proof.json \
  --public examples/MulCircuit/artifacts/bls12_381/public.json \
  --out examples/generated/mul_circuit_bls12381_snarkjs \
  --crate-name mul-circuit-bls12381-snarkjs \
  --contract-name MulCircuitBls12381SnarkJsVerifier

cargo run -p soroban-verifier-gen -- \
  --vk examples/gnark-native/cubic/artifacts/bls12381/verification_key_gnark.json \
  --proof examples/gnark-native/cubic/artifacts/bls12381/proof_gnark.json \
  --public examples/gnark-native/cubic/artifacts/bls12381/public.json \
  --out examples/generated/gnark_cubic_bls12_381_json \
  --crate-name gnark-cubic-bls12_381-json \
  --contract-name GnarkCubicBls12381JsonVerifier

cargo run -p soroban-verifier-gen -- \
  --vk examples/gnark-native/cubic/artifacts/bn254/verification_key_gnark.json \
  --proof examples/gnark-native/cubic/artifacts/bn254/proof_gnark.json \
  --public examples/gnark-native/cubic/artifacts/bn254/public.json \
  --out examples/generated/gnark_cubic_bn254_json \
  --crate-name gnark-cubic-bn254-json \
  --contract-name GnarkCubicBn254JsonVerifier

cargo run -p soroban-verifier-gen -- \
  --vk examples/gnark-native/cubic/artifacts/bls12381/verification_key.bin \
  --proof examples/gnark-native/cubic/artifacts/bls12381/proof.bin \
  --public examples/gnark-native/cubic/artifacts/bls12381/public.json \
  --out examples/generated/gnark_cubic_bls12_381_bin \
  --crate-name gnark-cubic-bls12_381-bin \
  --contract-name GnarkCubicBls12381BinVerifier

cargo run -p soroban-verifier-gen -- \
  --vk examples/gnark-native/cubic/artifacts/bn254/verification_key.bin \
  --proof examples/gnark-native/cubic/artifacts/bn254/proof.bin \
  --public examples/gnark-native/cubic/artifacts/bn254/public.json \
  --out examples/generated/gnark_cubic_bn254_bin \
  --crate-name gnark-cubic-bn254-bin \
  --contract-name GnarkCubicBn254BinVerifier

cargo run -p soroban-verifier-gen -- \
  --vk examples/sp1-groth16/fibonacci/artifacts/groth16_vk_v5.bin \
  --proof examples/sp1-groth16/fibonacci/artifacts/fibonacci_proof.bin \
  --out examples/generated/sp1_fibonacci_groth16_v5 \
  --crate-name sp1-fibonacci-groth16-v5 \
  --contract-name Sp1FibonacciGroth16V5Verifier

cargo run -p soroban-verifier-gen -- \
  --vk examples/sp1-groth16/fibonacci/artifacts/sp1_groth16_vk.bin \
  --proof examples/sp1-groth16/fibonacci/artifacts/fibonacci_sp1_6_proof.bin \
  --out examples/generated/sp1_fibonacci_groth16_sp1_6 \
  --crate-name sp1-fibonacci-groth16-sp1-6 \
  --contract-name Sp1FibonacciGroth16Sp16Verifier
```

## Notes

- `--bundle` is used for compact Arkworks artifacts (`groth16_artifacts.json`); when the bundle includes proof/public inputs, generated contract tests embed them.
- `--public` is required only for formats that include public inputs in a separate file.
- `--curve` is optional and used only for explicit format disambiguation.
