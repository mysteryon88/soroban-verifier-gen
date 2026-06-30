# Gnark Native Cubic Artifacts

This example contains native Gnark Groth16 artifacts for a small cubic circuit.

Checked artifacts:

- `artifacts/bn254/verification_key_gnark.json`
- `artifacts/bn254/proof_gnark.json`
- `artifacts/bn254/verification_key.bin`
- `artifacts/bn254/proof.bin`
- `artifacts/bn254/public.json`
- the same file set under `artifacts/bls12381/`

Generate Soroban verifier contracts:

```sh
cargo run -p soroban-verifier-gen -- --vk examples/gnark-native/cubic/artifacts/bn254/verification_key_gnark.json --proof examples/gnark-native/cubic/artifacts/bn254/proof_gnark.json --public examples/gnark-native/cubic/artifacts/bn254/public.json --out examples/generated/gnark_cubic_bn254_json --crate-name gnark-cubic-bn254-json --contract-name GnarkCubicBn254JsonVerifier

cargo run -p soroban-verifier-gen -- --vk examples/gnark-native/cubic/artifacts/bls12381/verification_key.bin --proof examples/gnark-native/cubic/artifacts/bls12381/proof.bin --public examples/gnark-native/cubic/artifacts/bls12381/public.json --out examples/generated/gnark_cubic_bls12_381_bin --crate-name gnark-cubic-bls12_381-bin --contract-name GnarkCubicBls12381BinVerifier
```
