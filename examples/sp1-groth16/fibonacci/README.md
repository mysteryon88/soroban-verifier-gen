# SP1 Groth16 Fibonacci Artifacts

This example contains SP1 Groth16 wrapper artifacts for a Fibonacci program.
The checked fixtures are copied from
[`mysteryon88/export-sui-verifier`](https://github.com/mysteryon88/export-sui-verifier).

Checked artifacts:

- `artifacts/groth16_vk_v5.bin`
- `artifacts/fibonacci_proof.bin`
- `artifacts/sp1_groth16_vk.bin`
- `artifacts/fibonacci_sp1_6_proof.bin`

Generate Soroban verifier contracts:

```sh
cargo run -p soroban-verifier-gen -- --vk examples/sp1-groth16/fibonacci/artifacts/groth16_vk_v5.bin --proof examples/sp1-groth16/fibonacci/artifacts/fibonacci_proof.bin --out examples/generated/sp1_fibonacci_groth16_v5 --crate-name sp1-fibonacci-groth16-v5 --contract-name Sp1FibonacciGroth16V5Verifier

cargo run -p soroban-verifier-gen -- --vk examples/sp1-groth16/fibonacci/artifacts/sp1_groth16_vk.bin --proof examples/sp1-groth16/fibonacci/artifacts/fibonacci_sp1_6_proof.bin --out examples/generated/sp1_fibonacci_groth16_sp1_6 --crate-name sp1-fibonacci-groth16-sp1-6 --contract-name Sp1FibonacciGroth16Sp16Verifier
```
