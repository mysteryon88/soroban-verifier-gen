# Tests And Example Generation

Run tests for the generator crate itself from the repository root:

```sh
cargo test
```

Regenerate both example verifier crates from `examples/data/...`:

```sh
cargo run --example generate_verifier
```

Run tests for the generated BN254 verifier crate:

```sh
cargo test --manifest-path ./my_verifier_bn254/Cargo.toml
```

Run tests for the generated BLS12-381 verifier crate:

```sh
cargo test --manifest-path ./my_verifier_bls12-381/Cargo.toml
```

If `cargo test` ever prints `running 0 tests`, check that the generated crate still includes the test module in `src/lib.rs`:

```rust
#[cfg(test)]
#[path = "test.rs"]
mod proof_test;
```
