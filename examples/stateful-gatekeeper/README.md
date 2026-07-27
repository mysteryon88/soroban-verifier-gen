# Stateful Soroban gatekeeper

This example keeps the generated `Verifier` stateless and adds a separate `Gatekeeper` contract that owns replay state.

`Gatekeeper::authorize` length-prefixes and hashes the domain, nullifier, generated VK fingerprint, current Soroban contract address, network identifier, and operation into the circuit's sole public input. It calls `verify_proof_strict`, then stores `DataKey::Used(canonical_nullifier)` in persistent storage only after the real BN254 proof succeeds. The example extends the entry TTL to 241,920 ledgers whenever its remaining TTL is below 120,960 ledgers; production deployments should select values that match their network retention policy.

The fixed `CONTEXT_MASK` is a 248-bit output encoding chosen so the example can reuse the repository's existing proof fixture while always producing a canonical BN254 scalar. The first byte is fixed and the remaining 31 bytes are `SHA-256(context) XOR mask`. A production circuit may prove an unmasked hash-to-field value directly.

The fixture is bound to contract address `CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADFP5BVL`. Registering the same code at a different address changes the public input and the proof fails.

Tests cover the first valid authorization, replay of the same canonical nullifier, another domain, another contract address, an invalid proof, and a wrong VK fingerprint:

```sh
cargo test --manifest-path examples/stateful-gatekeeper/Cargo.toml
```

The generated `verifier-manifest.json` records the canonical VK fingerprint used by the context commitment. The fingerprint proves integrity, not the honesty of the trusted setup.
