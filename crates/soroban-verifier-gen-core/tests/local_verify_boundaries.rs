use soroban_verifier_gen_core::curves::create_adapter;
use soroban_verifier_gen_core::error::Error;
use soroban_verifier_gen_core::formats::{load_arkworks_bundle, load_snarkjs_json_inputs};
use soroban_verifier_gen_core::verifier::local_verify;
use std::fs::{self, File};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

fn fixture(curve: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/ark-mimc/artifacts")
        .join(curve)
        .join("groth16_artifacts.json")
}

#[test]
fn local_verify_rejects_mutated_models_without_panicking() {
    for (fixture_name, curve_name) in [("bn254", "bn254"), ("bls12_381", "bls12381")] {
        let mut inputs = load_arkworks_bundle(&fixture(fixture_name), None).unwrap();
        let adapter = create_adapter(curve_name).unwrap();
        assert!(local_verify(adapter.as_ref(), &inputs).unwrap());

        inputs.public_inputs.push("0".to_string());
        assert!(matches!(
            local_verify(adapter.as_ref(), &inputs),
            Err(Error::PublicInputCountMismatch(_))
        ));
        assert!(matches!(
            adapter.local_verify(&inputs),
            Err(Error::PublicInputCountMismatch(_))
        ));

        inputs.verifying_key.ic.clear();
        let result = catch_unwind(AssertUnwindSafe(|| local_verify(adapter.as_ref(), &inputs)));
        assert!(matches!(result, Ok(Err(Error::IcLengthMismatch(_)))));
        assert!(matches!(
            adapter.local_verify(&inputs),
            Err(Error::IcLengthMismatch(_))
        ));
    }
}

#[test]
fn arkworks_loader_rejects_oversized_and_malformed_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let oversized = dir.path().join("oversized.json");
    File::create(&oversized)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    assert!(matches!(
        load_arkworks_bundle(&oversized, Some("bn254")),
        Err(Error::InputTooLarge { .. })
    ));

    let malformed = dir.path().join("malformed.json");
    let mut vk = vec![0; 232];
    vk[224..232].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(
        &malformed,
        serde_json::json!({ "curve": "bn254", "vk": hex::encode(vk) }).to_string(),
    )
    .unwrap();
    assert!(matches!(
        load_arkworks_bundle(&malformed, None),
        Err(Error::IcLengthMismatch(_))
    ));
}

#[test]
fn snarkjs_loader_bounds_public_input_arrays() {
    let artifacts = fixture("bn254").parent().unwrap().to_path_buf();
    assert!(
        load_snarkjs_json_inputs(
            &artifacts.join("verification_key.json"),
            &artifacts.join("proof.json"),
            None,
        )
        .is_ok()
    );

    let dir = tempfile::tempdir().unwrap();
    let public = dir.path().join("public.json");
    fs::write(&public, serde_json::to_vec(&vec!["0"; 65_537]).unwrap()).unwrap();
    assert!(matches!(
        load_snarkjs_json_inputs(
            &artifacts.join("verification_key.json"),
            &artifacts.join("proof.json"),
            Some(&public),
        ),
        Err(Error::PublicInputCountMismatch(_))
    ));
}
