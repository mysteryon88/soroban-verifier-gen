use soroban_verifier_gen_core::formats::load_arkworks_inputs;
use std::fs;
use std::path::Path;

fn fixture(curve: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/ark-mimc/artifacts")
        .join(curve)
        .join("groth16_artifacts.json")
}

#[test]
fn raw_public_scalar_files_match_json_strings_for_both_curves() {
    let dir = tempfile::tempdir().unwrap();
    let vk_path = dir.path().join("vk.json");
    let public_path = dir.path().join("public");
    for curve in ["bn254", "bls12_381"] {
        let mut vk: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture(curve)).unwrap()).unwrap();
        vk.as_object_mut().unwrap().remove("proof");
        fs::write(&vk_path, vk.to_string()).unwrap();
        let decimal = "1".repeat(64);
        for (raw, expected) in [
            (decimal.clone(), decimal.as_str()),
            ("0x1".to_string(), "1"),
            ("0X123".to_string(), "291"),
            (format!("le:01{}", "0".repeat(62)), "1"),
            ("123".to_string(), "123"),
        ] {
            for quoted in [true, false] {
                let text = if quoted {
                    serde_json::to_string(&raw).unwrap()
                } else {
                    raw.clone()
                };
                fs::write(&public_path, text).unwrap();
                let inputs = load_arkworks_inputs(&vk_path, None, Some(&public_path), None)
                    .unwrap_or_else(|err| panic!("{curve} {raw} quoted={quoted}: {err}"));
                assert_eq!(inputs.public_inputs, vec![expected]);
            }
        }
    }
}

#[test]
fn raw_public_selection_preserves_json_and_byte_validation() {
    let dir = tempfile::tempdir().unwrap();
    let vk_path = dir.path().join("vk.json");
    let public_path = dir.path().join("public");
    let raw_path = dir.path().join("raw");
    for (curve, hint) in [("bn254", "bn254"), ("bls12_381", "bls12381")] {
        let mut vk: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture(curve)).unwrap()).unwrap();
        vk.as_object_mut().unwrap().remove("proof");
        fs::write(&vk_path, vk.to_string()).unwrap();
        for bad in [
            "{\"public_inputs\":[",
            "[\"1\",{broken]",
            "0xgg",
            "le:01",
            "le:zz",
            "",
        ] {
            fs::write(&public_path, bad).unwrap();
            assert!(
                load_arkworks_inputs(&vk_path, None, Some(&public_path), None).is_err(),
                "accepted malformed public {bad}"
            );
        }
        fs::write(&public_path, "\"1\"").unwrap();
        for raw in [
            "0x1",
            "0X123",
            "le:0100000000000000000000000000000000000000000000000000000000000000",
        ] {
            fs::write(&raw_path, raw).unwrap();
            assert!(
                load_arkworks_inputs(&raw_path, None, None, Some(hint)).is_err(),
                "accepted invalid VK bytes {raw}"
            );
            assert!(
                load_arkworks_inputs(&vk_path, Some(&raw_path), Some(&public_path), None).is_err(),
                "accepted invalid proof bytes {raw}"
            );
        }
        let oversized = format!("[{}{{malformed]", "null,".repeat(65_537));
        fs::write(&public_path, oversized).unwrap();
        let err = load_arkworks_inputs(&vk_path, None, Some(&public_path), None).unwrap_err();
        assert!(err.to_string().contains("collection"), "{err}");
    }
}

#[test]
fn decimal_files_preserve_field_and_digit_boundaries() {
    use ark_ff::PrimeField;
    use soroban_verifier_gen_core::error::Error;
    let dir = tempfile::tempdir().unwrap();
    let vk_path = dir.path().join("vk.json");
    let public_path = dir.path().join("public");
    for (curve, hint) in [("bn254", "bn254"), ("bls12_381", "bls12381")] {
        let mut vk: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture(curve)).unwrap()).unwrap();
        vk.as_object_mut().unwrap().remove("proof");
        fs::write(&vk_path, vk.to_string()).unwrap();
        let modulus = if curve == "bn254" {
            ark_bn254::Fr::MODULUS.to_string()
        } else {
            ark_bls12_381::Fr::MODULUS.to_string()
        };
        let overlong = "9".repeat(256 + 1);
        for quoted in [true, false] {
            let text = if quoted {
                serde_json::to_string(&modulus).unwrap()
            } else {
                modulus.clone()
            };
            fs::write(&public_path, text).unwrap();
            let inputs = load_arkworks_inputs(&vk_path, None, Some(&public_path), None).unwrap();
            let adapter = soroban_verifier_gen_core::curves::create_adapter(hint).unwrap();
            assert!(matches!(
                adapter.serialize_fr_public_input(&inputs.public_inputs[0]),
                Err(Error::FieldOverflow(_))
            ));
            let text = if quoted {
                serde_json::to_string(&overlong).unwrap()
            } else {
                overlong.clone()
            };
            fs::write(&public_path, text).unwrap();
            assert!(matches!(
                load_arkworks_inputs(&vk_path, None, Some(&public_path), None),
                Err(Error::DecimalParse(_))
            ));
        }
    }
}
