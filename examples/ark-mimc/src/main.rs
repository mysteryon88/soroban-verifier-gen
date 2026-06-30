#![warn(unused)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    variant_size_differences,
    stable_features,
    non_shorthand_field_patterns,
    renamed_and_removed_lints,
    unsafe_code
)]

#[cfg(test)]
use std::any::type_name;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::time::{Duration, Instant};

use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
#[cfg(test)]
use ark_relations::gr1cs::{ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use ark_snarkjs::{AsFp2, CurveTag, export_proof, export_vk};
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::test_rng;

const MIMC_ROUNDS: usize = 322;

/// This is an implementation of MiMC, specifically a
/// variant named `LongsightF322p3`.
/// See http://eprint.iacr.org/2016/492 for more
/// information about this construction.
///
/// ```
/// function LongsightF322p3(xL, xR) {
///     for i from 0 up to 321 {
///         xL, xR := xR + (xL + Ci)^3, xL
///     }
///     return xL
/// }
/// ```
fn mimc<F: Field>(mut xl: F, mut xr: F, constants: &[F]) -> F {
    assert_eq!(constants.len(), MIMC_ROUNDS);

    for constant in constants.iter().take(MIMC_ROUNDS) {
        let mut tmp1 = xl;
        tmp1.add_assign(constant);
        let mut tmp2 = tmp1;
        tmp2.square_in_place();
        tmp2.mul_assign(&tmp1);
        tmp2.add_assign(&xr);
        xr = xl;
        xl = tmp2;
    }

    xl
}

/// This is our demo circuit for proving knowledge of the
/// preimage of a MiMC hash invocation.
#[derive(Copy, Clone)]
struct MiMCDemo<'a, F: Field> {
    xl: Option<F>,
    xr: Option<F>,
    output: Option<F>,
    constants: &'a [F],
}

impl<'a, F: PrimeField> ConstraintSynthesizer<F> for MiMCDemo<'a, F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        let mut xl = FpVar::new_witness(cs.clone(), || {
            self.xl.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let mut xr = FpVar::new_witness(cs.clone(), || {
            self.xr.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let output = FpVar::new_input(cs.clone(), || {
            self.output.ok_or(SynthesisError::AssignmentMissing)
        })?;

        for constant in self.constants.iter().take(MIMC_ROUNDS) {
            let tmp = (&xl + *constant).square()?;
            let new_xl = tmp * (&xl + *constant) + xr;
            xr = xl;
            xl = new_xl;
        }
        output.enforce_equal(&xl)?;

        Ok(())
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 0x0f) as usize]));
    }
    out
}

fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn write_hex_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(to_hex(bytes).as_bytes())?;
    Ok(())
}

fn resolve_output_dir(out_dir: &str, curve: &str) -> PathBuf {
    let base = Path::new(out_dir);
    let base = if base.is_absolute() {
        base.to_path_buf()
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(base)
    };

    if base.file_name().and_then(|name| name.to_str()) == Some(curve) {
        base
    } else {
        base.join(curve)
    }
}

fn write_artifacts_for_curve<E>(name: &str, out_dir: &Path)
where
    E: Pairing + CurveTag,
    <E::G2Affine as ark_ec::AffineRepr>::BaseField: AsFp2,
{
    use ark_groth16::Groth16;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let mut constants = Vec::with_capacity(MIMC_ROUNDS);
    for _ in 0..MIMC_ROUNDS {
        constants.push(E::ScalarField::rand(&mut rng));
    }

    let c = MiMCDemo::<E::ScalarField> {
        xl: None,
        xr: None,
        output: None,
        constants: &constants,
    };
    let (pk, vk) = Groth16::<E>::setup(c, &mut rng).unwrap();

    let xl: E::ScalarField = E::ScalarField::rand(&mut rng);
    let xr: E::ScalarField = E::ScalarField::rand(&mut rng);
    let image = mimc(xl, xr, &constants);
    let c = MiMCDemo {
        xl: Some(xl),
        xr: Some(xr),
        output: Some(image),
        constants: &constants,
    };
    let proof = Groth16::<E>::prove(&pk, c, &mut rng).unwrap();
    let pvk = Groth16::<E>::process_vk(&vk).unwrap();
    assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[image], &proof).unwrap());

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    let mut image_bytes = Vec::new();
    image.serialize_compressed(&mut image_bytes).unwrap();

    let mut proof_a_bytes = Vec::new();
    proof.a.serialize_compressed(&mut proof_a_bytes).unwrap();
    let mut proof_b_bytes = Vec::new();
    proof.b.serialize_compressed(&mut proof_b_bytes).unwrap();
    let mut proof_c_bytes = Vec::new();
    proof.c.serialize_compressed(&mut proof_c_bytes).unwrap();

    let mut vk_alpha_g1 = Vec::new();
    vk.alpha_g1.serialize_compressed(&mut vk_alpha_g1).unwrap();
    let mut vk_beta_g2 = Vec::new();
    vk.beta_g2.serialize_compressed(&mut vk_beta_g2).unwrap();
    let mut vk_gamma_g2 = Vec::new();
    vk.gamma_g2.serialize_compressed(&mut vk_gamma_g2).unwrap();
    let mut vk_delta_g2 = Vec::new();
    vk.delta_g2.serialize_compressed(&mut vk_delta_g2).unwrap();

    let mut vk_gamma_abc_g1 = Vec::new();
    for (idx, x) in vk.gamma_abc_g1.iter().enumerate() {
        let mut entry = Vec::new();
        x.serialize_compressed(&mut entry).unwrap();
        vk_gamma_abc_g1.push((idx, entry));
    }

    fs::create_dir_all(out_dir).unwrap();
    let public_inputs = [image];
    let _ = export_proof::<E, _>(&proof, &public_inputs, out_dir.join("proof.json")).unwrap();
    let _ = export_vk::<E, _>(
        &vk,
        public_inputs.len(),
        out_dir.join("verification_key.json"),
    )
    .unwrap();

    write_file(&out_dir.join("vk.bin"), &vk_bytes).unwrap();
    write_file(&out_dir.join("proof.bin"), &proof_bytes).unwrap();
    write_file(&out_dir.join("public_input.bin"), &image_bytes).unwrap();
    write_file(&out_dir.join("proof_a.bin"), &proof_a_bytes).unwrap();
    write_file(&out_dir.join("proof_b.bin"), &proof_b_bytes).unwrap();
    write_file(&out_dir.join("proof_c.bin"), &proof_c_bytes).unwrap();
    write_file(&out_dir.join("vk_alpha_g1.bin"), &vk_alpha_g1).unwrap();
    write_file(&out_dir.join("vk_beta_g2.bin"), &vk_beta_g2).unwrap();
    write_file(&out_dir.join("vk_gamma_g2.bin"), &vk_gamma_g2).unwrap();
    write_file(&out_dir.join("vk_delta_g2.bin"), &vk_delta_g2).unwrap();
    for (idx, bytes) in vk_gamma_abc_g1 {
        write_file(&out_dir.join(format!("vk_gamma_abc_g1_{idx}.bin")), &bytes).unwrap();
    }

    write_hex_file(&out_dir.join("vk.hex"), &vk_bytes).unwrap();
    write_hex_file(&out_dir.join("proof.hex"), &proof_bytes).unwrap();
    write_hex_file(&out_dir.join("public_input.hex"), &image_bytes).unwrap();
    write_hex_file(&out_dir.join("proof_a.hex"), &proof_a_bytes).unwrap();
    write_hex_file(&out_dir.join("proof_b.hex"), &proof_b_bytes).unwrap();
    write_hex_file(&out_dir.join("proof_c.hex"), &proof_c_bytes).unwrap();

    let json = format!(
        "{{\n  \"curve\": \"{}\",\n  \"vk\": \"{}\",\n  \"proof\": \"{}\",\n  \"public_input\": \"{}\",\n  \"proof_a\": \"{}\",\n  \"proof_b\": \"{}\",\n  \"proof_c\": \"{}\",\n  \"vk_alpha_g1\": \"{}\",\n  \"vk_beta_g2\": \"{}\",\n  \"vk_gamma_g2\": \"{}\",\n  \"vk_delta_g2\": \"{}\"\n}}",
        name,
        to_hex(&vk_bytes),
        to_hex(&proof_bytes),
        to_hex(&image_bytes),
        to_hex(&proof_a_bytes),
        to_hex(&proof_b_bytes),
        to_hex(&proof_c_bytes),
        to_hex(&vk_alpha_g1),
        to_hex(&vk_beta_g2),
        to_hex(&vk_gamma_g2),
        to_hex(&vk_delta_g2)
    );
    write_file(&out_dir.join("groth16_artifacts.json"), json.as_bytes()).unwrap();
}

#[cfg(test)]
fn test_mimc_groth16_for_curve<E: Pairing>() {
    use ark_groth16::Groth16;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let curve_name = type_name::<E>();

    let constants = (0..MIMC_ROUNDS)
        .map(|_| E::ScalarField::rand(&mut rng))
        .collect::<Vec<_>>();

    println!("Creating parameters for {curve_name}...");

    let (pk, vk) = {
        let c = MiMCDemo::<E::ScalarField> {
            xl: None,
            xr: None,
            output: None,
            constants: &constants,
        };
        Groth16::<E>::setup(c, &mut rng).unwrap()
    };

    let pvk = Groth16::<E>::process_vk(&vk).unwrap();

    println!("Creating proofs for {curve_name}...");

    const SAMPLES: u32 = 50;
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    for _ in 0..SAMPLES {
        let xl = E::ScalarField::rand(&mut rng);
        let xr = E::ScalarField::rand(&mut rng);
        let image = mimc(xl, xr, &constants);

        let c = MiMCDemo {
            xl: Some(xl),
            xr: Some(xr),
            output: Some(image),
            constants: &constants,
        };

        let cs = ConstraintSystem::<E::ScalarField>::new_ref();
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
            generate_lc_assignments: false,
        });
        c.generate_constraints(cs.clone()).unwrap();
        cs.finalize();
        assert!(cs.is_satisfied().unwrap());

        let start_prove = Instant::now();
        let proof = Groth16::<E>::prove(&pk, c, &mut rng).unwrap();
        total_proving += start_prove.elapsed();

        let start_verify = Instant::now();
        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[image], &proof).unwrap());
        total_verifying += start_verify.elapsed();
    }

    let proving_avg = total_proving / SAMPLES;
    let verifying_avg = total_verifying / SAMPLES;

    println!(
        "Average proving time for {curve_name}: {:?} seconds",
        proving_avg.as_secs_f64()
    );
    println!(
        "Average verification time for {curve_name}: {:?} seconds",
        verifying_avg.as_secs_f64()
    );
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  cargo test test_mimc_groth16_bn254");
    eprintln!("  cargo test test_mimc_groth16_bls12_381");
    eprintln!("  cargo run -- export <bn254|bls12_381> [output_dir]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  cargo run -- export bn254 artifacts");
    eprintln!("  cargo run -- export bls12_381 artifacts");
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 2 || args[1] == "help" || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return;
    }

    if args[1] != "export" {
        eprintln!("Unknown command: {}", args[1]);
        print_usage();
        return;
    }

    if args.len() < 3 {
        eprintln!("Curve is required");
        print_usage();
        return;
    }

    let curve = args[2].as_str();
    let out_dir = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "artifacts".to_string());
    let out_dir = resolve_output_dir(&out_dir, curve);

    match curve {
        "bn254" => write_artifacts_for_curve::<Bn254>("bn254", &out_dir),
        "bls12_381" => write_artifacts_for_curve::<Bls12_381>("bls12_381", &out_dir),
        _ => {
            eprintln!("Unsupported curve: {curve}");
            print_usage();
        }
    }
}

#[test]
fn test_mimc_groth16_bls12_381() {
    test_mimc_groth16_for_curve::<Bls12_381>();
}

#[test]
fn test_mimc_groth16_bn254() {
    test_mimc_groth16_for_curve::<Bn254>();
}
