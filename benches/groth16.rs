use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

// Conditional imports for pedersen modules
mod pedersen381 {
    use ark_bls12_381::Bls12_381;
    use zkmember::commitments::pedersen381;

    super::bench_groth16!(
        pedersen381,
        Bls12_381,
        16,
        50,
        64,
        100,
        128,
        512,
        1000,
        1024
    );
}

// Conditional curve import/alias
mod pedersen761 {
    use ark_bw6_761::BW6_761;
    pub use zkmember::commitments::pedersen761;

    super::bench_groth16!(pedersen761, BW6_761, 16, 50, 64, 100, 128, 512, 1000, 1024);
}

fn criterion_config(measurement_secs: u64) -> Criterion {
    Criterion::default()
        .measurement_time(Duration::from_secs(measurement_secs))
        .sample_size(10)
}

criterion_group! {
    name = pedersen381_benches;
    config = criterion_config(30);
    targets = pedersen381::bench_groth16
}
criterion_group! {
    name = pedersen761_benches;
    config = criterion_config(30);
    targets = pedersen761::bench_groth16
}
criterion_main!(pedersen381_benches, pedersen761_benches);

#[macro_export]
macro_rules! bench_groth16 {
    ($module:ident, $curve:ident, $($num_members:expr),+) => {
        use $module::{
            common::{new_membership_tree, LeafHash, TwoToOneHash},
            constraint::MerkleTreeCircuit,
        };

        use ark_crypto_primitives::{
            crh::{TwoToOneCRH, CRH},
            SNARK,
        };
        use ark_groth16::Groth16;
        use criterion::{black_box, Criterion};
        use rand::Rng;

        use zkmember::member::{generate_members, Member};

        pub fn bench_groth16(c: &mut Criterion) {
            for &num_members in &[$($num_members),+] {
                let mut rng = ark_std::test_rng();

                let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
                let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

                // Generate mock members
                let mut members = Box::new(vec![]);
                generate_members(&mut members, num_members as u32);

                // Hash mock members
                let mut leaves = members
                    .iter()
                    .map(|member| member.hash::<LeafHash>(&leaf_crh_params))
                    .collect::<Vec<_>>();

                // Construct membership Merkle tree
                let tree =
                    new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);
                let root = tree.root();

                // Fetch random member from the tree
                let index = black_box(rand::rng().random_range(0..num_members as u32));
                let path = black_box(tree.generate_proof(index as usize).unwrap());
                let member: &Member = members.get(index as usize).unwrap();

                // Initialize circuit constraints struct for merkle tree
                let circuit = MerkleTreeCircuit {
                    leaf_crh_params: leaf_crh_params.clone(),
                    two_to_one_crh_params: two_to_one_crh_params,
                    root,
                    leaf_hash: member.hash::<LeafHash>(&leaf_crh_params),
                    authentication_path: Some(path),
                };

                let (pk, vk) =
                    Groth16::<$curve>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

                c.bench_function(
                    format!("{}_groth16_prove_{}", stringify!($curve), num_members).as_str(),
                    |b| {
                        b.iter(|| {
                            let proof =
                                Groth16::<$curve>::prove(&pk, circuit.clone(), &mut rng).unwrap();
                            black_box(proof);
                        });
                    },
                );

                let proof = Groth16::<$curve>::prove(&pk, circuit, &mut rng).unwrap();
                let public_input = vec![root, member.hash::<LeafHash>(&leaf_crh_params)];

                c.bench_function(
                    format!("{}_groth16_verify_{}", stringify!($curve), num_members).as_str(),
                    |b| {
                        b.iter(|| {
                            let is_valid =
                                Groth16::<$curve>::verify(&vk, &public_input, &proof).unwrap();
                            assert!(is_valid);
                        });
                    },
                );
            }
        }
    };
}
