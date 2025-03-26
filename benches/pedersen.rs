use std::time::Duration;

use ark_crypto_primitives::SNARK;
use ark_crypto_primitives::{crh::TwoToOneCRH, CRH};
use ark_groth16::Groth16;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use zkmember::member::generate_members;
use zkmember::member::Member;

use rand::Rng;

// Conditional imports for pedersen modules
mod pedersen381 {
    use super::*;
    pub use zkmember::commitments::pedersen381::{
        common::{
            new_membership_tree as new_membership381_tree, LeafHash as LeafHash381,
            TwoToOneHash as TwoToOneHash381,
        },
        constraint::MerkleTreeCircuit as MerkleTreeCircuit381,
    };

    pub type Bls12_381Curve = ark_bls12_381::Bls12_381;

    pub fn bench_groth16(c: &mut Criterion) {
        const TEST_MEMBERS_COUNT: usize = 10;

        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <LeafHash381 as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash381 as TwoToOneCRH>::setup(&mut rng).unwrap();

        let mut members = Box::new(vec![]);
        generate_members(&mut members, TEST_MEMBERS_COUNT as u32);

        let mut leaves = members
            .iter()
            .map(|member| member.hash::<LeafHash381>(&leaf_crh_params))
            .collect::<Vec<_>>();

        let tree = new_membership381_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);
        let root = tree.root();

        let index = black_box(rand::rng().random_range(0..TEST_MEMBERS_COUNT as u32));
        let path = black_box(tree.generate_proof(index as usize).unwrap());
        let member: &Member = members.get(index as usize).unwrap();

        let circuit = MerkleTreeCircuit381 {
            leaf_crh_params: &leaf_crh_params,
            two_to_one_crh_params: &two_to_one_crh_params,
            root,
            leaf_hash: member.hash::<LeafHash381>(&leaf_crh_params),
            authentication_path: Some(path),
        };

        let (pk, vk) =
            Groth16::<Bls12_381Curve>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

        c.bench_function("pedersen381_groth16_prove", |b| {
            b.iter(|| {
                let proof =
                    Groth16::<Bls12_381Curve>::prove(&pk, circuit.clone(), &mut rng).unwrap();
                black_box(proof);
            });
        });

        let proof = Groth16::<Bls12_381Curve>::prove(&pk, circuit, &mut rng).unwrap();
        let public_input = vec![root, member.hash::<LeafHash381>(&leaf_crh_params)];

        c.bench_function("pedersen381_groth16_verify", |b| {
            b.iter(|| {
                let is_valid =
                    Groth16::<Bls12_381Curve>::verify(&vk, &public_input, &proof).unwrap();
                assert!(is_valid);
            });
        });
    }
}

// Conditional curve import/alias
mod pedersen761 {
    use super::*;

    pub use ark_bw6_761::BW6_761;
    pub use zkmember::commitments::pedersen761::{
        common::{
            new_membership_tree as new_membership761_tree, LeafHash as LeafHash761,
            TwoToOneHash as TwoToOneHash761,
        },
        constraint::MerkleTreeCircuit as MerkleTreeCircuit761,
    };
    pub type BW6_761Curve = BW6_761;

    pub fn bench_groth16(c: &mut Criterion) {
        const TEST_MEMBERS_COUNT: usize = 10;

        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <LeafHash761 as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash761 as TwoToOneCRH>::setup(&mut rng).unwrap();

        let mut members = Box::new(vec![]);
        generate_members(&mut members, TEST_MEMBERS_COUNT as u32);

        let mut leaves = members
            .iter()
            .map(|member| member.hash::<LeafHash761>(&leaf_crh_params))
            .collect::<Vec<_>>();

        let tree = new_membership761_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);
        let root = tree.root();

        let index = black_box(rand::rng().random_range(0..TEST_MEMBERS_COUNT as u32));
        let path = black_box(tree.generate_proof(index as usize).unwrap());
        let member: &Member = members.get(index as usize).unwrap();

        let circuit = MerkleTreeCircuit761 {
            leaf_crh_params: &leaf_crh_params,
            two_to_one_crh_params: &two_to_one_crh_params,
            root,
            leaf_hash: member.hash::<LeafHash761>(&leaf_crh_params),
            authentication_path: Some(path),
        };

        let (pk, vk) =
            Groth16::<BW6_761Curve>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

        c.bench_function("pedersen761_groth16_prove", |b| {
            b.iter(|| {
                let proof = Groth16::<BW6_761Curve>::prove(&pk, circuit.clone(), &mut rng).unwrap();
                black_box(proof);
            });
        });

        let proof = Groth16::<BW6_761Curve>::prove(&pk, circuit, &mut rng).unwrap();
        let public_input = vec![root, member.hash::<LeafHash761>(&leaf_crh_params)];

        c.bench_function("pedersen761_groth16_verify", |b| {
            b.iter(|| {
                let is_valid = Groth16::<BW6_761Curve>::verify(&vk, &public_input, &proof).unwrap();
                assert!(is_valid);
            });
        });
    }
}

fn criterion_config(measurement_secs: u64) -> Criterion {
    Criterion::default()
        .measurement_time(Duration::from_secs(measurement_secs))
        .sample_size(10)
}

criterion_group! {
    name = pedersen381_benches;
    config = criterion_config(10);
    targets = pedersen381::bench_groth16
}
criterion_group! {
    name = pedersen761_benches;
    config = criterion_config(10);
    targets = pedersen761::bench_groth16
}
criterion_main!(pedersen381_benches, pedersen761_benches);
