use std::sync::Arc;

use ark_crypto_primitives::SNARK;
use ark_crypto_primitives::{
    crh::{CRHGadget, TwoToOneCRH, TwoToOneCRHGadget},
    PathVar, CRH,
};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zkmember::member::Member;
use zkmember::{commitments::MerkleTreeCircuit, member::generate_members};

use rand::Rng;

// Conditional imports for pedersen modules
#[cfg(feature = "pedersen381")]
mod pedersen381 {
    pub use zkmember::commitments::pedersen381::{
        common::{
            new_membership_tree as new_membership381_tree, LeafHash as LeafHash381,
            MerkleConfig as Merkle381Config, Pedersen381Field, Root as Root381,
            TwoToOneHash as TwoToOneHash381,
        },
        constraint::MerkleTreeCircuit as MerkleTreeCircuit381,
    };

    pub type Curve = ark_bls12_381::Bls12_381;
}
#[cfg(feature = "pedersen381")]
use pedersen381::*;

// Conditional curve import/alias
#[cfg(feature = "pedersen761")]
mod pedersen761 {
    pub use ark_bw6_761::BW6_761;
    pub use zkmember::commitments::pedersen761::{
        common::{
            new_membership_tree as new_membership761_tree, LeafHash as LeafHash761,
            MerkleConfig as Merkle761Config, Pedersen761Field, Root as Root761,
            TwoToOneHash as TwoToOneHash761,
        },
        constraint::MerkleTreeCircuit as MerkleTreeCircuit761,
    };
    pub type Curve = BW6_761;
}
#[cfg(feature = "pedersen761")]
use pedersen761::*;

fn criterion_benchmark(c: &mut Criterion) {
    const TEST_MEMBERS_COUNT: usize = 100;

    c.bench_function("MerkleTreeCircuit::new", |b| {
        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <LeafHash381 as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash381 as TwoToOneCRH>::setup(&mut rng).unwrap();

        let mut members = Box::new(vec![]);
        generate_members(&mut members, TEST_MEMBERS_COUNT as u32);

        let circuit = Arc::new(MerkleTreeCircuit::<
            Pedersen381Field,
            LeafHash381,
            TwoToOneHash381,
            Merkle381Config,
        > {
            leaf_crh_params: &leaf_crh_params,
            two_to_one_crh_params: &two_to_one_crh_params,
            root: Root381::default(),
            leaf_hash: Pedersen381Field::default(),
            authentication_path: None,
        });

        b.iter(|| {
            let index = black_box(rand::thread_rng().gen_range(0..TEST_MEMBERS_COUNT as u32));

            let mut leaves = members
                .iter()
                .map(|member| member.hash::<LeafHash381>(&leaf_crh_params))
                .collect::<Vec<_>>();
            let tree =
                new_membership381_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);

            let root = tree.root();
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
                Groth16::<Curve>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
            let proof = Groth16::<Curve>::prove(&pk, circuit, &mut rng).unwrap();

            let mut leaf_hash_serialization = Vec::new();
            member
                .hash::<LeafHash381>(&leaf_crh_params)
                .serialize(&mut leaf_hash_serialization)
                .unwrap();
            println!(
                "\x1b[0;32mLeaf hash: {}\x1b[0m",
                hex::encode(&leaf_hash_serialization)
            );

            let mut root_serialization = Vec::new();
            root.serialize(&mut root_serialization).unwrap();
            println!(
                "\x1b[0;34mRoot: {}\x1b[0m",
                hex::encode(&root_serialization)
            );

            let mut proof_serialization = Vec::new();
            proof.serialize(&mut proof_serialization).unwrap();
            println!(
                "\x1b[0;33mGenerated proof: {}\x1b[0m",
                hex::encode(&proof_serialization)
            );

            let mut vk_serialization = Vec::new();
            vk.serialize(&mut vk_serialization).unwrap();
            println!(
                "\x1b[0;90mVerification key: {}\x1b[0m",
                hex::encode(&vk_serialization)
            );

            // Construct public input vector properly
            let public_input = vec![root, member.hash::<LeafHash381>(&leaf_crh_params)];
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
