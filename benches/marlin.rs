use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

mod marlin381 {
    use ark_bls12_381::{Bls12_381, Fr};
    use zkmember::commitments::pedersen381;

    super::bench_marlin!(
        pedersen381,
        Bls12_381,
        Fr,
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

mod marlin761 {
    use ark_bw6_761::{Fr, BW6_761};
    pub use zkmember::commitments::pedersen761;

    super::bench_marlin!(
        pedersen761,
        BW6_761,
        Fr,
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

fn criterion_config(measurement_secs: u64) -> Criterion {
    Criterion::default()
        .measurement_time(Duration::from_secs(measurement_secs))
        .sample_size(10)
}

criterion_group! {
    name = marlin381_benches;
    config = criterion_config(60);
    targets = marlin381::bench_marlin
}
criterion_group! {
    name = marlin761_benches;
    config = criterion_config(60);
    targets = marlin761::bench_marlin
}

criterion_main!(marlin381_benches, marlin761_benches);

#[macro_export]
macro_rules! bench_marlin {
    ($module:ident, $curve:ident, $field:ident, $($num_members:expr),+) => {
        use ark_crypto_primitives::crh::{TwoToOneCRH, CRH};
        use ark_marlin::Marlin;
        use ark_poly::univariate::DensePolynomial;
        use ark_poly_commit::marlin_pc::MarlinKZG10;
        use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
        use blake2::Blake2s;
        use criterion::{black_box, Criterion};
        use rand::Rng;
        use $module::{
            common::{new_membership_tree, LeafHash, TwoToOneHash},
            constraint::MerkleTreeCircuit,
        };

        use zkmember::member::{generate_members, Member};

        type PC = MarlinKZG10<$curve, DensePolynomial<$field>>;
        type MarlinM = Marlin<$field, PC, Blake2s>;

        pub fn bench_marlin(c: &mut Criterion) {
			let mut rng = ark_std::test_rng();
			let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
			let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

			// Max constraints
			let mut members = Box::new(vec![]);
			let &max_members = [$($num_members),+].iter().max().unwrap();
			println!("max_members: {}", max_members);

			generate_members(&mut members, max_members);

			// Compute global constraints (gc)
			let mut gc_leaves = members.iter().map(|member| {
				member.hash::<LeafHash>(&leaf_crh_params)
			}).collect::<Vec<_>>();

			let gc_tree = new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &mut gc_leaves);
			let gc_root = gc_tree.root();
			let gc_index = black_box(rand::rng().random_range(0..max_members as u32));
			let gc_path = black_box(gc_tree.generate_proof(gc_index as usize).unwrap());
			let gc_member: &Member = members.get(gc_index as usize).unwrap();

			// Initialize circuit constraints struct for merkle tree
			let circuit = MerkleTreeCircuit {
				leaf_crh_params: leaf_crh_params.clone(),
				two_to_one_crh_params: two_to_one_crh_params.clone(),
				root: gc_root,
				leaf_hash: gc_member.hash::<LeafHash>(&leaf_crh_params),
				authentication_path: Some(gc_path),
			};

			let cs = ConstraintSystem::<Fr>::new_ref();
			circuit.clone().generate_constraints(cs.clone()).unwrap();

			// NOTE: Correctness requires every later circuit to satisfy:
			//  - rows ≤ num_constraints
			let n_constraints = cs.num_constraints();
			//  - vars ≤ num_variables
			let n_variables = cs.num_instance_variables() + cs.num_witness_variables();
			//  - non-zeros ≤ num_non_zero
			let n_non_zero = 5 * n_constraints;

			let srs = MarlinM::universal_setup(
				n_constraints.next_power_of_two(), // round up   ▸ security proof assumes power‑of‑two
				n_variables.next_power_of_two(),
				n_non_zero.next_power_of_two(),
				&mut rng,
			)
			.unwrap();

			let (pk, vk) = MarlinM::index(&srs, circuit.clone()).unwrap();

			for &num_members in &[$($num_members),+] {
				let mut members = Box::new(members[0..num_members].to_vec());
				generate_members(&mut members, max_members - (num_members as u32)); // pad up to max

				// Hash mock members
				let mut leaves = members
					.iter()
					.map(|member| member.hash::<LeafHash>(&leaf_crh_params))
					.collect::<Vec<_>>();

				// Construct membership Merkle tree
				let tree = new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);
				let root = tree.root();

				// Fetch random member from the tree
				let index = black_box(rand::rng().random_range(0..num_members as u32));
				let path = black_box(tree.generate_proof(index as usize).unwrap());
				let member: &Member = members.get(index as usize).unwrap();

				// Initialize circuit constraints struct for merkle tree
				let circuit = MerkleTreeCircuit {
					leaf_crh_params: leaf_crh_params.clone(),
					two_to_one_crh_params: two_to_one_crh_params.clone(),
					root,
					leaf_hash: member.hash::<LeafHash>(&leaf_crh_params),
					authentication_path: Some(path),
				};

				c.bench_function(
					format!("{}_marlin_prove_{}", stringify!($curve), num_members).as_str(),
					|b| {
						b.iter(|| {
							let proof = MarlinM::prove(&pk.clone(), circuit.clone(), &mut rng).unwrap();
							black_box(proof);
						});
					},
				);

				let proof = MarlinM::prove(&pk, circuit, &mut rng).unwrap();
				let public_input = vec![root, member.hash::<LeafHash>(&leaf_crh_params)];

				c.bench_function(
					format!("{}_marlin_verify_{}", stringify!($curve), num_members).as_str(),
					|b| {
						b.iter(|| {
							let is_valid =
								MarlinM::verify(&vk.clone(), &public_input, &proof, &mut rng).unwrap();
							assert!(is_valid);
						});
					},
				);
			}
        }
    };
}
