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
				let tree = new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);
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

				c.bench_function(
					format!("{}_groth16_setup", stringify!($curve)).as_str(),
					|b| {
						b.iter(|| {
							black_box(Groth16::<$curve>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap());
						});
					},
				);

				let (pk, vk) =
					Groth16::<$curve>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

				c.bench_function(
					format!("{}_groth16_prove", stringify!($curve)).as_str(),
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
					format!("{}_groth16_verify", stringify!($curve)).as_str(),
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

#[macro_export]
macro_rules! bench_marlin {
    ($module:ident, $curve:ident, $field:ident, $($num_members:expr),+ $(,)?) => {
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
			let num_members_slice = &[$($num_members),+];

			let mut rng = ark_std::test_rng();
			let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
			let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

			// Compute max constraints
			let max_members = *num_members_slice.iter().max().unwrap();

			// Shared test parameters
			let mut members = Box::new(vec![]);

			for &num_members in num_members_slice {
				let curr_members = - members.len();
				generate_members(&mut members, (max_members - num_members - curr_members) as u32);

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

				let cs = ConstraintSystem::<Fr>::new_ref();
				circuit.clone().generate_constraints(cs.clone()).unwrap();

				// NOTE: Correctness requires every later circuit to satisfy:
				//  - rows ≤ num_constraints
				let n_constraints = cs.num_constraints();
				//  - vars ≤ num_variables
				let n_variables = cs.num_instance_variables() + cs.num_witness_variables();
				//  - non-zeros ≤ num_non_zero
				let n_non_zero = 5 * n_constraints;

				println!(
					"n_constraints: {}, n_variables: {}, n_non_zero: {}",
					n_constraints, n_variables, n_non_zero
				);

				let srs = MarlinM::universal_setup(
					n_constraints.next_power_of_two(), // round up, security proof assumes power‑of‑two
					n_variables.next_power_of_two(),
					n_non_zero.next_power_of_two(),
					&mut rng,
				)
				.unwrap();

				c.bench_function(
					format!("{}_marlin_setup", stringify!($curve)).as_str(),
					|b| {
						b.iter(|| {
							black_box(MarlinM::universal_setup(
								n_constraints.next_power_of_two(), // round up, security proof assumes power‑of‑two
								n_variables.next_power_of_two(),
								n_non_zero.next_power_of_two(),
								&mut rng,
							).unwrap());
						});
					},
				);


				// let (pk, vk) = MarlinM::index(&srs, circuit.clone()).unwrap();

				// c.bench_function(
				// 	format!("{}_marlin_prove", stringify!($curve)).as_str(),
				// 	|b| {
				// 		b.iter(|| {
				// 			let proof = MarlinM::prove(&pk.clone(), circuit.clone(), &mut rng).unwrap();
				// 			black_box(proof);
				// 		});
				// 	},
				// );

				// let proof = MarlinM::prove(&pk.clone(), circuit.clone(), &mut rng).unwrap();
				// let public_input = vec![root, member.hash::<LeafHash>(&leaf_crh_params)];

				// c.bench_function(
				// 	format!("{}_marlin_verify", stringify!($curve)).as_str(),
				// 	|b| {
				// 		b.iter(|| {
				// 			let is_valid =
				// 				MarlinM::verify(&vk.clone(), &public_input, &proof, &mut rng).unwrap();
				// 			assert!(is_valid);
				// 		});
				// 	},
				// );

				let (pk, vk) = MarlinM::index(&srs.clone(), circuit.clone()).unwrap();

				for _ in 1..10 {
					leaves.pop(); // Remove a declared member from the tree to benchmark universal setup

					// Construct membership Merkle tree
					let tree = new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);

					// Fetch random member from the tree
					let index = rand::rng().random_range(0..num_members as u32);

					// Initialize proof inputs
					let root = tree.root();
					let leaf_hash = members.get(index as usize).unwrap().hash::<LeafHash>(&leaf_crh_params);
					let path = tree.generate_proof(index as usize).unwrap();

					// Initialize circuit constraints struct for merkle tree
					let circuit = MerkleTreeCircuit {
						leaf_crh_params: leaf_crh_params.clone(),
						two_to_one_crh_params: two_to_one_crh_params.clone(),
						root,
						leaf_hash,
						authentication_path: Some(path),
					};
					circuit.clone().generate_constraints(cs.clone()).unwrap();


					c.bench_function(
						format!("{}_rec_{}_marlin_prove", stringify!($curve), num_members).as_str(),
						|b| {
							b.iter(|| {
								let proof = MarlinM::prove(&pk.clone(), circuit.clone(), &mut rng).unwrap();
								black_box(proof);
							});
						},
					);

					let proof = MarlinM::prove(&pk.clone(), circuit.clone(), &mut rng).unwrap();
					let public_inputs = vec![root, leaf_hash];

					c.bench_function(
						format!("{}_rec_{}_marlin_verify", stringify!($curve), num_members).as_str(),
						|b| {
							b.iter(|| {
								let is_valid =
									MarlinM::verify(&vk.clone(), &public_inputs, &proof, &mut rng).unwrap();
								assert!(is_valid);
							});
						},
					);

				}
			}
		}
    };
}
