#[macro_export]
macro_rules! bench_groth16 {
    ($module:ident, $curve:ident, $num_members:expr) => {
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
            const TEST_MEMBERS_COUNT: usize = $num_members as usize;

            let mut rng = ark_std::test_rng();

            let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
            let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

            // Generate mock members
            let mut members = Box::new(vec![]);
            generate_members(&mut members, TEST_MEMBERS_COUNT as u32);

            // Hash mock members
            let mut leaves = members
                .iter()
                .map(|member| member.hash::<LeafHash>(&leaf_crh_params))
                .collect::<Vec<_>>();

            // Construct membership Merkle tree
            let tree = new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);
            let root = tree.root();

            // Fetch random member from the tree
            let index = black_box(rand::rng().random_range(0..TEST_MEMBERS_COUNT as u32));
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
    };
}

#[macro_export]
macro_rules! bench_marlin {
    ($module:ident, $curve:ident, $num_members:expr) => {
        // use $module::{
        //     common::{new_membership_tree, LeafHash, TwoToOneHash},
        //     constraint::MerkleTreeCircuit,
        // };

        // use ark_crypto_primitives::crh::{TwoToOneCRH, CRH};
        use ark_marlin::Marlin;
        use ark_poly::univariate::DensePolynomial;
        use ark_poly_commit::marlin_pc::MarlinKZG10;

        pub fn bench_marlin(c: &mut Criterion) {
            const TEST_MEMBERS_COUNT: usize = $num_members as usize;

            let mut rng = ark_std::test_rng();

            let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
            let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

            // Generate mock members
            let mut members = Box::new(vec![]);
            generate_members(&mut members, TEST_MEMBERS_COUNT as u32);

            // Hash mock members
            let mut leaves = members
                .iter()
                .map(|member| member.hash::<LeafHash>(&leaf_crh_params))
                .collect::<Vec<_>>();

            // Construct membership Merkle tree
            let tree = new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);
            let root = tree.root();

            // Fetch random member from the tree
            let index = black_box(rand::rng().random_range(0..TEST_MEMBERS_COUNT as u32));
            let path = black_box(tree.generate_proof(index as usize).unwrap());
            let member: &Member = members.get(index as usize).unwrap();

            // Initialize circuit constraints struct for merkle tree
            let circuit = MerkleTreeCircuit {
                leaf_crh_params: &leaf_crh_params,
                two_to_one_crh_params: &two_to_one_crh_params,
                root,
                leaf_hash: member.hash::<LeafHash>(&leaf_crh_params),
                authentication_path: Some(path),
            };

            type MarlinInst = Marlin<
                $curve,
                DensePolynomial<<$curve as ark_ec::PairingEngine>::Fr>,
                MarlinKZG10<$curve, DensePolynomial<<$curve as ark_ec::PairingEngine>::Fr>>,
            >;

            let universal_srs =
                MarlinInst::universal_setup(TEST_MEMBERS_COUNT, 2, 2, &mut rng).unwrap();
            let (pk, vk) = MarlinInst::index(&universal_srs, circuit.clone()).unwrap();

            c.bench_function(
                format!("{}_marlin_prove", stringify!($curve)).as_str(),
                |b| {
                    b.iter(|| {
                        let proof = MarlinInst::prove(&pk, circuit.clone(), &mut rng).unwrap();
                        black_box(proof);
                    });
                },
            );

            let proof = MarlinInst::prove(&pk, circuit, &mut rng).unwrap();
            let public_input = vec![root, member.hash::<LeafHash>(&leaf_crh_params)];

            c.bench_function(
                format!("{}_marlin_verify", stringify!($curve)).as_str(),
                |b| {
                    b.iter(|| {
                        let is_valid =
                            MarlinInst::verify(&vk, &public_input, &proof, &mut rng).unwrap();
                        assert!(is_valid);
                    });
                },
            );
        }
    };
}
