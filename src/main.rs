use zkmember::member::{generate_members, Member};

// Conditional imports for pedersen modules
#[cfg(feature = "pedersen381")]
mod pedersen381 {
    pub use ark_bls12_381::{Bls12_381, Fr};
    pub use zkmember::commitments::pedersen381::{
        new_membership_tree, LeafHash, MerkleTreeCircuit, Pedersen381Field as PedersenField, Root,
        TwoToOneHash,
    };
    pub type Curve = Bls12_381;
}

#[cfg(feature = "pedersen381")]
use pedersen381::*;

// Conditional curve import/alias
#[cfg(feature = "pedersen761")]
mod pedersen761 {
    pub use ark_bw6_761::{Fr, BW6_761};
    pub use zkmember::commitments::pedersen761::{
        new_membership_tree, LeafHash, MerkleTreeCircuit, Pedersen761Field as PedersenField, Root,
        TwoToOneHash,
    };
    pub type Curve = BW6_761;
}
#[cfg(feature = "pedersen761")]
use pedersen761::*;

// #[cfg(any(feature = "pedersen381", feature = "pedersen761"))]
fn exec_marlin(num_members: usize) {
    use ark_crypto_primitives::crh::{TwoToOneCRH, CRH};
    use ark_marlin::Marlin;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly_commit::marlin_pc::MarlinKZG10;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use blake2::Blake2s;
    use rand::Rng;

    type PC = MarlinKZG10<Curve, DensePolynomial<Fr>>;
    type MarlinM = Marlin<Fr, PC, Blake2s>;

    let mut rng = ark_std::test_rng();

    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // Generate members
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
    let index = rand::rng().random_range(0..num_members as u32);
    let path = tree.generate_proof(index as usize).unwrap();
    let member: &Member = members.get(index as usize).unwrap();

    // Initialize circuit constraints struct for merkle tree
    let circuit = MerkleTreeCircuit {
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_crh_params: two_to_one_crh_params,
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

    let srs = MarlinM::universal_setup(
        n_constraints.next_power_of_two(), // round up   ▸ security proof assumes power‑of‑two
        n_variables.next_power_of_two(),
        n_non_zero.next_power_of_two(),
        &mut rng,
    )
    .unwrap();

    let (pk, vk) = MarlinM::index(&srs, circuit.clone()).unwrap();

    let proof = MarlinM::prove(&pk.clone(), circuit.clone(), &mut rng).unwrap();

    let proof = MarlinM::prove(&pk, circuit, &mut rng).unwrap();
    let public_input = vec![root, member.hash::<LeafHash>(&leaf_crh_params)];

    let is_valid = MarlinM::verify(&vk.clone(), &public_input, &proof, &mut rng).unwrap();
    assert!(is_valid);
}

pub fn main() {
    exec_marlin(16);
}
