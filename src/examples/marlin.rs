use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::{crh::TwoToOneCRH, CRH};
use ark_marlin::Marlin;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use blake2::Blake2s;

use crate::commitments::pedersen381::{
    common::{
        new_membership_tree, LeafHash, MembershipTree, MerklePath, Pedersen381Field, Root,
        TwoToOneHash,
    },
    MerkleTreeCircuit,
};

type PC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
type MarlinM = Marlin<Fr, PC, Blake2s>;

#[test]
fn create_test_circuit() {
    let mut rng = ark_std::test_rng();

    // Setup CRH params
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // Generate members
    let mut members = Box::new(vec![]);
    crate::member::generate_members(&mut members, 4);

    // Hash each member to get leaves
    let mut leaves: Vec<_> = members
        .iter()
        .map(|m| m.hash::<LeafHash>(&leaf_crh_params))
        .collect();

    // Create tree
    let tree: MembershipTree =
        new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);
    let root = tree.root();

    // Prove inclusion of member at index 2
    let index = rand::random_range(..4);
    let path: MerklePath = tree.generate_proof(index).unwrap();
    let member_hash = members[index].hash::<LeafHash>(&leaf_crh_params);

    // Build circuit
    let circuit = MerkleTreeCircuit {
        leaf_crh_params: leaf_crh_params.clone(),
        two_to_one_crh_params: two_to_one_crh_params,
        root,
        leaf_hash: member_hash,
        authentication_path: Some(path),
    };

    /* 4.a  Count constraints to know how big the SRS must be  */
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();

    // NOTE: Correctness requires every later circuit to satisfy:
    //	- rows ≤ num_constraints
    let n_constraints = cs.num_constraints();
    //	- vars ≤ num_variables
    let n_variables = cs.num_instance_variables() + cs.num_witness_variables();
    //	- non-zeros ≤ num_non_zero
    let n_non_zero = 5 * n_constraints;

    /* 4.b  Universal setup (re‑use it for all trees of the same depth)           */
    let srs = MarlinM::universal_setup(
        n_constraints.next_power_of_two(), // round up   ▸ security proof assumes power‑of‑two
        n_variables.next_power_of_two(),
        n_non_zero.next_power_of_two(),
        &mut rng,
    )
    .unwrap();

    // One-time setup for the circuit
    let (pk, vk) = MarlinM::index(&srs, circuit.clone()).unwrap();

    let proof = MarlinM::prove(&pk, circuit.clone(), &mut rng).unwrap();

    let inputs = public_inputs(&root, &member_hash);

    assert!(MarlinM::verify(&vk, &inputs, &proof, &mut rng).unwrap());
}

fn public_inputs(root: &Root, leaf: &Pedersen381Field) -> Vec<Pedersen381Field> {
    vec![root.clone(), leaf.clone()]
}
