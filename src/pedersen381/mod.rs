pub mod common;
pub mod constraint;

#[cfg(test)]
mod groth16_tests {
    use super::common::*;
    use super::constraint::*;
    use crate::member::Member;
    use ark_bls12_381::Bls12_381;
    use ark_crypto_primitives::{MerkleTree, CRH, SNARK};
    use ark_ff::Fp256;
    use ark_groth16::Groth16;
    use ark_std::rand::RngCore;

    #[test]
    fn test_groth16_snark() {
        // Set up RNG
        let mut rng = ark_std::test_rng();

        // Generate CRH parameters
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as CRH>::setup(&mut rng).unwrap();

        // Create some test members
        let members = vec![
            Member::new("alice".into(), "alice@usc.edu".into(), None),
            Member::new("bob".into(), "bob@usc.edu".into(), None),
            Member::new("carol".into(), "carol@usc.edu".into(), None),
        ];

        // Create Merkle tree
        let tree = new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &members);
        let root = tree.root();

        // Generate proof for bob (index 1)
        let merkle_path = tree.generate_proof(1).unwrap();

        // Create circuit
        let circuit = MerkleTreeCircuit {
            leaf_crh_params: &leaf_crh_params,
            two_to_one_crh_params: &two_to_one_crh_params,
            root,
            leaf: &members[1],
            authentication_path: Some(merkle_path),
        };

        // Generate proving and verifying keys
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng)
            .expect("setup failed");

        // Create the proof
        let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng)
            .expect("proof generation failed");

        // Calculate public inputs
        let mut public_inputs = vec![root];
        let member_bytes = members[1].to_bytes();
        let member_field_elements: Vec<Fp256<ark_ed_on_bls12_381::FqParameters>> = member_bytes
            .iter()
            .map(|&byte| Fp256::from(byte as u64))
            .collect();
        public_inputs.extend_from_slice(&member_field_elements);

        // Verify the proof
        let verified =
            Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof).expect("verification failed");

        assert!(verified, "SNARK proof verification failed");
    }
}
