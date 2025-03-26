use super::common::{
    LeafHash, LeafHashGadget, LeafHashParamsVar, MerkleConfig, MerklePath, Pedersen761Field, Root,
    TwoToOneHash, TwoToOneHashGadget, TwoToOneHashParamsVar,
};
use ark_crypto_primitives::{
    crh::{CRHGadget, TwoToOneCRH, TwoToOneCRHGadget},
    PathVar, CRH,
};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::{eq::EqGadget, prelude::Boolean};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};

/// R1CS representation of the Merkle tree root.
pub type PedersenRootVar =
    <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, Pedersen761Field>>::OutputVar;

pub type PedersenLeafVar = <LeafHashGadget as CRHGadget<LeafHash, Pedersen761Field>>::OutputVar;

/// R1CS representation of the Merkle tree path.
pub type PedersenPathVar =
    PathVar<MerkleConfig, LeafHashGadget, TwoToOneHashGadget, Pedersen761Field>;

#[derive(Clone)]
pub struct MerkleTreeCircuit<'a> {
    // constants that will be embedded into the circuit
    pub leaf_crh_params: &'a <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: &'a <TwoToOneHash as TwoToOneCRH>::Parameters,

    // These are the public inputs to the circuit
    pub root: Root,
    pub leaf_hash: Pedersen761Field,

    // This is the private witness to the circuit
    pub authentication_path: Option<MerklePath>,
}

impl<'a> ConstraintSynthesizer<Pedersen761Field> for MerkleTreeCircuit<'a> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Pedersen761Field>,
    ) -> ark_relations::r1cs::Result<()> {
        // Allocate parameters as constants
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), self.two_to_one_crh_params)?;

        // Allocate public inputs
        let root =
            PedersenRootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;

        let hashed_leaf: PedersenLeafVar =
            PedersenLeafVar::new_input(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf_hash))?;

        // Allocate path as witness
        let path: PedersenPathVar =
            PedersenPathVar::new_witness(ark_relations::ns!(cs, "path_witness"), || {
                self.authentication_path
                    .as_ref()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let is_member: Boolean<Pedersen761Field> = path.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &hashed_leaf,
        )?;

        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

// impl<'a> ConstraintSynthesizer<Pedersen761Field>
//     for CommonMerkleTreeCircuit<'a, LeafHash, TwoToOneHash, Root, Pedersen761Field, MerkleConfig>
// {
//     fn generate_constraints(
//         self,
//         cs: ark_relations::r1cs::ConstraintSystemRef<Pedersen761Field>,
//     ) -> ark_relations::r1cs::Result<()> {
//         // Allocate parameters as constants
//         let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), self.leaf_crh_params)?;
//         let two_to_one_crh_params =
//             TwoToOneHashParamsVar::new_constant(cs.clone(), self.two_to_one_crh_params)?;

//         // Allocate public inputs
//         let root =
//             PedersenRootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;

//         let hashed_leaf: PedersenLeafVar =
//             PedersenLeafVar::new_input(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf_hash))?;

//         // Allocate path as witness
//         let path: PedersenPathVar =
//             PedersenPathVar::new_witness(ark_relations::ns!(cs, "path_witness"), || {
//                 self.authentication_path
//                     .as_ref()
//                     .ok_or(SynthesisError::AssignmentMissing)
//             })?;

//         let is_member: Boolean<Pedersen761Field> = path.verify_membership(
//             &leaf_crh_params,
//             &two_to_one_crh_params,
//             &root,
//             &hashed_leaf,
//         )?;

//         is_member.enforce_equal(&Boolean::TRUE)?;

//         Ok(())
//     }
// }

#[cfg(test)]
mod tests {
    use ark_crypto_primitives::{crh::TwoToOneCRH, CRH};
    use ark_relations::r1cs::ConstraintSynthesizer;

    use crate::{
        commitments::pedersen761::{
            common::{LeafHash, MembershipTree, MerkleConfig, MerklePath, TwoToOneHash},
            constraint::MerkleTreeCircuit,
        },
        member::Member,
    };

    #[test]
    fn merkle_tree_constraints_correctness() {
        use ark_crypto_primitives::MerkleTree;
        use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
        use tracing_subscriber::layer::SubscriberExt;

        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let mut rng = ark_std::test_rng();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Next, let's construct our tree.
        let members = [
            Member::new("1".into(), "1@usc.edu".into(), None),
            Member::new("2".into(), "2@usc.edu".into(), None),
        ];

        let leaves = members
            .clone()
            .map(|member| member.hash::<LeafHash>(&leaf_crh_params));

        let tree: MerkleTree<MerkleConfig> =
            MerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, &leaves).unwrap();

        // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
        let path: MerklePath = tree.generate_proof(1).unwrap();

        // First, let's get the root we want to verify against:
        let root = tree.root();

        let circuit = MerkleTreeCircuit {
            // constants
            leaf_crh_params: &leaf_crh_params,
            two_to_one_crh_params: &two_to_one_crh_params,

            // public inputs
            root,
            leaf_hash: members[1].hash::<LeafHash>(&leaf_crh_params),

            // witness
            authentication_path: Some(path),
        };

        // First, some boilerplat that helps with debugging
        let mut layer = ConstraintLayer::default();
        layer.mode = TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // Next, let's make the circuit!
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("Public inputs: {}", cs.num_instance_variables());
        println!("Private witnesses: {}", cs.num_witness_variables());
        println!("Total constraints: {}", cs.num_constraints());

        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        if !is_satisfied {
            // If it isn't, find out the offending constraint.
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(is_satisfied);
    }

    #[test]
    fn merkle_tree_constraints_soundness() {
        use ark_relations::r1cs::ConstraintSystem;

        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let mut rng = ark_std::test_rng();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

        // Next, let's construct our tree.
        let organization1 = [
            Member::new("1".into(), "1@usc.edu".into(), None),
            Member::new("2".into(), "2@usc.edu".into(), None),
            Member::new("3".into(), "3@usc.edu".into(), None),
            Member::new("4".into(), "4@usc.edu".into(), None),
            Member::new("5".into(), "5@usc.edu".into(), None),
            Member::new("6".into(), "6@usc.edu".into(), None),
            Member::new("7".into(), "7@usc.edu".into(), None),
            Member::new("8".into(), "8@usc.edu".into(), None),
        ];

        let organization2 = [
            Member::new("9".into(), "9@usc.edu".into(), None),
            Member::new("2".into(), "2@usc.edu".into(), None),
            Member::new("3".into(), "3@usc.edu".into(), None),
            Member::new("4".into(), "4@usc.edu".into(), None),
            Member::new("5".into(), "5@usc.edu".into(), None),
            Member::new("6".into(), "6@usc.edu".into(), None),
            Member::new("7".into(), "7@usc.edu".into(), None),
            Member::new("8".into(), "8@usc.edu".into(), None),
        ];

        let org1_leaves = organization1
            .clone()
            .map(|m| <LeafHash as CRH>::evaluate(&leaf_crh_params, &m.to_bytes()).unwrap());
        let org2_leaves = organization2
            .clone()
            .map(|m| <LeafHash as CRH>::evaluate(&leaf_crh_params, &m.to_bytes()).unwrap());
        let tree =
            MembershipTree::new(&leaf_crh_params, &two_to_one_crh_params, &org1_leaves).unwrap();

        // We just mutate the first leaf
        let second_tree =
            MembershipTree::new(&leaf_crh_params, &two_to_one_crh_params, &org2_leaves).unwrap();

        let proof = tree.generate_proof(4).unwrap();

        // But, let's get the root we want to verify against:
        let wrong_root = second_tree.root();

        let circuit = MerkleTreeCircuit {
            // constants
            leaf_crh_params: &leaf_crh_params,
            two_to_one_crh_params: &two_to_one_crh_params,

            // public inputs
            root: wrong_root,
            leaf_hash: Member::new("5".into(), "5@usc.edu".into(), None)
                .hash::<LeafHash>(&leaf_crh_params),

            // witness
            authentication_path: Some(proof),
        };

        // First, let's make the constraint system!
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("Public inputs: {}", cs.num_instance_variables());
        println!("Private witnesses: {}", cs.num_witness_variables());
        println!("Total constraints: {}", cs.num_constraints());

        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        // We expect this to fail!
        assert!(!is_satisfied);
    }
}
