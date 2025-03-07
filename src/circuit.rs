use ark_crypto_primitives::{
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
    MerkleTree, PathVar, CRH,
};
use ark_r1cs_std::{eq::EqGadget, prelude::Boolean, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::seq::SliceRandom;

use crate::{
    crypto::{
        ConstraintF, LeafHash, LeafHashGadget, LeafHashParamsVar, TwoToOneHash, TwoToOneHashGadget,
        TwoToOneHashParamsVar,
    },
    member::Member,
    merkle::{MembershipTree, MerkleConfig, Root, SimplePath},
};

/// R1CS representation of the Merkle tree root.
pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::OutputVar;

/// R1CS representation of the Merkle tree path.
pub type SimplePathVar = PathVar<MerkleConfig, LeafHashGadget, TwoToOneHashGadget, ConstraintF>;

////////////////////////////////////////////////////////////////////////////////

pub struct MerkleTreeVerification<'a> {
    // constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    // These are the public inputs to the circuit
    pub root: Root,
    pub leaf: Member<'a>,

    // This is the private witness to the circuit
    pub authentication_path: Option<SimplePath>,
}

use ark_r1cs_std::alloc::AllocVar;
impl<'a> ConstraintSynthesizer<ConstraintF> for MerkleTreeVerification<'a> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<ConstraintF>,
    ) -> ark_relations::r1cs::Result<()> {
        // Allocate public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;

        let leaf_bytes: Vec<UInt8<ConstraintF>> = self
            .leaf
            .to_bytes()
            .iter()
            .enumerate()
            // .map(|(i, byte)| UInt8::new_input(ark_relations::ns!(cs, &name), || Ok(byte)))
            .map(|(_, byte)| UInt8::new_input(cs.clone(), || Ok(byte)))
            .collect::<Result<Vec<_>, _>>()?;
        let leaf_bytes = leaf_bytes.as_slice();

        // Allocate parameters as constants
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // Allocate path as witness
        let path: SimplePathVar =
            SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
                self.authentication_path
                    .as_ref()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let is_member: Boolean<ConstraintF> =
            path.verify_membership(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf_bytes)?;

        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[test]
fn merkle_tree_constraints_correctness() {
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
        Member::new("1", "1@usc.edu", None),
        Member::new("2", "2@usc.edu", None),
    ];

    let tree: MerkleTree<MerkleConfig> =
        MembershipTree::new::<Member>(&leaf_crh_params, &two_to_one_crh_params, &members).unwrap();

    // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
    let path: SimplePath = tree.generate_proof(1).unwrap();

    // First, let's get the root we want to verify against:
    let root = tree.root();

    let circuit = MerkleTreeVerification {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root,
        leaf: members[1],

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
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    let organization1 = [
        Member::new("1", "1@usc.edu", None),
        Member::new("2", "2@usc.edu", None),
        Member::new("3", "3@usc.edu", None),
        Member::new("4", "4@usc.edu", None),
        Member::new("5", "5@usc.edu", None),
        Member::new("6", "6@usc.edu", None),
        Member::new("7", "7@usc.edu", None),
        Member::new("8", "8@usc.edu", None),
    ];

    let organization2 = [
        Member::new("9", "9@usc.edu", None),
        Member::new("2", "2@usc.edu", None),
        Member::new("3", "3@usc.edu", None),
        Member::new("4", "4@usc.edu", None),
        Member::new("5", "5@usc.edu", None),
        Member::new("6", "6@usc.edu", None),
        Member::new("7", "7@usc.edu", None),
        Member::new("8", "8@usc.edu", None),
    ];

    let tree = crate::MembershipTree::new(&leaf_crh_params, &two_to_one_crh_params, &organization1)
        .unwrap();

    // We just mutate the first leaf
    let second_tree =
        crate::MembershipTree::new(&leaf_crh_params, &two_to_one_crh_params, &organization2)
            .unwrap();

    let proof = tree.generate_proof(4).unwrap();

    // But, let's get the root we want to verify against:
    let wrong_root = second_tree.root();

    let circuit = MerkleTreeVerification {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root: wrong_root,
        leaf: Member::new("5", "5@usc.edu", None),

        // witness
        authentication_path: Some(proof),
    };
    // First, some boilerplate that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    // Next, let's make the constraint system!
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();
    // We expect this to fail!
    assert!(!is_satisfied);
}
