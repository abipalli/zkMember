use crate::member::Member;
use ark_crypto_primitives::crh::constraints::{CRHGadget, TwoToOneCRHGadget};
use ark_crypto_primitives::crh::injective_map::constraints::{
    PedersenCRHCompressorGadget, TECompressorGadget,
};
use ark_crypto_primitives::crh::TwoToOneCRH;
use ark_crypto_primitives::crh::{
    injective_map::{PedersenCRHCompressor, TECompressor},
    pedersen,
};
use ark_crypto_primitives::merkle_tree::Config;
use ark_crypto_primitives::{MerkleTree, Path, CRH};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};

/////////////////////////////

pub type ConstraintF = ark_ed_on_bls12_381::Fq;

/////////////////////////////

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 128;
}

pub type TwoToOneHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;
pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;

pub type TwoToOneHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    TwoToOneWindow,
    EdwardsVar,
    TECompressorGadget,
>;

/////////////////////////////

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LeafWindow;
impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 144;
}

pub type LeafHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, LeafWindow>;

pub type LeafHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    LeafWindow,
    EdwardsVar,
    TECompressorGadget,
>;

/////////////////////////////

pub type LeafHashParamsVar = <LeafHashGadget as CRHGadget<LeafHash, ConstraintF>>::ParametersVar;

pub type TwoToOneHashParamsVar =
    <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::ParametersVar;

/////////////////////////////

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleConfig;
impl Config for MerkleConfig {
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

pub type MerklePath = Path<MerkleConfig>;

pub type MembershipTree = MerkleTree<MerkleConfig>;

pub fn new_membership_tree(
    leaf_crh_params: &<LeafHash as CRH>::Parameters,
    two_to_one_crh_params: &<TwoToOneHash as CRH>::Parameters,
    members: &Vec<Member>,
) -> MembershipTree {
    MembershipTree::new(
        leaf_crh_params,
        two_to_one_crh_params,
        clean_members_list(members).as_slice(),
    )
    .unwrap()
}

fn clean_members_list(members: &Vec<Member>) -> Vec<Member> {
    let num_members = members.len();
    let num_empty = if num_members == 1 {
        1
    } else {
        num_members.next_power_of_two() - num_members
    };

    let mut cleaned_members_list = members.clone();
    cleaned_members_list.append(&mut vec![Member::default(); num_empty]);

    cleaned_members_list
}

#[cfg(test)]
mod membership_tree_tests {
    use super::clean_members_list as new_membership_tree;
    use crate::{
        member::Member,
        pedersen381::common::{LeafHash, MembershipTree, MerkleConfig, MerklePath, TwoToOneHash},
    };
    use ark_crypto_primitives::MerkleTree;

    #[test]
    fn one() {
        let cleaned_list = new_membership_tree(&vec![Member::default()]);
        assert!(cleaned_list.len().next_power_of_two() == 2)
    }

    #[test]
    fn two() {
        let cleaned_list = new_membership_tree(&vec![Member::default(), Member::default()]);
        assert!(cleaned_list.len().next_power_of_two() == 2)
    }

    #[test]
    fn three() {
        let cleaned_list = new_membership_tree(&vec![
            Member::default(),
            Member::default(),
            Member::default(),
        ]);
        assert!(cleaned_list.len() == 4)
    }

    #[test]
    fn merkle_tree() {
        use ark_crypto_primitives::crh::CRH;

        let mut rng = ark_std::test_rng();

        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as CRH>::setup(&mut rng).unwrap();

        let members = [
            Member::new("1".into(), "1@usc.edu".into(), None),
            Member::new("2".into(), "2@usc.edu".into(), None),
        ];

        let tree: MerkleTree<MerkleConfig> =
            MembershipTree::new::<Member>(&leaf_crh_params, &two_to_one_crh_params, &members)
                .unwrap();

        let path: MerklePath = tree.generate_proof(1).unwrap();
        let root = tree.root();

        // Next, let's verify the proof!
        let result = path
            .verify(
                &leaf_crh_params,
                &two_to_one_crh_params,
                &root,
                &members[1], // The claimed leaf
            )
            .unwrap();

        assert!(result);
    }
}
