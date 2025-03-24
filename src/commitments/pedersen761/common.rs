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
use ark_ed_on_bw6_761::{constraints::EdwardsVar, EdwardsProjective};

/////////////////////////////

pub type Pedersen761Field = ark_ed_on_bw6_761::Fq;

/////////////////////////////

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 192;
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
    // Increased from 144 to 256 to accommodate 768 bits (96 bytes) of input
    const NUM_WINDOWS: usize = 192;
}

pub type LeafHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, LeafWindow>;
pub type Leaf = <LeafHash as CRH>::Output;

pub type LeafHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    LeafWindow,
    EdwardsVar,
    TECompressorGadget,
>;

/////////////////////////////

pub type LeafHashParamsVar =
    <LeafHashGadget as CRHGadget<LeafHash, Pedersen761Field>>::ParametersVar;

pub type TwoToOneHashParamsVar =
    <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, Pedersen761Field>>::ParametersVar;

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
    leaves: &mut Vec<Pedersen761Field>,
) -> MembershipTree {
    clean_membership_list(leaf_crh_params, leaves);
    MembershipTree::new(leaf_crh_params, two_to_one_crh_params, leaves.as_ref()).unwrap()
}

fn clean_membership_list(
    leaf_crh_params: &<LeafHash as CRH>::Parameters,
    leaves: &mut Vec<Pedersen761Field>,
) {
    let leaf_crh_params: &<LeafHash as CRH>::Parameters = &leaf_crh_params;
    let num_members = leaves.len();

    let num_needed = if num_members == 1 {
        1
    } else {
        num_members.next_power_of_two() - num_members
    };

    leaves.append(&mut vec![
        <LeafHash as CRH>::evaluate(
            leaf_crh_params,
            Member::default().to_bytes().as_slice(),
        )
        .unwrap();
        num_needed
    ]);
}

#[cfg(test)]
mod membership_tree_tests {
    use crate::{
        member::Member,
        pedersen761::common::{
            clean_membership_list, new_membership_tree, LeafHash, MerkleConfig, MerklePath,
            TwoToOneHash,
        },
    };
    use ark_crypto_primitives::{MerkleTree, CRH};

    fn setup() -> (
        <LeafHash as CRH>::Parameters,
        <TwoToOneHash as CRH>::Parameters,
    ) {
        let mut rng = ark_std::test_rng();
        let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as CRH>::setup(&mut rng).unwrap();
        (leaf_crh_params, two_to_one_crh_params)
    }

    #[test]
    fn one_leaf() {
        let params = setup().0;

        let members = &vec![Member::default()];
        let mut leaves = members
            .iter()
            .map(|member| <LeafHash as CRH>::evaluate(&params, &member.to_bytes()).unwrap())
            .collect::<Vec<_>>();

        clean_membership_list(&params, &mut leaves);
        assert!(leaves.len().next_power_of_two() == 2)
    }

    #[test]
    fn two_leaves() {
        let params = setup().0;

        let members = vec![Member::default(), Member::default()];
        let mut leaves = members
            .iter()
            .map(|member| <LeafHash as CRH>::evaluate(&params, &member.to_bytes()).unwrap())
            .collect::<Vec<_>>();

        clean_membership_list(&params, &mut leaves);
        assert_eq!(leaves.len(), 2); // Already a power of two, no additional elements should be added
    }

    #[test]
    fn three_leaves() {
        let params = setup().0;

        let members = vec![Member::default(), Member::default(), Member::default()];
        let mut leaves = members
            .iter()
            .map(|member| <LeafHash as CRH>::evaluate(&params, &member.to_bytes()).unwrap())
            .collect::<Vec<_>>();

        clean_membership_list(&params, &mut leaves);
        assert_eq!(leaves.len(), 4); // Should add 1 more element to make it a power of two
    }

    #[test]
    fn merkle_tree() {
        use ark_crypto_primitives::crh::CRH;

        let (leaf_crh_params, two_to_one_crh_params) = setup();

        let members = [
            Member::new("1".into(), "1@usc.edu".into(), None),
            Member::new("2".into(), "2@usc.edu".into(), None),
        ];
        let leaves = members.clone().map(|member| {
            <LeafHash as CRH>::evaluate(&leaf_crh_params, &member.to_bytes()).unwrap()
        });

        let tree: MerkleTree<MerkleConfig> = new_membership_tree(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &mut leaves.to_vec(),
        );

        let root = tree.root();
        let path: MerklePath = tree.generate_proof(1).unwrap();

        // Next, let's verify the proof!
        let result = path
            .verify(
                &leaf_crh_params,
                &two_to_one_crh_params,
                &root,
                &<LeafHash as CRH>::evaluate(&leaf_crh_params, &members[1].to_bytes()).unwrap(), // The claimed leaf
            )
            .unwrap();

        assert!(result);
    }
}
