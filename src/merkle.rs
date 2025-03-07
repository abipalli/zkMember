use ark_crypto_primitives::{crh::TwoToOneCRH, merkle_tree::Config, MerkleTree, Path};

use crate::{
    crypto::{LeafHash, TwoToOneHash},
    member::Member,
};

#[derive(Clone)]
pub struct MerkleConfig;
impl Config for MerkleConfig {
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

pub type MembershipTree = MerkleTree<MerkleConfig>;
pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;
pub type SimplePath = Path<MerkleConfig>;

#[test]
fn test_merkle_tree() {
    use ark_crypto_primitives::crh::CRH;

    let mut rng = ark_std::test_rng();

    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as CRH>::setup(&mut rng).unwrap();

    let members = [
        Member::new("1", "1@usc.edu", None),
        Member::new("2", "2@usc.edu", None),
    ];

    let tree: MerkleTree<MerkleConfig> =
        MembershipTree::new::<Member>(&leaf_crh_params, &two_to_one_crh_params, &members).unwrap();

    let proof: Path<MerkleConfig> = tree.generate_proof(1).unwrap();
    let root = tree.root();

    // Next, let's verify the proof!
    let result = proof
        .verify(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &members[1], // The claimed leaf
        )
        .unwrap();

    assert!(result);
}
