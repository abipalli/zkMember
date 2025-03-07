use ark_crypto_primitives::{crh::TwoToOneCRH, merkle_tree::Config, MerkleTree, Path};

use crate::crypto::{LeafHash, TwoToOneHash};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleConfig;
impl Config for MerkleConfig {
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

#[allow(dead_code)]
pub type MembershipTree = MerkleTree<MerkleConfig>;

pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;
pub type SimplePath = Path<MerkleConfig>;

#[test]
fn test_merkle_tree() {
    use crate::member::Member;
    use ark_crypto_primitives::crh::CRH;

    let mut rng = ark_std::test_rng();

    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as CRH>::setup(&mut rng).unwrap();

    let members = [
        Member::new("1".into(), "1@usc.edu".into(), None),
        Member::new("2".into(), "2@usc.edu".into(), None),
    ];

    let tree: MerkleTree<MerkleConfig> =
        MembershipTree::new::<Member>(&leaf_crh_params, &two_to_one_crh_params, &members).unwrap();

    let path: SimplePath = tree.generate_proof(1).unwrap();
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
