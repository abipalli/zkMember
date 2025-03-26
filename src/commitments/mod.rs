pub mod pedersen381;
pub mod pedersen761;

use ark_crypto_primitives::crh::TwoToOneCRH;
use ark_crypto_primitives::merkle_tree::Config;
use ark_crypto_primitives::{Path, CRH};
use ark_ff::Field as FiniteField;

#[derive(Clone)]
pub struct MerkleTreeCircuit<'a, Field, LeafHash, TwoToOneHash, MerkleConfig>
where
    Field: FiniteField,
    LeafHash: ark_crypto_primitives::crh::CRH,
    TwoToOneHash: ark_crypto_primitives::crh::TwoToOneCRH,
    MerkleConfig: Config,
{
    // public constants
    pub leaf_crh_params: &'a <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: &'a <TwoToOneHash as TwoToOneCRH>::Parameters,

    // public inputs
    pub root: <TwoToOneHash as TwoToOneCRH>::Output,
    pub leaf_hash: Field,

    // private witness
    pub authentication_path: Option<Path<MerkleConfig>>,
}
