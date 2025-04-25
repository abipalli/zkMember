#[cfg(all(feature = "pedersen381", feature = "pedersen761"))]
compile_error!("Cannot enable both pedersen381 and pedersen761 features at the same time.");

pub mod pedersen381;
pub mod pedersen761;

#[cfg(feature = "generic")]
use ark_crypto_primitives::{crh::TwoToOneCRH, merkle_tree::Config, Path, CRH};
#[cfg(feature = "generic")]
use ark_ff::Field as FiniteField;

#[cfg(feature = "generic")]
#[derive(Clone)]
pub struct GenericMerkleTreeCircuit<Field, LeafHash, TwoToOneHash, MerkleConfig>
where
    Field: FiniteField,
    LeafHash: ark_crypto_primitives::crh::CRH,
    TwoToOneHash: ark_crypto_primitives::crh::TwoToOneCRH,
    MerkleConfig: Config,
{
    // public constants
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    // public inputs
    pub root: <TwoToOneHash as TwoToOneCRH>::Output,
    pub leaf_hash: Field,

    // private witness
    pub authentication_path: Option<Path<MerkleConfig>>,
}
