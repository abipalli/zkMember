use std::sync::Arc;

use ark_crypto_primitives::{
    crh::{CRHGadget, TwoToOneCRH, TwoToOneCRHGadget},
    PathVar, CRH,
};
use zkmember::commitments::MerkleTreeCircuit;

use criterion::{criterion_group, criterion_main, Criterion};

// Conditional imports for pedersen modules
#[cfg(feature = "pedersen381")]
mod pedersen381 {
    pub use zkmember::commitments::pedersen381::{
        common::{
            LeafHash as LeafHash381, MerkleConfig as Merkle381Config, Pedersen381Field,
            Root as Root381, TwoToOneHash as TwoToOneHash381,
        },
        constraint::MerkleTreeCircuit as MerkleTreeCircuit381,
    };
}
#[cfg(feature = "pedersen381")]
use pedersen381::*;

// Conditional curve import/alias
#[cfg(feature = "pedersen761")]
mod pedersen761 {
    pub use ark_bw6_761::BW6_761;
    pub use zkmember::commitments::pedersen761::{
        common::{
            LeafHash as LeafHash761, MerkleConfig as Merkle761Config, Pedersen761Field,
            Root as Root761, TwoToOneHash as TwoToOneHash761,
        },
        constraint::MerkleTreeCircuit as MerkleTreeCircuit761,
    };
    pub type Curve = BW6_761;
}
#[cfg(feature = "pedersen761")]
use pedersen761::*;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("MerkleTreeCircuit::new", |b| {
        b.iter(|| {
            let mut rng = ark_std::test_rng();

            let leaf_crh_params = <LeafHash381 as CRH>::setup(&mut rng).unwrap();
            let two_to_one_crh_params = <TwoToOneHash381 as TwoToOneCRH>::setup(&mut rng).unwrap();

            let circuit = Arc::new(MerkleTreeCircuit::<
                Pedersen381Field,
                LeafHash381,
                TwoToOneHash381,
                Merkle381Config,
            > {
                leaf_crh_params: &leaf_crh_params,
                two_to_one_crh_params: &two_to_one_crh_params,
                root: Root381::default(),
                leaf_hash: Pedersen381Field::default(),
                authentication_path: None,
            });
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
