use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

#[macro_use]
mod macros;

// Conditional imports for pedersen modules
mod pedersen381 {
    use ark_bls12_381::Bls12_381;
    use zkmember::commitments::pedersen381;

    bench_groth16!(pedersen381, Bls12_381, 1000);
}

// Conditional curve import/alias
mod pedersen761 {
    use ark_bw6_761::BW6_761;
    pub use zkmember::commitments::pedersen761;

    bench_groth16!(pedersen761, BW6_761, 1000);
}

fn criterion_config(measurement_secs: u64) -> Criterion {
    Criterion::default()
        .measurement_time(Duration::from_secs(measurement_secs))
        .sample_size(10)
}

criterion_group! {
    name = pedersen381_benches;
    config = criterion_config(30);
    targets = pedersen381::bench_groth16
}
criterion_group! {
    name = pedersen761_benches;
    config = criterion_config(30);
    targets = pedersen761::bench_groth16
}
criterion_main!(pedersen381_benches, pedersen761_benches);
