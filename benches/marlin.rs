use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

#[macro_use]
mod macros;

mod marlin381 {
    use ark_bls12_381::{Bls12_381, Fr};
    use zkmember::commitments::pedersen381;

    bench_marlin!(pedersen381, Bls12_381, Fr, 20);
}

mod marlin761 {
    use ark_bw6_761::{Fr, BW6_761};
    pub use zkmember::commitments::pedersen761;

    bench_marlin!(pedersen761, BW6_761, Fr, 20);
}

fn criterion_config(measurement_secs: u64) -> Criterion {
    Criterion::default()
        .measurement_time(Duration::from_secs(measurement_secs))
        .sample_size(10)
}

criterion_group! {
    name = marlin381_benches;
    config = criterion_config(30);
    targets = marlin381::bench_marlin
}
criterion_group! {
    name = marlin761_benches;
    config = criterion_config(30);
    targets = marlin761::bench_marlin
}

criterion_main!(marlin381_benches, marlin761_benches);
