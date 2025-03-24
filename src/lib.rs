pub mod commitments;
pub mod member;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CurveType {
    BLS12_381,
    BW6_761,
}

impl Default for CurveType {
    fn default() -> Self {
        CurveType::BLS12_381
    }
}

use std::sync::atomic::{AtomicU8, Ordering};

static CURRENT_CURVE: AtomicU8 = AtomicU8::new(0); // 0 = BLS12_381, 1 = BW6_761

pub fn set_global_curve(curve_type: CurveType) {
    CURRENT_CURVE.store(
        match curve_type {
            CurveType::BLS12_381 => 0,
            CurveType::BW6_761 => 1,
        },
        Ordering::SeqCst,
    );
}

pub fn get_global_curve() -> CurveType {
    match CURRENT_CURVE.load(Ordering::SeqCst) {
        0 => CurveType::BLS12_381,
        1 => CurveType::BW6_761,
        _ => CurveType::BLS12_381, // Default
    }
}
