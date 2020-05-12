//! this file is part of the pointproofs.
//! It defines some misc functions.

use pairing::CurveAffine;
use pairings::err::ERR_PARAM;
use pairings::*;
use std::collections::HashSet;
use std::hash::Hash;

/// checks if a slice/vector constains duplicated elements
pub(crate) fn has_unique_elements<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + Hash,
{
    let mut uniq = HashSet::new();
    iter.into_iter().all(move |x| uniq.insert(x))
}

/// This helper computes the sum of product:
///     \sum_{i=start}^{end-1}
///         param.generator[i]^scarlar_u64[i]
/// It tries to use pre-computed data when possible.
/// It assumes end - start = n; and the lengths matches.
/// It doesnot perform any sanity checks of those conditions.
pub(crate) fn pp_sum_of_prod_helper(
    prover_params: &ProverParams,
    scalars_u64: &[&[u64; 4]],
    start: usize,
    end: usize,
) -> PointproofsG1 {
    // the second condition `n <= 1024` comes from benchmarking
    // pre-computation is faster only when the #basis is <1024
    if prover_params.precomp.len() == 512 * prover_params.n && prover_params.n <= 1024 {
        PointproofsG1Affine::sum_of_products_precomp_256(
            &prover_params.generators[start..end],
            &scalars_u64,
            &prover_params.precomp[start * 256..end * 256],
        )
    } else {
        PointproofsG1Affine::sum_of_products(&prover_params.generators[start..end], &scalars_u64)
    }
}

/// Computes prover_params.generator[index] ^ scalars
/// Tries to use pre-computated data when possible.
pub(crate) fn pp_single_exp_helper(
    prover_params: &ProverParams,
    scalar: Fr,
    index: usize,
) -> PointproofsG1 {
    if prover_params.precomp.len() == 3 * prover_params.generators.len() {
        prover_params.generators[index]
            .mul_precomp_3(scalar, &prover_params.precomp[index * 3..(index + 1) * 3])
    } else if prover_params.precomp.len() == 256 * prover_params.generators.len() {
        prover_params.generators[index].mul_precomp_256(
            scalar,
            &prover_params.precomp[index * 256..(index + 1) * 256],
        )
    } else {
        assert_eq!(prover_params.precomp.len(), 0, "{}", ERR_PARAM);
        prover_params.generators[index].mul(scalar)
    }
}
