use super::ciphersuite::*;
use super::err::*;
use super::hash_to_field_veccom::hash_to_field_veccom;
use super::{Commitment, ProverParams};
use ff::Field;
use pairing::{bls12_381::*, CurveAffine, CurveProjective};
use pairings::hash_to_field_veccom::hash_to_field_repr_veccom;
use pairings::*;

impl Commitment {
    pub fn new<Blob: AsRef<[u8]>>(
        prover_params: &ProverParams,
        values: &[Blob],
    ) -> Result<Self, String> {
        // checks that cipersuite is supported
        assert!(
            check_ciphersuite(prover_params.ciphersuite),
            ERR_CIPHERSUITE.to_owned()
        );

        if prover_params.n != values.len() {
            return Err(ERR_INVALID_VALUE.to_owned());
        };

        Ok(Self {
            ciphersuite: 0,
            commit: commit(&prover_params, values),
        })
    }

    pub fn update<Blob: AsRef<[u8]>>(
        &mut self,
        prover_params: &ProverParams,
        changed_index: usize,
        value_before: Blob,
        value_after: Blob,
    ) -> Result<(), String> {
        // checks that cipersuite is supported
        assert!(
            check_ciphersuite(prover_params.ciphersuite),
            ERR_CIPHERSUITE.to_owned()
        );

        if prover_params.n < changed_index {
            return Err(ERR_INVALID_INDEX.to_owned());
        };

        (*self).commit = commit_update(
            &prover_params,
            &self.commit,
            changed_index,
            value_before.as_ref(),
            value_after.as_ref(),
        );
        Ok(())
    }
}

/**
 * Assumes prover_params are correctly generated for n = values.len
 */
fn commit<Blob: AsRef<[u8]>>(prover_params: &ProverParams, values: &[Blob]) -> VeccomG1 {
    let n = values.len();

    let scalars_fr_repr: Vec<FrRepr> = values
        .iter()
        .map(|s| hash_to_field_repr_veccom(s.as_ref()))
        .collect();
    let scalars_u64: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();
    if prover_params.precomp.len() == 512 * n {
        VeccomG1Affine::sum_of_products_precomp_256(
            &prover_params.generators[0..n],
            &scalars_u64,
            &prover_params.precomp,
        )
    } else {
        VeccomG1Affine::sum_of_products(&prover_params.generators[0..n], &scalars_u64)
    }
}

/**
 * Assumes prover_params are correctly generated for n such that changed_index<n
 */
fn commit_update(
    prover_params: &ProverParams,
    com: &VeccomG1,
    changed_index: usize,
    value_before: &[u8],
    value_after: &[u8],
) -> VeccomG1 {
    let mut multiplier = hash_to_field_veccom(&value_before);
    multiplier.negate();
    multiplier.add_assign(&hash_to_field_veccom(&value_after));

    let res = if prover_params.precomp.len() == 3 * prover_params.generators.len() {
        prover_params.generators[changed_index].mul_precomp_3(
            multiplier,
            &prover_params.precomp[changed_index * 3..(changed_index + 1) * 3],
        )
    } else if prover_params.precomp.len() == 256 * prover_params.generators.len() {
        prover_params.generators[changed_index].mul_precomp_256(
            multiplier,
            &prover_params.precomp[changed_index * 256..(changed_index + 1) * 256],
        )
    } else {
        prover_params.generators[changed_index].mul(multiplier)
    };

    let mut new_com = *com;
    new_com.add_assign(&res);
    new_com
}

#[cfg(test)]
/**
 * Updates the commitment to commit to a value whose hash is 0 in changed_index
 * Needed for testing only (in order to test verify, which handles the case of hash ==  0 separately)
 * Assumes prover_params are correctly generated for n such that changed_index<n
 */
// no longer needed since the hash_to_field_veccom will never output 0
pub fn update_to_zero_hash(
    prover_params: &ProverParams,
    com: &Commitment,
    changed_index: usize,
    value_before: &[u8],
) -> Commitment {
    let mut multiplier = hash_to_field_veccom(&value_before);
    multiplier.negate();

    let res = if prover_params.precomp.len() == 3 * prover_params.generators.len() {
        prover_params.generators[changed_index].mul_precomp_3(
            multiplier,
            &prover_params.precomp[changed_index * 3..(changed_index + 1) * 3],
        )
    } else if prover_params.precomp.len() == 256 * prover_params.generators.len() {
        prover_params.generators[changed_index].mul_precomp_256(
            multiplier,
            &prover_params.precomp[changed_index * 256..(changed_index + 1) * 256],
        )
    } else {
        prover_params.generators[changed_index].mul(multiplier)
    };

    let mut new_com = com.clone();
    new_com.commit.add_assign(&res);
    new_com
}
