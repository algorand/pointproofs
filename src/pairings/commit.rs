//! this file is part of the pointproofs.
//! It defines APIs for constructing and updating commitments.

use ff::{Field, PrimeField};
use pairing::{bls12_381::*, CurveAffine, CurveProjective};
use pairings::err::*;
use pairings::hash_to_field_pointproofs::*;
use pairings::misc::*;
use pairings::param::*;
use pairings::*;

impl Commitment {
    /// generate a new commitment.
    ///     * input: prover parameter set
    ///     * input: a list of n values
    ///     * output: a commitment
    ///     * error: invalid ciphersuite/parameters
    /// note that if the #values does not match the parameter n,
    /// an error will be returned.
    /// if one were to generate a commitment for a vector of length
    /// less than n, then the caller should pad the vector.
    /// In this scenario, the caller should define the right
    /// format for padding.
    pub fn new<Blob: AsRef<[u8]>>(
        prover_params: &ProverParams,
        values: &[Blob],
    ) -> Result<Self, String> {
        // checks that cipersuite is supported
        if !check_ciphersuite(prover_params.ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        };

        if prover_params.n != values.len() {
            return Err(ERR_INVALID_VALUE.to_owned());
        };

        // hash the values into scalars
        let scalars_fr_repr: Vec<FrRepr> = values
            .iter()
            .map(|s| hash_to_field_repr_pointproofs(s.as_ref()))
            .collect();
        let scalars_u64: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();

        // commit = \prod pp[i]^scalar[i]
        let commit = pp_sum_of_prod_helper(&prover_params, &scalars_u64, 0, prover_params.n);

        Ok(Self {
            ciphersuite: prover_params.ciphersuite,
            commit,
        })
    }

    /// upated an existing commitment
    ///     * input: commitment
    ///     * input: prover parameter set
    ///     * input: the index of the value to be updated
    ///     * input: the old value
    ///     * input: the new value
    ///     * output: mutate self to the new commitment
    ///     * error: invalid ciphersuite, parameters
    pub fn update<Blob: AsRef<[u8]>>(
        &mut self,
        prover_params: &ProverParams,
        changed_index: usize,
        value_before: Blob,
        value_after: Blob,
    ) -> Result<(), String> {
        // checks that cipersuite is supported
        if self.ciphersuite != prover_params.ciphersuite {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        if !check_ciphersuite(prover_params.ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        if prover_params.n <= changed_index {
            return Err(ERR_INVALID_INDEX.to_owned());
        };

        // multiplier = hash(new_value) - hash(old_value)
        let mut multiplier = hash_to_field_pointproofs(&value_before);
        multiplier.negate();
        multiplier.add_assign(&hash_to_field_pointproofs(&value_after));

        // new_commit = old_commit * g[index]^multiplier
        let res = pp_single_exp_helper(&prover_params, multiplier, changed_index);
        self.commit.add_assign(&res);

        Ok(())
    }

    /// upated an existing commitment with a list of messages
    ///     * input: commitment
    ///     * input: prover parameter set
    ///     * input: the indices of the value to be updated
    ///     * input: the old values
    ///     * input: the new values
    ///     * output: mutate self to the new commitment
    ///     * error: invalid ciphersuite, parameters
    /// Note that if their exist duplicated indices, an error
    /// will be returned.
    /// Also note that changed_index.len() should be within [0, n)
    /// 0 is valid -- the output commit stays unchanged
    /// n is invalid -- in this case the caller should call Commitment::new
    pub fn batch_update<Blob: AsRef<[u8]>>(
        &mut self,
        prover_params: &ProverParams,
        changed_index: &[usize],
        value_before: &[Blob],
        value_after: &[Blob],
    ) -> Result<(), String> {
        // checks that cipersuite is supported
        if self.ciphersuite != prover_params.ciphersuite {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        if !check_ciphersuite(prover_params.ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        // check the parameters are valid
        for index in changed_index {
            if prover_params.n <= *index {
                return Err(ERR_INVALID_INDEX.to_owned());
            };
        }
        if changed_index.len() >= prover_params.n {
            return Err(ERR_INVALID_INDEX.to_owned());
        }
        if changed_index.len() != value_before.len() || changed_index.len() != value_after.len() {
            return Err(ERR_INDEX_VALUE_NOT_MATCH.to_owned());
        }
        if !misc::has_unique_elements(changed_index) {
            return Err(ERR_DUPLICATED_INDEX.to_owned());
        }

        // get the scalars from the hashes
        let mut multiplier_set: Vec<FrRepr> = Vec::with_capacity(value_before.len());
        for i in 0..value_before.len() {
            // multiplier = hash(new_value) - hash(old_value)
            let mut multiplier = hash_to_field_pointproofs(&value_before[i]);
            multiplier.negate();
            multiplier.add_assign(&hash_to_field_pointproofs(&value_after[i]));
            multiplier_set.push(multiplier.into_repr());
        }
        let scalars_u64: Vec<&[u64; 4]> = multiplier_set.iter().map(|s| &s.0).collect();

        // form the basis for `sum_of_products`
        let basis = changed_index
            .iter()
            .map(|i| prover_params.generators[*i])
            .collect::<Vec<PointproofsG1Affine>>();

        // compute delta = \prod g[index]^multiplier
        let delta = {
            // to use sum_of_products with pre_computation,
            // we need to form the right basis
            if prover_params.precomp.len() == 256 * prover_params.generators.len() {
                let mut pre: Vec<PointproofsG1Affine> =
                    Vec::with_capacity(changed_index.len() * 256);
                for e in changed_index.iter() {
                    pre = [
                        pre,
                        prover_params.precomp
                            [changed_index[*e] * 256..(changed_index[*e] + 1) * 256]
                            .to_vec(),
                    ]
                    .concat();
                }
                PointproofsG1Affine::sum_of_products_precomp_256(&basis, &scalars_u64, &pre)
            } else {
                // without pre_computation
                PointproofsG1Affine::sum_of_products(&basis[..], &scalars_u64)
            }
        };
        // new_commit = old_commit * \prod g[index]^multiplier
        self.commit.add_assign(&delta);
        Ok(())
    }
}
