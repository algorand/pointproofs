//! This file is part of the veccom crate.
//! Defines functions for proofs.
use ff::{Field, PrimeField};
use pairing::{bls12_381::*, CurveAffine, CurveProjective};
use pairings::err::*;
use pairings::hash_to_field_veccom::*;
use pairings::param::*;
use pairings::*;

impl Proof {
    /// Generate a new proof.
    ///     * input: prover parameter set
    ///     * input: values for the proof
    ///     * input: the index of the proof
    ///     * output: a new proof
    ///     * error: invalid ciphersuite/parameters
    pub fn new<Blob: AsRef<[u8]>>(
        prover_params: &ProverParams,
        values: &[Blob],
        index: usize,
    ) -> Result<Self, String> {
        // checks that cipersuite is supported
        if !check_ciphersuite(prover_params.ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }

        // check index is valid
        if index >= prover_params.n {
            return Err(ERR_INVALID_INDEX.to_owned());
        };
        // check param
        if values.len() != prover_params.n {
            return Err(ERR_INVALID_INDEX.to_owned());
        }

        // hash into a set of scalars
        let scalars_fr_repr: Vec<FrRepr> = values
            .iter()
            .map(|s| hash_to_field_repr_veccom(&s.as_ref()))
            .collect();
        let scalars_u64: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();

        // generate the proof use `sum of product` function
        let proof = {
            if prover_params.precomp.len() == 512 * prover_params.n {
                VeccomG1Affine::sum_of_products_precomp_256(
                    &prover_params.generators[prover_params.n - index..2 * prover_params.n - index],
                    &scalars_u64,
                    &prover_params.precomp
                        [(prover_params.n - index) * 256..(2 * prover_params.n - index) * 256],
                )
            } else {
                VeccomG1Affine::sum_of_products(
                    &prover_params.generators[prover_params.n - index..2 * prover_params.n - index],
                    &scalars_u64,
                )
            }
        };

        Ok(Self {
            ciphersuite: prover_params.ciphersuite,
            proof,
        })
    }

    /// Updating an existing proof.
    ///     * input: prover parameter set
    ///     * input: the index for the proof
    ///     * input: the index for the value that is being changed
    ///     * input: the value before the change
    ///     * input: the value after the change
    ///     * output: update self to a new proof
    ///     * error: invalid ciphersuite/parameters
    pub fn update<Blob: AsRef<[u8]>>(
        &mut self,
        prover_params: &ProverParams,
        proof_index: usize,
        changed_index: usize,
        value_before: Blob,
        value_after: Blob,
    ) -> Result<(), String> {
        // checks that cipersuite is supported
        if !check_ciphersuite(prover_params.ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        if self.ciphersuite != prover_params.ciphersuite {
            return Err(ERR_CIPHERSUITE.to_owned());
        }

        // check indices are valid
        if proof_index >= prover_params.n || changed_index >= prover_params.n {
            return Err(ERR_INVALID_INDEX.to_owned());
        }

        // update the proof
        // For updating your proof when someone else's value changes
        // Not for updating your own proof when your value changes -- because then the proof does not change!
        // proof_param may be pre-computed -- the code will determine this
        // by checking the length of pre_comp
        if proof_index != changed_index {
            let mut multiplier = hash_to_field_veccom(&value_before);
            multiplier.negate();
            multiplier.add_assign(&hash_to_field_veccom(&value_after));

            let param_index = changed_index + prover_params.n - proof_index;

            let res = if prover_params.precomp.len() == 6 * prover_params.n {
                prover_params.generators[param_index].mul_precomp_3(
                    multiplier,
                    &prover_params.precomp[param_index * 3..(param_index + 1) * 3],
                )
            } else if prover_params.precomp.len() == 512 * prover_params.n {
                prover_params.generators[param_index].mul_precomp_256(
                    multiplier,
                    &prover_params.precomp[param_index * 256..(param_index + 1) * 256],
                )
            } else {
                assert_eq!(prover_params.precomp.len(), 0, "{}", ERR_PARAM);
                prover_params.generators[param_index].mul(multiplier)
            };

            self.proof.add_assign(&res);
        }

        // if proof_index == changed_index, do nothing
        Ok(())
    }

    /// Verify the proof.
    ///     * input: the proof
    ///     * input: verifier parameter set
    ///     * input: the commitment
    ///     * input: the value
    ///     * input: the index
    ///     * output: if the proof is valid w.r.t. the rest of inputs
    pub fn verify<Blob: AsRef<[u8]>>(
        &self,
        verifier_params: &VerifierParams,
        com: &Commitment,
        value: Blob,
        index: usize,
    ) -> bool {
        if self.ciphersuite != verifier_params.ciphersuite || self.ciphersuite != com.ciphersuite {
            #[cfg(debug_assertions)]
            println!(
                " ciphersuite fails {}, {}, {}",
                self.ciphersuite, verifier_params.ciphersuite, com.ciphersuite
            );
            return false;
        }

        if !check_ciphersuite(com.ciphersuite) {
            return false;
        }

        if index >= verifier_params.n {
            return false;
        }

        // verification formula: e(com, param[n-index-1]) = gt_elt ^ hash(value) * e(proof, generator_of_g2)
        // which is to check
        //  e(com^hash_inverse,  param[n-index-1]) * e(proof^{-hash_inverse}, generator_of_g2)
        //  ?= gt_elt
        // We modify the formula as above in order to avoid slow exponentation in the target group (which is Fq12)
        // and perform two scalar multiplication by to 1/hash(value) in G1 instead, which is considerably faster.
        // We also move the pairing from the right-hand-side to the left-hand-side in order
        // to take advantage of the pairing product computation, which is faster than two pairings.

        // step 1. compute hash_inverse
        let hash = hash_to_field_veccom(&value);
        let hash_inverse = match hash.inverse() {
            Some(p) => p,
            // should not arrive here since hash to field will never return 0
            None => panic!("hash_to_field_veccom failed"),
        };

        // step 2, compute com^hash_inverse and proof^{-hash_inverse}
        let mut com_mut = com.commit;
        let mut proof_mut = self.proof;
        proof_mut.negate();
        com_mut.mul_assign(hash_inverse);
        proof_mut.mul_assign(hash_inverse);

        // step 3. check pairing product
        veccom_pairing_product(
            com_mut.into_affine(),
            verifier_params.generators[verifier_params.n - index - 1],
            proof_mut.into_affine(),
            VeccomG2Affine::one(),
        ) == verifier_params.gt_elt
    }

    /// Aggregates a vector of proofs from a same commitment into a single one.
    ///     * input: the commitment
    ///     * input: the list of proofs
    ///     * input: the list of the indices of the proofs
    ///     * input: the list of the values of the proofs
    ///     * input: parameter n (size of the vector)
    ///     * output: the aggregated proof
    ///     * error: invalid ciphersuite/length, or hash to scalars failes
    ///     * Note:
    ///         the aggregator does not check the validity of individual commit/proofs.
    ///         The caller may need to check them if they care for it.
    pub fn same_commit_aggregate<Blob: AsRef<[u8]>>(
        commit: &Commitment,
        proofs: &[Self],
        set: &[usize],
        value_sub_vector: &[Blob],
        n: usize,
    ) -> Result<Self, String> {
        // check that the csids are valid/match
        let csid = commit.ciphersuite;
        if !check_ciphersuite(csid) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        for e in proofs.iter() {
            if e.ciphersuite != csid {
                return Err(ERR_CIPHERSUITE.to_owned());
            }
        }
        // check that the length of proofs and sets match
        if proofs.len() != set.len() || proofs.len() != value_sub_vector.len() {
            return Err(ERR_INDEX_PROOF_NOT_MATCH.to_owned());
        }

        // get the list of scalas
        let ti = hash_to_ti_repr(commit, set, value_sub_vector, n)?;
        let scalars_u64: Vec<&[u64; 4]> = ti.iter().map(|s| &s.0).collect();

        let mut bases: Vec<VeccomG1> = proofs.iter().map(|s| s.proof).collect();
        CurveProjective::batch_normalization(&mut bases);
        let bases_affine: Vec<VeccomG1Affine> = bases.iter().map(|s| s.into_affine()).collect();
        // proof = \prod proofs[i]^ti[i]
        let proof = VeccomG1Affine::sum_of_products(&bases_affine[..], &scalars_u64);

        Ok(Proof {
            ciphersuite: csid,
            proof,
        })
    }

    /// Aggregate an array of proofs, each
    /// proof is a same-commit aggregated proof.
    ///     * input: a list of commitments
    ///     * input: a list of (aggregated) proofs, each for one commitment
    ///     * input: a 2-dim array of indices for the proofs, each vector of indices for an aggregated proof
    ///     * input: a 2-dim array of values for the proofs, each vector of values for an aggregated proof
    ///     * input: parameter n (size of the vector)
    ///     * Note:
    ///         * The aggregator does not check the validity of the proof.
    ///         * The proofs are already aggregated within each commitment.
    ///     * Steps:
    ///         * t\[j\] = hash_to_tj(...)
    ///         * return prod proofs\[j\]^t\[j\]
    pub fn cross_commit_aggregate_partial<Blob: AsRef<[u8]>>(
        commits: &[Commitment],
        proofs: &[Self],
        set: &[Vec<usize>],
        value_sub_vector: &[Vec<Blob>],
        n: usize,
    ) -> Result<Self, String> {
        // check ciphersuite
        let ciphersuite = commits[0].ciphersuite;
        if !check_ciphersuite(ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        for e in commits.iter() {
            if e.ciphersuite != ciphersuite {
                return Err(ERR_CIPHERSUITE.to_owned());
            }
        }
        for e in proofs.iter() {
            if e.ciphersuite != ciphersuite {
                return Err(ERR_CIPHERSUITE.to_owned());
            }
        }

        // check the length are correct
        if commits.len() != proofs.len()
            || commits.len() != set.len()
            || commits.len() != value_sub_vector.len()
            || commits.is_empty()
        {
            #[cfg(debug_assertions)]
            println!(
                "commit: {}, proofs: {}, set: {}, value_sub_vector: {}",
                commits.len(),
                proofs.len(),
                set.len(),
                value_sub_vector.len()
            );
            return Err(ERR_X_COM_SIZE.to_owned());
        };

        // if commit.len() == 1, return the aggregated proof
        if commits.len() == 1 {
            return Ok(proofs[0].clone());
        }

        // start aggregation
        let scalars = hash_to_tj(&commits, &set, &value_sub_vector, n)?;
        if scalars.len() != proofs.len() {
            return Err(ERR_X_COM_SIZE.to_owned());
        }

        let scalars_u64: Vec<&[u64; 4]> = scalars.iter().map(|s| &s.0).collect();

        let mut bases: Vec<VeccomG1> = proofs.iter().map(|s| s.proof).collect();
        CurveProjective::batch_normalization(&mut bases);
        let bases_affine: Vec<VeccomG1Affine> = bases.iter().map(|s| s.into_affine()).collect();

        // proof = \prod pi[i] ^ tj[i]
        let proof = VeccomG1Affine::sum_of_products(&bases_affine[..], &scalars_u64);

        Ok(Proof { ciphersuite, proof })
    }

    /// Aggregate a 2-dim array of proofs, each row corresponding to a
    /// commit, into a single proof.
    ///     * input: a list of commitments
    ///     * input: a 2-dim array of non-aggregated proofs, each vector of proofs for one commitment
    ///     * input: a 2-dim array of indices for the proofs, each indice for a proof
    ///     * input: a 2-dim array of values for the proofs, each value for a proof
    ///     * input: parameter n (size of the vector)
    ///     * output: an aggregated proof
    ///     * error: invalid ciphersuite, input vectors length does not match
    ///     * Note:
    ///         1. The aggregator does not check the validity of the proof.
    ///         2. The proofs are already aggregated within each commitment.
    ///     * Steps:
    ///         1. t\[j\] = hash_to_tj(...)
    ///         2. pi\[j\] = same_commit_aggregate(...)
    ///         3. return prod pi\[j\]^t\[j\]
    pub fn cross_commit_aggregate_full<Blob: AsRef<[u8]>>(
        commits: &[Commitment],
        proofs: &[Vec<Self>],
        set: &[Vec<usize>],
        value_sub_vector: &[Vec<Blob>],
        n: usize,
    ) -> Result<Self, String> {
        // check ciphersuite
        let ciphersuite = commits[0].ciphersuite;
        if !check_ciphersuite(ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        for e in commits.iter() {
            if e.ciphersuite != ciphersuite {
                return Err(ERR_CIPHERSUITE.to_owned());
            }
        }
        for e in proofs.iter() {
            for ee in e.iter() {
                if ee.ciphersuite != ciphersuite {
                    return Err(ERR_CIPHERSUITE.to_owned());
                }
            }
        }

        // check the length are correct
        if commits.len() != proofs.len()
            || commits.len() != set.len()
            || commits.len() != value_sub_vector.len()
            || commits.is_empty()
        {
            #[cfg(debug_assertions)]
            println!(
                "commit: {}, proofs: {}, set: {}, value_sub_vector: {}",
                commits.len(),
                proofs.len(),
                set.len(),
                value_sub_vector.len()
            );
            return Err(ERR_X_COM_SIZE.to_owned());
        };

        // if commit.len() == 1, call normal aggregation
        if commits.len() == 1 {
            return Self::same_commit_aggregate(
                &commits[0],
                &proofs[0],
                &set[0],
                &value_sub_vector[0],
                n,
            );
        }

        // start aggregation
        let scalars = hash_to_tj(&commits, &set, &value_sub_vector, n)?;

        let mut pi: Vec<Self> = vec![];
        for i in 0..commits.len() {
            pi.push(Self::same_commit_aggregate(
                &commits[i],
                &proofs[i],
                &set[i],
                &value_sub_vector[i],
                n,
            )?);
        }
        if scalars.len() != pi.len() {
            return Err(ERR_X_COM_SIZE.to_owned());
        }

        let scalars_u64: Vec<&[u64; 4]> = scalars.iter().map(|s| &s.0).collect();

        let mut bases: Vec<VeccomG1> = pi.iter().map(|s| s.proof).collect();
        CurveProjective::batch_normalization(&mut bases);
        let bases_affine: Vec<VeccomG1Affine> = bases.iter().map(|s| s.into_affine()).collect();

        // proof = \prod pi[i] ^ tj[i]
        let proof = VeccomG1Affine::sum_of_products(&bases_affine[..], &scalars_u64);

        Ok(Proof { ciphersuite, proof })
    }

    /// batch verify a proof for a list of values/indices
    ///     * input: the proof
    ///     * input: verifier parameter set
    ///     * input: the commitment
    ///     * input: the list of indices
    ///     * input: the list of values
    ///     * output: if the proof is valid w.r.t. the rest of inputs
    pub fn same_commit_batch_verify<Blob: AsRef<[u8]>>(
        &self,
        verifier_params: &VerifierParams,
        com: &Commitment,
        set: &[usize],
        value_sub_vector: &[Blob],
    ) -> bool {
        // we want to check if
        //   e(com, g2^{\sum_{i \in set} \alpha^{N+1-i} t_i})
        //    ?= e(proof, g2) * e(g1, g2)^{alpha^{N+1} \sum value_i*t_i}
        // which is to check
        //   e(com^tmp, g2^{\sum_{i \in set} \alpha^{N+1-i} t_i})
        //    * e(proof^{-tmp}, g2)
        //    ?= e(g1, g2)^{alpha^N+1}
        // where
        //   tmp = 1/ \sum value_i*t_i

        // 0. check the validity of the inputs: csid, length, etc
        if !check_ciphersuite(com.ciphersuite) {
            return false;
        }
        if com.ciphersuite != verifier_params.ciphersuite || com.ciphersuite != self.ciphersuite {
            #[cfg(debug_assertions)]
            println!(
                "Ciphersuite failed? {} {} {}\n",
                com.ciphersuite, verifier_params.ciphersuite, self.ciphersuite
            );

            return false;
        }
        if set.len() != value_sub_vector.len() {
            return false;
        }
        if value_sub_vector.len() > verifier_params.n {
            return false;
        }
        for e in set {
            if *e >= verifier_params.n {
                return false;
            }
        }

        // if the length == 1, call normal verification method
        if set.len() == 1 {
            return self.verify(&verifier_params, &com, value_sub_vector[0].as_ref(), set[0]);
        }
        // 1. compute tmp
        // 1.1 get the list of scalas, return false if this failed
        let ti = match hash_to_ti_repr(com, set, value_sub_vector, verifier_params.n) {
            Err(_e) => return false,
            Ok(p) => p,
        };

        // 1.2 tmp = 1/\sum value_i*t_i
        let mut tmp = Fr::zero();
        for i in 0..set.len() {
            let mut mi = hash_to_field_veccom(value_sub_vector[i].as_ref());
            let fr = match Fr::from_repr(ti[i]) {
                Ok(p) => p,
                Err(_e) => return false,
            };
            mi.mul_assign(&fr);
            tmp.add_assign(&mi);
        }

        // 1.3 if tmp == 0 (should never happen in practise)
        assert!(!tmp.is_zero());
        let mut tmp = tmp.inverse().unwrap();

        // 2 check
        //   e(com^tmp, g2^{\sum_{i \in set} \alpha^{N+1-i} t_i})
        //    * e(proof^{-tmp}, g2)
        //    ?= e(g1, g2)^{alpha^N+1}

        // 2.1 com ^ tmp
        let mut com_mut = com.commit;
        com_mut.mul_assign(tmp);

        // 2.2 g2^{\sum_{i \in set} \alpha^{N+1-i} t_i}

        let mut bases: Vec<VeccomG2Affine> = vec![];
        for index in set.iter().take(ti.len()) {
            bases.push(verifier_params.generators[verifier_params.n - index - 1]);
        }
        let scalars_u64: Vec<&[u64; 4]> = ti.iter().map(|s| &s.0).collect();
        let param_subset_sum = VeccomG2Affine::sum_of_products(&bases, &scalars_u64);

        // 2.3 proof ^ {-tmp}
        let mut proof_mut = self.proof;
        tmp.negate();
        proof_mut.mul_assign(tmp);

        // 3 pairing product
        veccom_pairing_product(
            com_mut.into_affine(),
            param_subset_sum.into_affine(),
            proof_mut.into_affine(),
            VeccomG2Affine::one(),
        ) == verifier_params.gt_elt
    }

    /// Verify a proof which was aggregated from 2-dim array of proofs
    ///     * input: the proof
    ///     * input: verifier parameter set
    ///     * input: the list of commitments
    ///     * input: a 2-dim array of indices
    ///     * input: a 2-dim array of values
    ///     * output: if the proof is valid w.r.t. the rest of inputs
    pub fn cross_commit_batch_verify<Blob: AsRef<[u8]>>(
        &self,
        verifier_params: &VerifierParams,
        com: &[Commitment],
        set: &[Vec<usize>],
        value_sub_vector: &[Vec<Blob>],
    ) -> bool {
        // check ciphersuite
        if self.ciphersuite != verifier_params.ciphersuite {
            return false;
        }
        for e in com {
            if self.ciphersuite != e.ciphersuite {
                return false;
            }
        }

        // check length
        let num_commit = com.len();
        if num_commit != set.len() || num_commit != value_sub_vector.len() || num_commit == 0 {
            // length does not match
            return false;
        }
        for j in 0..num_commit {
            if set[j].len() != value_sub_vector[j].len()
                || set[j].is_empty()
                || set[j].len() > verifier_params.n
            {
                // length does not match
                return false;
            }
        }

        // handled the case where there is only 1 commit
        if num_commit == 1 {
            // call normal batch verification
            return self.same_commit_batch_verify(
                &verifier_params,
                &com[0],
                &set[0],
                &value_sub_vector[0],
            );
        }

        // generate all the t_i-s for j \in [num_commit]
        let mut ti_s: Vec<Vec<Fr>> = vec![];
        for i in 0..num_commit {
            let ti = match hash_to_ti_fr(&com[i], &set[i], &value_sub_vector[i], verifier_params.n)
            {
                Err(_e) => return false,
                Ok(p) => p,
            };
            ti_s.push(ti);
        }
        // generate tj
        let tj = match hash_to_tj(&com, &set, &value_sub_vector, verifier_params.n) {
            Err(_e) => return false,
            Ok(p) => p,
        };

        // we want to check
        //  \prod_{j=1}^num_commit e(com[j], g2^{\sum alpha^{n + 1 -i} * t_i,j} ) ^ t_j
        //      ?= e (proof, g2) * e (g1, g2)^{alpha^{n+1} * {\sum m_i,j * t_i,j * tj}}
        // step 1. compute tmp = \sum m_i,j * t_i,j * tj
        let mut tmp = Fr::zero();
        for j in 0..num_commit {
            let mut tmp2 = Fr::zero();

            // tmp2 = sum_i m_ij * t_ij
            for i in 0..ti_s[j].len() {
                let mut tmp3 = ti_s[j][i];
                let mij = hash_to_field_veccom(value_sub_vector[j][i].as_ref());
                tmp3.mul_assign(&mij);
                tmp2.add_assign(&tmp3);
            }
            // tmp2 = tj * tmp2
            let tmp3 = match Fr::from_repr(tj[j]) {
                Ok(p) => p,
                Err(_e) => return false,
            };
            tmp2.mul_assign(&tmp3);
            // tmp += tj * (sum_i m_ij * t_ij)
            tmp.add_assign(&tmp2);
        }

        let tmp_inverse = match tmp.inverse() {
            Some(p) => p,
            // tmp == 0 should never happen in practise
            None => panic!("some thing is wrong, check verification formula"),
        };

        // step 2. now the formula becomes
        // \prod e(com[j], g2^{\sum alpha^{n + 1 - i} * t_i,j * tj/tmp} )
        //  * e(proof^{-1/tmp}, g2)
        //  ?= e(g1, g2)^{alpha^{n+1}} == verifier_params.Fq12

        // g1_vec stores the g1 components for the pairing product
        // for j \in [num_commit], store com[j]
        let mut g1_vec: Vec<VeccomG1Affine> = vec![];
        for c in com {
            g1_vec.push(c.commit.into_affine());
        }
        // the last element for g1_vec is proof^{-1/tmp}
        let mut tmp2 = self.proof;
        tmp2.negate();
        tmp2.mul_assign(tmp_inverse);
        g1_vec.push(tmp2.into_affine());

        // g2_vec stores the g2 components for the pairing product
        // for j \in [num_commit], g2^{\sum alpha^{n + 1 - i} * t_i,j} * tj/tmp )
        let mut g2_vec: Vec<VeccomG2Affine> = vec![];
        for j in 0..num_commit {
            let mut tmp3 = tmp_inverse;
            let scalar = match Fr::from_repr(tj[j]) {
                Ok(p) => p,
                // the output of hash should always be a field element
                Err(_e) => panic!("some thing is wrong, check hash_to_field function"),
            };
            tmp3.mul_assign(&scalar);

            let mut bases: Vec<VeccomG2Affine> = vec![];
            let mut scalars_u64: Vec<[u64; 4]> = vec![];
            for i in 0..ti_s[j].len() {
                bases.push(verifier_params.generators[verifier_params.n - set[j][i] - 1]);

                let mut t = ti_s[j][i];
                t.mul_assign(&tmp3);
                scalars_u64.push(t.into_repr().0);
            }

            let mut scalars_u64_ref: Vec<&[u64; 4]> = vec![];
            for e in scalars_u64.iter().take(ti_s[j].len()) {
                scalars_u64_ref.push(&e);
            }

            let param_subset_sum = VeccomG2Affine::sum_of_products(&bases, &scalars_u64_ref);

            g2_vec.push(param_subset_sum.into_affine());
        }
        // the last element for g1_vec is g2
        g2_vec.push(VeccomG2::one().into_affine());

        // now check the pairing product ?= verifier_params.Fq12
        veccom_pairing_multi_product(&g1_vec[..], &g2_vec[..]) == verifier_params.gt_elt
    }
}
